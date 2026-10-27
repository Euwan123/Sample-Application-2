from __future__ import annotations

import argparse
from pathlib import Path

import httpx
import numpy as np
import pandas as pd

from attacks.common import (
    DEFAULT_BASE_URL,
    DEFAULT_POLICY_PATH,
    DEFAULT_SETTINGS_PATH,
    PROJECT_ROOT,
    load_run_configuration,
    parse_response,
    submit_login,
    validate_local_target,
)
from replica.service import MFA_CODE, synthetic_password


DEFAULT_HELDOUT_PATH = PROJECT_ROOT / "data" / "heldout_sessions.csv"
REQUIRED_COLUMNS = {
    "volunteer_id",
    "session_id",
    "login_attempts",
    "failed_attempts",
    "forgot_password",
    "mfa_challenged",
    "mfa_device_available",
}


def read_heldout_sessions(path: Path) -> pd.DataFrame:
    sessions = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(sessions.columns)
    if missing:
        raise ValueError(f"held-out CSV is missing columns: {', '.join(sorted(missing))}")
    if sessions.empty:
        raise ValueError("held-out CSV contains no sessions")
    if sessions[["login_attempts", "failed_attempts"]].isna().any().any():
        raise ValueError("held-out attempt counts cannot be blank")
    if (sessions["login_attempts"] < 1).any() or (sessions["failed_attempts"] < 0).any():
        raise ValueError("held-out attempt counts must be non-negative and include at least one login attempt")
    if (sessions["failed_attempts"] > sessions["login_attempts"]).any():
        raise ValueError("failed_attempts cannot exceed login_attempts")
    for column in ("forgot_password", "mfa_challenged", "mfa_device_available"):
        if column not in sessions:
            raise ValueError(f"held-out CSV is missing column: {column}")
        values = sessions[column]
        normalized = values.astype("string").str.strip().str.lower()
        valid = normalized.isna() | normalized.isin({"true", "false", "1", "0", "yes", "no"})
        if not valid.all():
            raise ValueError(f"{column} must contain only true/false values")
        sessions[column] = normalized.map(
            {"true": True, "1": True, "yes": True, "false": False, "0": False, "no": False}
        ).astype("boolean")
    if sessions["forgot_password"].isna().any() or sessions["mfa_challenged"].isna().any():
        raise ValueError("forgot_password and mfa_challenged cannot be blank")
    return sessions


def replay_heldout_sessions(
    base_url: str,
    sessions_path: Path = DEFAULT_HELDOUT_PATH,
    policy_path: Path = DEFAULT_POLICY_PATH,
    settings_path: Path = DEFAULT_SETTINGS_PATH,
    *,
    seed: int = 3,
) -> dict[str, int]:
    base_url = validate_local_target(base_url)
    _, settings = load_run_configuration(policy_path, settings_path)
    sessions = read_heldout_sessions(sessions_path)
    rng = np.random.default_rng(seed)
    totals = {"sessions": len(sessions), "requests": 0, "successful_logins": 0, "mfa_challenges": 0}

    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for row in sessions.itertuples(index=False):
            account_index = int(rng.integers(0, settings.accounts))
            account_id = f"acct-{account_index:05d}"
            password = synthetic_password(account_id)
            failures = int(row.failed_attempts)
            attempts = int(row.login_attempts)

            for _ in range(min(failures, attempts)):
                submit_login(
                    client,
                    account_id,
                    f"synthetic-invalid-{rng.integers(0, 2**31)}",
                    traffic="normal",
                )
                totals["requests"] += 1
            if not bool(row.forgot_password) and attempts > failures:
                result = submit_login(client, account_id, password, traffic="normal")
                totals["requests"] += 1
                if result["outcome"] == "success":
                    totals["successful_logins"] += 1
                elif result["outcome"] == "mfa_challenge":
                    totals["mfa_challenges"] += 1
                    device_available = (
                        False
                        if pd.isna(row.mfa_device_available)
                        else bool(row.mfa_device_available)
                    )
                    if device_available:
                        mfa_response = client.post(
                            "/mfa",
                            json={"account_id": account_id, "code": MFA_CODE},
                            headers={
                                "X-Traffic-Actor": "legitimate",
                                "X-Traffic-Scenario": "normal",
                            },
                        )
                        parse_response(mfa_response)
                        totals["requests"] += 1
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay local held-out volunteer sessions on synthetic accounts.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--input", type=Path, default=DEFAULT_HELDOUT_PATH)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--seed", type=int, default=3)
    args = parser.parse_args()
    try:
        validate_local_target(args.base_url)
    except ValueError as exc:
        parser.error(str(exc))
    print(replay_heldout_sessions(args.base_url, args.input, args.policy, args.settings, seed=args.seed))


if __name__ == "__main__":
    main()
