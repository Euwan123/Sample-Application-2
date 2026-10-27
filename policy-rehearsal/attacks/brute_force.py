from __future__ import annotations

import argparse
from pathlib import Path

import httpx

from attacks.common import (
    DEFAULT_BASE_URL,
    DEFAULT_POLICY_PATH,
    DEFAULT_SETTINGS_PATH,
    MAX_TARGETS,
    attempt_budget,
    load_run_configuration,
    submit_login,
    synthetic_password_candidates,
    target_accounts,
    validate_local_target,
)


def run_brute_force(
    base_url: str,
    policy_path: Path = DEFAULT_POLICY_PATH,
    settings_path: Path = DEFAULT_SETTINGS_PATH,
    *,
    seed: int = 1,
    target_limit: int = MAX_TARGETS,
) -> dict[str, int]:
    base_url = validate_local_target(base_url)
    policy, settings = load_run_configuration(policy_path, settings_path)
    targets = target_accounts(settings.accounts, min(target_limit, settings.brute_accounts_targeted), seed)
    passwords = synthetic_password_candidates(settings.accounts, seed)
    budget = attempt_budget(settings.brute_attempt_rate, settings.days, policy.threshold)
    totals = {"requests": 0, "locked_accounts": 0, "compromised_accounts": 0}

    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for account_id in targets:
            for password in passwords[:budget]:
                result = submit_login(
                    client, account_id, password, actor="attacker", traffic="brute_force"
                )
                totals["requests"] += 1
                if result["outcome"] == "locked":
                    totals["locked_accounts"] += 1
                    break
                if result["outcome"] == "success":
                    totals["compromised_accounts"] += 1
                    break
                if result["outcome"] == "mfa_challenge":
                    break
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded synthetic brute-force traffic against the local replica.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--target-limit", type=int, default=MAX_TARGETS)
    args = parser.parse_args()
    try:
        validate_local_target(args.base_url)
    except ValueError as exc:
        parser.error(str(exc))
    print(run_brute_force(args.base_url, args.policy, args.settings, seed=args.seed, target_limit=args.target_limit))


if __name__ == "__main__":
    main()
