from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_COLUMNS = {
    "volunteer_id",
    "session_id",
    "login_attempts",
    "failed_attempts",
    "forgot_password",
    "mfa_challenged",
    "mfa_device_available",
}


def _parse_boolean_column(values: pd.Series, column: str, *, allow_missing: bool = False) -> pd.Series:
    true_values = {"true", "1", "yes"}
    false_values = {"false", "0", "no"}

    def parse(value: Any) -> Any:
        if pd.isna(value) or str(value).strip() == "":
            return pd.NA if allow_missing else None
        normalized = str(value).strip().lower()
        if normalized in true_values:
            return True
        if normalized in false_values:
            return False
        return None

    parsed = values.map(parse)
    if (parsed.isna().any() and not allow_missing) or parsed.map(lambda value: value is None).any():
        raise ValueError(f"{column} must contain only true/false values")
    return parsed.astype("boolean")


def read_sessions(csv_source: Any) -> pd.DataFrame:
    sessions = pd.read_csv(csv_source, dtype={"volunteer_id": "string", "session_id": "string"})
    missing = REQUIRED_COLUMNS - set(sessions.columns)
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(sorted(missing))}")
    extra = set(sessions.columns) - REQUIRED_COLUMNS
    if extra:
        raise ValueError(
            "CSV has unsupported columns. Remove names, usernames, emails, passwords, tokens, "
            f"and all fields not required for session calibration: {', '.join(sorted(extra))}"
        )
    if sessions.empty:
        raise ValueError("CSV contains no session rows")
    if sessions[["volunteer_id", "session_id"]].isna().any().any():
        raise ValueError("volunteer_id and session_id cannot be blank")
    if sessions["session_id"].duplicated().any():
        raise ValueError("session_id must be unique for each session row")

    for column in ("login_attempts", "failed_attempts"):
        sessions[column] = pd.to_numeric(sessions[column], errors="coerce")
        if sessions[column].isna().any() or (sessions[column] < 0).any():
            raise ValueError(f"{column} must contain non-negative numbers")
    if (sessions["login_attempts"] < 1).any():
        raise ValueError("login_attempts must be at least one")
    if (sessions["failed_attempts"] > sessions["login_attempts"]).any():
        raise ValueError("failed_attempts cannot exceed login_attempts")

    sessions["forgot_password"] = _parse_boolean_column(sessions["forgot_password"], "forgot_password")
    sessions["mfa_challenged"] = _parse_boolean_column(sessions["mfa_challenged"], "mfa_challenged")
    sessions["mfa_device_available"] = _parse_boolean_column(
        sessions["mfa_device_available"], "mfa_device_available", allow_missing=True
    )
    if (sessions["mfa_device_available"].notna() & ~sessions["mfa_challenged"]).any():
        raise ValueError("mfa_device_available can be set only for MFA-challenged sessions")
    return sessions


def split_volunteers(sessions: pd.DataFrame, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    volunteers = np.asarray(sorted(sessions["volunteer_id"].unique()), dtype=object)
    if len(volunteers) < 30:
        raise ValueError(f"calibration requires at least 30 volunteers; found {len(volunteers)}")
    selected = np.random.default_rng(seed).permutation(volunteers)[:30]
    fitting_volunteers = set(selected[:20])
    heldout_volunteers = set(selected[20:])
    fitting = sessions[sessions["volunteer_id"].isin(fitting_volunteers)].copy()
    heldout = sessions[sessions["volunteer_id"].isin(heldout_volunteers)].copy()
    return fitting, heldout


def fit_user_settings(fitting_sessions: pd.DataFrame) -> dict[str, float | int]:
    if fitting_sessions.empty:
        raise ValueError("no fitting sessions were selected")
    nonforgot = fitting_sessions[~fitting_sessions["forgot_password"]]
    mistype_denominator = float(nonforgot["login_attempts"].sum())
    if mistype_denominator == 0:
        raise ValueError("cannot fit mistype_rate without non-forgotten login attempts")

    challenged = fitting_sessions[fitting_sessions["mfa_challenged"]]
    device_observations = challenged["mfa_device_available"].dropna()
    if device_observations.empty:
        raise ValueError("cannot fit mfa_device_at_hand without observed MFA-device availability")

    failed_attempts = fitting_sessions["failed_attempts"].to_numpy(dtype=int)
    return {
        "mistype_rate": float(nonforgot["failed_attempts"].sum() / mistype_denominator),
        "forget_rate": float(fitting_sessions["forgot_password"].mean()),
        "max_retries": max(1, int(np.quantile(failed_attempts, 0.95, method="higher"))),
        "mfa_device_at_hand": float(device_observations.astype(bool).mean()),
    }


def prepare_heldout_for_replica(heldout_sessions: pd.DataFrame) -> pd.DataFrame:
    """Keep replay data local while replacing volunteer/session identifiers."""
    replay = heldout_sessions.copy()
    volunteer_ids = sorted(replay["volunteer_id"].unique())
    volunteer_aliases = {volunteer_id: f"heldout_{index + 1:02d}" for index, volunteer_id in enumerate(volunteer_ids)}
    replay["volunteer_id"] = replay["volunteer_id"].map(volunteer_aliases)
    replay["session_id"] = [f"session_{index + 1:05d}" for index in range(len(replay))]
    return replay


def calibrate(
    input_csv: Path,
    settings_path: Path,
    settings_output: Path,
    heldout_output: Path,
    seed: int,
) -> tuple[dict[str, float | int], int, int]:
    sessions = read_sessions(input_csv)
    fitting, heldout = split_volunteers(sessions, seed)
    fitted = fit_user_settings(fitting)

    with settings_path.open(encoding="utf-8") as stream:
        settings: dict[str, Any] = yaml.safe_load(stream)
    if not isinstance(settings, dict) or not isinstance(settings.get("users"), dict):
        raise ValueError("settings YAML must contain a users mapping")
    settings["users"].update(fitted)

    settings_output.parent.mkdir(parents=True, exist_ok=True)
    settings_output.write_text(
        yaml.safe_dump(settings, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )
    heldout_output.parent.mkdir(parents=True, exist_ok=True)
    prepare_heldout_for_replica(heldout).to_csv(heldout_output, index=False)
    return fitted, int(fitting["volunteer_id"].nunique()), int(heldout["volunteer_id"].nunique())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fit simulator user settings from local volunteer sessions and hold out replica sessions."
    )
    parser.add_argument("--input", type=Path, required=True, help="Local CSV of one row per volunteer login session.")
    parser.add_argument("--settings", type=Path, default=PROJECT_ROOT / "simulator" / "settings.yaml")
    parser.add_argument("--output-settings", type=Path, default=PROJECT_ROOT / "simulator" / "settings.yaml")
    parser.add_argument("--heldout-output", type=Path, default=PROJECT_ROOT / "data" / "heldout_sessions.csv")
    parser.add_argument("--seed", type=int, default=20261027)
    args = parser.parse_args()

    fitted, fitting_count, heldout_count = calibrate(
        args.input, args.settings, args.output_settings, args.heldout_output, args.seed
    )
    print(
        f"Calibration complete: {fitting_count} fitting volunteers, {heldout_count} held-out volunteers. "
        f"Fitted settings: {fitted}"
    )


if __name__ == "__main__":
    main()
