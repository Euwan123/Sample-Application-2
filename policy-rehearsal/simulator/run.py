from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import t

from simulator.model import (
    MEASURES,
    RATE_MEASURES,
    TRAFFIC_SCENARIOS,
    Policy,
    all_policies,
    load_policy,
    load_settings,
    simulate,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_predictions(
    policies: list[Policy],
    settings_path: Path,
    policy_path: Path,
    runs: int | None = None,
    accounts: int | None = None,
) -> pd.DataFrame:
    settings = load_settings(settings_path)
    runs = runs or settings.runs
    if runs < 1:
        raise ValueError("runs must be positive")
    if accounts is not None:
        if accounts < 1:
            raise ValueError("accounts must be positive")
        from dataclasses import replace

        settings = replace(settings, accounts=accounts)

    configured_policy = load_policy(policy_path)
    rows = []
    for policy_index, policy in enumerate(policies):
        for traffic_index, traffic in enumerate(TRAFFIC_SCENARIOS):
            seeds = settings.seed + policy_index * len(TRAFFIC_SCENARIOS) * runs + traffic_index * runs
            samples = [
                simulate(policy, traffic, settings, seeds + run_index)
                for run_index in range(runs)
            ]
            row: dict[str, object] = {
                "policy": policy.label,
                "threshold": policy.threshold,
                "lockout": policy.lockout,
                "fixed_lock_seconds": policy.fixed_lock_seconds,
                "mfa": policy.mfa,
                "recovery": policy.recovery,
                "traffic": traffic,
                "runs": runs,
                "is_configured_policy": policy == configured_policy,
            }
            for measure in MEASURES:
                values = np.asarray([sample[measure] for sample in samples], dtype=float)
                mean = float(values.mean())
                if runs == 1:
                    margin = 0.0
                else:
                    margin = float(t.ppf((1 + settings.confidence_level) / 2, runs - 1) * values.std(ddof=1) / np.sqrt(runs))
                row[f"{measure}_mean"] = mean
                row[f"{measure}_ci_low"] = max(0.0, mean - margin)
                row[f"{measure}_ci_high"] = min(1.0, mean + margin) if measure in RATE_MEASURES else mean + margin
            rows.append(row)
    return pd.DataFrame(rows)


def write_locked_predictions(frame: pd.DataFrame, output_path: Path) -> str:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False, float_format="%.8f")
    digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
    lock_path = output_path.with_name("predictions.lock")
    lock_path.write_text(f"{digest}  {output_path.name}\n", encoding="ascii")
    return digest


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate locked, synthetic policy predictions.")
    parser.add_argument("--settings", type=Path, default=PROJECT_ROOT / "simulator" / "settings.yaml")
    parser.add_argument("--policy", type=Path, default=PROJECT_ROOT / "policies" / "policy.yaml")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "predictions.csv")
    parser.add_argument("--runs", type=int, help="Override the configured simulator runs per cell.")
    parser.add_argument("--accounts", type=int, help="Override the configured synthetic account count.")
    args = parser.parse_args()

    frame = build_predictions(
        all_policies(),
        args.settings,
        args.policy,
        args.runs,
        args.accounts,
    )
    digest = write_locked_predictions(frame, args.output)
    print(f"Wrote {len(frame)} prediction cells.")
    print(f"SHA-256: {digest}")
    print("Commit both prediction files before running the replica experiment:")
    print("  git add data/predictions.csv data/predictions.lock")
    print('  git commit -m "Lock predictions"')


if __name__ == "__main__":
    main()
