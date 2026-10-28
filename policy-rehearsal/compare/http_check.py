from __future__ import annotations

import argparse
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import pandas as pd

from attacks.common import DEFAULT_BASE_URL, parse_response, validate_local_target
from attacks.replay_traffic import DEFAULT_HELDOUT_PATH, read_heldout_sessions
from replica.experiment import VirtualClock, run_replica_cell
from replica.service import ReplicaService
from simulator.model import RATE_MEASURES, TRAFFIC_SCENARIOS, Policy, all_policies, load_settings


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "simulator" / "settings.yaml"
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "replica.sqlite3"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "http_check.csv"
HTTP_CHECK_POLICY_INDICES = (0, -1)
RATE_TOLERANCE_PERCENTAGE_POINTS = 1.0


class HttpReplicaRunner:
    def __init__(self, base_url: str, database_path: Path) -> None:
        self.client = httpx.Client(base_url=validate_local_target(base_url), timeout=30.0)
        self.database_path = database_path
        self.clock = VirtualClock()

    def reset_account_state(self) -> None:
        with sqlite3.connect(self.database_path) as connection:
            result = connection.execute(
                """
                UPDATE accounts
                SET failure_count = 0, locked_until = NULL, mfa_pending = 0
                """
            )
            if result.rowcount < 1:
                raise RuntimeError("HTTP replica database has no synthetic accounts to reset")

    def login(
        self,
        account_id: str,
        password: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
        now: datetime | None = None,
        policy_override: Policy | None = None,
    ) -> dict[str, object]:
        headers = self._headers(actor, traffic, run_index, virtual_hour)
        if now is not None:
            headers["X-Virtual-Minute"] = str(now.minute)
        if policy_override is not None:
            headers["X-Experiment-Policy"] = policy_override.label
        response = self.client.post(
            "/login",
            json={"account_id": account_id, "password": password},
            headers=headers,
        )
        return parse_response(response)

    def mfa(
        self,
        account_id: str,
        code: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]:
        response = self.client.post(
            "/mfa",
            json={"account_id": account_id, "code": code},
            headers=self._headers(actor, traffic, run_index, virtual_hour),
        )
        return parse_response(response)

    def recover(
        self,
        account_id: str,
        recovery_code: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]:
        response = self.client.post(
            "/recover",
            json={"account_id": account_id, "recovery_code": recovery_code},
            headers=self._headers(actor, traffic, run_index, virtual_hour),
        )
        return parse_response(response)

    @staticmethod
    def _headers(actor: str, traffic: str, run_index: int, virtual_hour: int) -> dict[str, str]:
        return {
            "X-Traffic-Actor": actor,
            "X-Traffic-Scenario": traffic,
            "X-Run-Index": str(run_index),
            "X-Virtual-Hour": str(virtual_hour),
        }

    def close(self) -> None:
        self.client.close()


def validate_replica_database(database_path: Path, account_count: int, sensitive_share: float) -> None:
    if not database_path.is_file():
        raise FileNotFoundError(
            f"replica database not found: {database_path}; start Docker Compose first"
        )
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(sensitive), 0) FROM accounts"
        ).fetchone()
    expected_sensitive = round(account_count * sensitive_share)
    if row != (account_count, expected_sensitive):
        raise ValueError(
            "Docker replica account database does not match simulator settings. "
            "Rebuild the local replica after changing account settings."
        )


def selected_http_cells() -> list[tuple[int, Policy, str]]:
    policies = all_policies()
    indices = [index % len(policies) for index in HTTP_CHECK_POLICY_INDICES]
    return [
        (policy_index, policies[policy_index], traffic)
        for policy_index in indices
        for traffic in TRAFFIC_SCENARIOS
    ]


def run_http_check(
    base_url: str = DEFAULT_BASE_URL,
    heldout_path: Path = DEFAULT_HELDOUT_PATH,
    settings_path: Path = DEFAULT_SETTINGS_PATH,
    database_path: Path = DEFAULT_DATABASE_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    runs: int | None = None,
) -> pd.DataFrame:
    base_url = validate_local_target(base_url)
    settings = load_settings(settings_path)
    runs = settings.replica_runs if runs is None else runs
    if runs < 1:
        raise ValueError("HTTP check runs must be positive")
    heldout = read_heldout_sessions(heldout_path)
    if heldout["volunteer_id"].nunique() != 10:
        raise ValueError("HTTP check requires exactly 10 held-out volunteers")
    validate_replica_database(database_path, settings.accounts, settings.sensitive_share)

    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="policy-rehearsal-http-check-") as temporary_directory:
        local_service = ReplicaService(
            Path(temporary_directory) / "in_process.sqlite3",
            settings_path=settings_path,
            account_count=settings.accounts,
            sensitive_share=settings.sensitive_share,
            clock=VirtualClock(),
            policy=all_policies()[0],
            reuse_connection=True,
            defer_commits=True,
            fast_mode=True,
        )
        http_service = HttpReplicaRunner(base_url, database_path)
        try:
            for policy_index, policy, traffic in selected_http_cells():
                cell_index = policy_index * len(TRAFFIC_SCENARIOS) + TRAFFIC_SCENARIOS.index(traffic)
                in_process_samples = []
                http_samples = []
                for run_index in range(runs):
                    seed = settings.seed + cell_index * runs + run_index
                    in_process_samples.append(
                        run_replica_cell(
                            local_service,
                            policy,
                            traffic,
                            settings,
                            heldout,
                            seed,
                            run_index,
                        )
                    )
                    http_samples.append(
                        run_replica_cell(
                            http_service,
                            policy,
                            traffic,
                            settings,
                            heldout,
                            seed,
                            run_index,
                        )
                    )
                for measure in sorted(RATE_MEASURES):
                    in_process_rate = float(
                        np.mean([sample[measure] for sample in in_process_samples])
                    )
                    http_rate = float(np.mean([sample[measure] for sample in http_samples]))
                    difference = (http_rate - in_process_rate) * 100
                    rows.append(
                        {
                            "policy": policy.label,
                            "threshold": policy.threshold,
                            "lockout": policy.lockout,
                            "mfa": policy.mfa,
                            "traffic": traffic,
                            "measure": measure,
                            "runs": runs,
                            "in_process_rate": in_process_rate,
                            "http_rate": http_rate,
                            "difference_percentage_points": difference,
                            "exceeds_1_percentage_point": (
                                abs(difference) > RATE_TOLERANCE_PERCENTAGE_POINTS
                            ),
                        }
                    )
        finally:
            http_service.close()
            local_service.close()

    frame = pd.DataFrame(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False, float_format="%.8f")
    return frame


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare in-process replica results with the localhost HTTP service."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--heldout", type=Path, default=DEFAULT_HELDOUT_PATH)
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--runs", type=int, help="Override replica runs per sampled cell.")
    args = parser.parse_args()
    try:
        frame = run_http_check(
            args.base_url,
            args.heldout,
            args.settings,
            args.database,
            args.output,
            args.runs,
        )
    except (ValueError, FileNotFoundError, httpx.HTTPError, sqlite3.Error) as exc:
        parser.error(str(exc))
    print(frame.to_string(index=False))
    if frame["exceeds_1_percentage_point"].any():
        parser.exit(1, "HTTP check failed: at least one rate differs by more than 1 percentage point.\n")
    print(f"HTTP check passed; no rate differed by more than 1 percentage point. Wrote {args.output}.")


if __name__ == "__main__":
    main()
