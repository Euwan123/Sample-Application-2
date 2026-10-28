import sqlite3
from pathlib import Path

import pandas as pd

from replica.experiment import run_experiments
from simulator.model import MEASURES


def test_experiment_writes_36_observation_cells_and_sqlite_request_log(tmp_path: Path):
    settings_path = tmp_path / "settings.yaml"
    settings_path.write_text(
        """
simulation:
  days: 7
  accounts: 4
  sensitive_share: 0.5
  runs: 1
  replica_runs: 1
  confidence_level: 0.95
  seed: 11
users:
  mistype_rate: 0.1
  forget_rate: 0.004
  max_retries: 8
  mfa_device_at_hand: 0.9
  recovery_success_rate: 0.9
  recovery_delay_seconds: 300
attackers:
  brute_force:
    attempt_rate: 1
    accounts_targeted: 2
    credential_list_size: 4
  credential_stuffing:
    attempt_rate: 1
    accounts_targeted: 2
    credential_list_size: 4
""",
        encoding="utf-8",
    )
    heldout_path = tmp_path / "heldout.csv"
    pd.DataFrame(
        [
            {
                "volunteer_id": f"heldout_{index + 1:02d}",
                "session_id": f"session_{index + 1:05d}",
                "login_attempts": 3 if index % 2 == 0 else 2,
                "failed_attempts": 2 if index % 2 == 0 else 1,
                "forgot_password": index == 0,
                "mfa_challenged": index % 2 == 0,
                "mfa_device_available": True if index % 2 == 0 else None,
            }
            for index in range(10)
        ]
    ).to_csv(heldout_path, index=False)
    output_path = tmp_path / "observed.csv"
    database_path = tmp_path / "replica_runs.sqlite3"

    frame, written_database = run_experiments(
        heldout_path, settings_path, output_path, database_path, runs=1
    )

    assert written_database == database_path
    assert len(frame) == 36
    assert frame["policy"].nunique() == 12
    assert set(MEASURES).issubset(frame.columns)
    assert frame["attacker_caused_lockout_rate"].between(0, 1).all()
    assert set(frame["runs"]) == {1}
    saved = pd.read_csv(output_path)
    assert len(saved) == 36
    with sqlite3.connect(database_path) as connection:
        logged_requests = connection.execute("SELECT COUNT(*) FROM request_log").fetchone()[0]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(request_log)")}
    assert logged_requests > 0
    assert {"actor", "traffic", "policy", "run_index", "virtual_hour"}.issubset(columns)
