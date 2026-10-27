from pathlib import Path

import pandas as pd
import pytest

from attacks.common import (
    attempt_budget,
    synthetic_password_candidates,
    target_accounts,
    validate_local_target,
)
from attacks.credential_stuffing import synthetic_breached_credential_list
from attacks.replay_traffic import read_heldout_sessions


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "http://127.0.0.1:8000/",
        "http://[::1]:8000",
        "http://replica:8000",
    ],
)
def test_target_guard_allows_only_local_replica_hosts(url):
    assert validate_local_target(url).startswith("http://")


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost:8000",
        "http://example.com:8000",
        "http://192.168.1.10:8000",
        "http://localhost:8080",
        "http://user@localhost:8000",
        "http://localhost:8000/path",
    ],
)
def test_target_guard_rejects_non_local_or_modified_targets(url):
    with pytest.raises(ValueError, match="Refusing to run"):
        validate_local_target(url)


def test_attack_helpers_are_bounded_and_synthetic():
    assert attempt_budget(2, 7, 5) == 5
    assert attempt_budget(0, 7, 5) == 0
    assert len(target_accounts(1000, 100, seed=7)) == 100
    assert len(set(target_accounts(1000, 100, seed=7))) == 100
    assert len(synthetic_password_candidates(100, seed=7)) == 100
    assert synthetic_breached_credential_list(20, seed=3) == synthetic_password_candidates(20, seed=3)


def test_heldout_replay_requires_calibration_session_schema(tmp_path: Path):
    invalid = tmp_path / "invalid.csv"
    pd.DataFrame({"account": ["acct-1"]}).to_csv(invalid, index=False)
    with pytest.raises(ValueError, match="missing columns"):
        read_heldout_sessions(invalid)


def test_heldout_replay_preserves_unobserved_mfa_device_status(tmp_path: Path):
    sessions_path = tmp_path / "heldout.csv"
    pd.DataFrame(
        [
            {
                "volunteer_id": "heldout_01",
                "session_id": "session_00001",
                "login_attempts": 1,
                "failed_attempts": 0,
                "forgot_password": False,
                "mfa_challenged": False,
                "mfa_device_available": None,
            }
        ]
    ).to_csv(sessions_path, index=False)

    sessions = read_heldout_sessions(sessions_path)
    assert pd.isna(sessions.loc[0, "mfa_device_available"])
