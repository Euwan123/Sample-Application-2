from io import StringIO
from pathlib import Path

import pandas as pd
import pytest

from simulator.calibrate import read_sessions
from simulator.model import Policy, load_settings, simulate
from ui.app import calibrate_uploaded_sessions


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_builtin_session_sample_calibrates_and_holds_out_ten_volunteers():
    sample = (PROJECT_ROOT / "data" / "sample_login_sessions.csv").read_bytes()

    fitted, heldout = calibrate_uploaded_sessions(sample, seed=23)

    assert 0 <= fitted["mistype_rate"] <= 1
    assert 0 <= fitted["forget_rate"] <= 1
    assert len(heldout) == 10
    assert heldout["volunteer_id"].nunique() == 10
    assert all(value.startswith("heldout_") for value in heldout["volunteer_id"])


def test_session_calibration_rejects_raw_credential_columns():
    sample = pd.DataFrame(
        [
            {
                "volunteer_id": "v1",
                "session_id": "s1",
                "login_attempts": 1,
                "failed_attempts": 0,
                "forgot_password": False,
                "mfa_challenged": False,
                "mfa_device_available": None,
                "password": "do-not-read",
            }
        ]
    )

    with pytest.raises(ValueError, match="unsupported columns"):
        read_sessions(StringIO(sample.to_csv(index=False)))


def test_defaults_produce_nonzero_lockout_and_attack_outcomes():
    settings = load_settings(PROJECT_ROOT / "simulator" / "settings.yaml")
    policy = Policy(10, "fixed", "sensitive")
    samples = [
        simulate(policy, "brute_force", settings, settings.seed + index)
        for index in range(settings.runs)
    ]

    assert sum(sample["legitimate_lockout_rate"] for sample in samples) > 0
    assert sum(sample["attack_success_rate"] for sample in samples) > 0
    assert all(sample["attack_success_rate"] <= 1 for sample in samples)
