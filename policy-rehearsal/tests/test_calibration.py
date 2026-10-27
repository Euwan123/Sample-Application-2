from io import StringIO
from pathlib import Path

import pandas as pd
import pytest
import yaml

from simulator.calibrate import (
    calibrate,
    fit_user_settings,
    prepare_heldout_for_replica,
    read_sessions,
    split_volunteers,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def make_sessions(volunteer_count=30):
    rows = []
    for index in range(volunteer_count):
        rows.append(
            {
                "volunteer_id": f"volunteer_{index:02d}",
                "session_id": f"session_{index:02d}",
                "login_attempts": 4,
                "failed_attempts": 1 if index % 2 == 0 else 0,
                "forgot_password": index % 5 == 0,
                "mfa_challenged": index % 2 == 0,
                "mfa_device_available": True if index % 2 == 0 else "",
            }
        )
    return pd.DataFrame(rows)


def test_split_keeps_volunteers_separate_and_is_reproducible():
    sessions = make_sessions()
    fitting, heldout = split_volunteers(sessions, seed=41)
    fitting_again, heldout_again = split_volunteers(sessions, seed=41)

    assert fitting["volunteer_id"].nunique() == 20
    assert heldout["volunteer_id"].nunique() == 10
    assert set(fitting["volunteer_id"]).isdisjoint(heldout["volunteer_id"])
    assert set(fitting["volunteer_id"]) == set(fitting_again["volunteer_id"])
    assert set(heldout["volunteer_id"]) == set(heldout_again["volunteer_id"])


def test_calibration_estimates_only_from_supplied_training_sessions():
    training = read_sessions(StringIO(make_sessions().to_csv(index=False)))
    fitted = fit_user_settings(training)

    assert fitted["mistype_rate"] == pytest.approx(12 / 96)
    assert fitted["forget_rate"] == pytest.approx(0.2)
    assert fitted["max_retries"] == 1
    assert fitted["mfa_device_at_hand"] == 1.0


def test_heldout_export_pseudonymizes_ids():
    heldout = read_sessions(StringIO(make_sessions(2).to_csv(index=False)))
    replay = prepare_heldout_for_replica(heldout)

    assert replay["volunteer_id"].tolist() == ["heldout_01", "heldout_02"]
    assert replay["session_id"].tolist() == ["session_00001", "session_00002"]
    assert not set(heldout["volunteer_id"]) & set(replay["volunteer_id"])


def test_calibration_requires_thirty_distinct_volunteers():
    with pytest.raises(ValueError, match="at least 30 volunteers"):
        split_volunteers(make_sessions(29), seed=1)


def test_calibrate_writes_fitted_settings_and_heldout_sessions(tmp_path):
    source = tmp_path / "volunteer_sessions.csv"
    source.write_text(make_sessions().to_csv(index=False), encoding="utf-8")
    settings_path = tmp_path / "settings.yaml"
    settings_path.write_text(
        (PROJECT_ROOT / "simulator" / "settings.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    output_settings = tmp_path / "fitted_settings.yaml"
    heldout_output = tmp_path / "heldout_sessions.csv"

    fitted, fitting_count, heldout_count = calibrate(
        source, settings_path, output_settings, heldout_output, seed=41
    )

    written_settings = yaml.safe_load(output_settings.read_text(encoding="utf-8"))
    assert fitting_count == 20
    assert heldout_count == 10
    assert output_settings.exists()
    assert heldout_output.exists()
    assert fitted["mistype_rate"] >= 0
    assert written_settings["users"]["mistype_rate"] == fitted["mistype_rate"]
    assert len(pd.read_csv(heldout_output)) == 10
