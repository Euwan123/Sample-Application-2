import hashlib
import sys
from pathlib import Path

import pandas as pd

from simulator import run


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_main_prints_hash_and_prediction_commit_commands(tmp_path, monkeypatch, capsys):
    predictions_path = tmp_path / "predictions.csv"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "simulator.run",
            "--settings",
            str(PROJECT_ROOT / "simulator" / "settings.yaml"),
            "--policy",
            str(PROJECT_ROOT / "policies" / "policy.yaml"),
            "--output",
            str(predictions_path),
            "--runs",
            "1",
            "--accounts",
            "4",
        ],
    )

    run.main()

    output = capsys.readouterr().out
    expected_hash = hashlib.sha256(predictions_path.read_bytes()).hexdigest()
    assert f"SHA-256: {expected_hash}" in output
    lock_path = predictions_path.with_name("predictions.lock")
    assert lock_path.read_text(encoding="ascii").startswith(f"{expected_hash}  predictions.csv")
    assert "git add data/predictions.csv data/predictions.lock" in output
    assert 'git commit -m "Lock predictions"' in output
    assert len(pd.read_csv(predictions_path)) == 36
