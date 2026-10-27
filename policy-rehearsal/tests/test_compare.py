import hashlib
from pathlib import Path

import pandas as pd
import pytest

from compare.run import (
    build_issue_items,
    compare_cells,
    compare_reviewers,
    run_comparison,
    score_sus,
    summarize_measures,
    verify_prediction_lock,
)
from simulator.model import MEASURES, TRAFFIC_SCENARIOS, all_policies

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def prediction_and_observation_frames():
    predictions = []
    observed = []
    for policy_index, policy in enumerate(all_policies()):
        for traffic_index, traffic in enumerate(TRAFFIC_SCENARIOS):
            prediction = {
                "policy": policy.label,
                "threshold": policy.threshold,
                "lockout": policy.lockout,
                "fixed_lock_seconds": policy.fixed_lock_seconds,
                "mfa": policy.mfa,
                "recovery": policy.recovery,
                "traffic": traffic,
                "runs": 30,
            }
            observation = {
                "threshold": policy.threshold,
                "lockout": policy.lockout,
                "fixed_lock_seconds": policy.fixed_lock_seconds,
                "mfa": policy.mfa,
                "recovery": policy.recovery,
                "traffic": traffic,
                "runs": 10,
            }
            for measure_index, measure in enumerate(MEASURES):
                mean = 0.02 if measure in {
                    "legitimate_lockout_rate",
                    "legitimate_challenge_rate",
                    "attack_success_rate",
                } else float(measure_index + 1)
                if measure in {"legitimate_lockout_rate", "attack_success_rate"}:
                    mean += policy_index / 1000
                prediction[f"{measure}_mean"] = mean
                prediction[f"{measure}_ci_low"] = max(0, mean - 0.005)
                prediction[f"{measure}_ci_high"] = mean + 0.005
                observation[measure] = mean + (0.01 if traffic_index == 0 else 0)
            predictions.append(prediction)
            observed.append(observation)
    return pd.DataFrame(predictions), pd.DataFrame(observed)


def test_locked_hash_matches_file_and_detects_tampering(tmp_path):
    predictions = tmp_path / "predictions.csv"
    predictions.write_text("test data\n", encoding="utf-8")
    digest = hashlib.sha256(predictions.read_bytes()).hexdigest()
    lock = tmp_path / "predictions.lock"
    lock.write_text(f"{digest}  predictions.csv\n", encoding="ascii")

    assert verify_prediction_lock(predictions, lock) == digest
    predictions.write_text("changed data\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash does not match"):
        verify_prediction_lock(predictions, lock)


def test_comparison_outputs_per_measure_per_cell_and_percentage_point_mae():
    predictions, observed = prediction_and_observation_frames()
    cells = compare_cells(predictions, observed, expected_runs=10)

    assert len(cells) == 108 * len(MEASURES)
    lockout = cells[cells["measure"] == "legitimate_lockout_rate"]
    assert lockout.iloc[0]["unit"] == "%"
    assert lockout.iloc[0]["absolute_error"] == pytest.approx(1.0)


def test_summary_computes_error_ci_coverage_and_wilcoxon():
    predictions, observed = prediction_and_observation_frames()
    cells = compare_cells(predictions, observed, expected_runs=10)
    summary = summarize_measures(
        cells,
        {
            "mae_target_percentage_points": 5,
            "alpha": 0.05,
        },
    )

    assert len(summary) == len(MEASURES)
    lockout = summary[summary["measure"] == "legitimate_lockout_rate"].iloc[0]
    assert lockout["mae"] == pytest.approx(1 / 3)
    assert lockout["inside_95_ci_share"] == pytest.approx(2 / 3)
    assert bool(lockout["mae_target_pass"])
    assert "wilcoxon_significant" in summary


def test_issue_review_majority_detection_rates_and_exact_mcnemar():
    predictions, observed = prediction_and_observation_frames()
    thresholds = {"operational_lockout_rate": 0.05, "attack_success_rate": 0.01}
    items = build_issue_items(predictions, observed, thresholds)
    assert len(items) == 108

    reviews = pd.DataFrame(
        [
            {
                "item_id": item_id,
                **{f"reviewer_{i}": "yes" if index == 0 else "no" for i in range(1, 6)},
            }
            for index, item_id in enumerate(items["item_id"])
        ]
    )
    scored, metrics, mcnemar = compare_reviewers(items, reviews)

    assert len(scored) == 108
    assert len(metrics) == 2
    assert mcnemar["discordant_items"] >= 0
    assert 0 <= mcnemar["exact_mcnemar_p_value"] <= 1


def test_sus_scores_standard_scoring_and_reports_interval():
    responses = pd.DataFrame(
        [{"respondent_id": f"r{i}", **{f"q{j}": 3 for j in range(1, 11)}} for i in range(10)]
    )

    per_person, summary = score_sus(responses, benchmark=68)

    assert per_person["sus_score"].tolist() == [50.0] * 10
    assert summary.iloc[0]["mean"] == pytest.approx(50)
    assert summary.iloc[0]["sd"] == pytest.approx(0)
    assert summary.iloc[0]["benchmark"] == 68


def test_full_comparison_writes_outputs_and_checks_locked_prediction_hash(tmp_path):
    predictions, observed = prediction_and_observation_frames()
    predictions_path = tmp_path / "predictions.csv"
    observed_path = tmp_path / "observed.csv"
    predictions.to_csv(predictions_path, index=False)
    observed.to_csv(observed_path, index=False)
    digest = hashlib.sha256(predictions_path.read_bytes()).hexdigest()
    lock_path = tmp_path / "predictions.lock"
    lock_path.write_text(f"{digest}  predictions.csv\n", encoding="ascii")

    flags = build_issue_items(
        predictions,
        observed,
        {"operational_lockout_rate": 0.05, "attack_success_rate": 0.01},
    )
    reviews_path = tmp_path / "reviews.csv"
    pd.DataFrame(
        [
            {"item_id": item_id, **{reviewer: "no" for reviewer in [f"reviewer_{i}" for i in range(1, 6)]}}
            for item_id in flags["item_id"]
        ]
    ).to_csv(reviews_path, index=False)
    sus_path = tmp_path / "sus.csv"
    pd.DataFrame(
        [{"respondent_id": f"r{i}", **{f"q{j}": 3 for j in range(1, 11)}} for i in range(10)]
    ).to_csv(sus_path, index=False)

    result = run_comparison(
        predictions_path,
        lock_path,
        observed_path,
        tmp_path / "out",
        PROJECT_ROOT / "compare" / "thresholds.yaml",
        reviews_path,
        sus_path,
    )

    assert result["issue_flags"] == 108
    assert result["exact_mcnemar"]["discordant_items"] >= 0
    assert result["sus"]["respondents"] == 10
    assert result["policy_ranking"]["spearman_rank_correlation"] == pytest.approx(1.0)
    assert (tmp_path / "out" / "summary.json").is_file()
    assert len(pd.read_csv(tmp_path / "out" / "cell_comparison.csv")) == 108 * len(MEASURES)
