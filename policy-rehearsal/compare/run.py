from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from scipy.stats import binomtest, spearmanr, t, wilcoxon

from simulator.model import MEASURES, RATE_MEASURES, TRAFFIC_SCENARIOS, Policy, all_policies


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MEASURE_UNITS = {
    "legitimate_lockout_rate": "%",
    "attacker_caused_lockout_rate": "%",
    "peak_hourly_lockouts": "accounts/hour",
    "legitimate_challenge_rate": "%",
    "avg_added_login_delay_seconds": "seconds",
    "attack_success_rate": "%",
    "attack_throughput_per_hour": "attempts/hour",
}
POLICY_COLUMNS = [
    "threshold",
    "lockout",
    "fixed_lock_seconds",
    "mfa",
    "recovery",
]
CELL_COLUMNS = [*POLICY_COLUMNS, "traffic"]
REVIEWERS = [f"reviewer_{index}" for index in range(1, 6)]
SUS_ITEMS = [f"q{index}" for index in range(1, 11)]


def verify_prediction_lock(predictions_path: Path, lock_path: Path) -> str:
    if not predictions_path.is_file() or not lock_path.is_file():
        raise ValueError("prediction CSV or its lock file is missing")
    lock_parts = lock_path.read_text(encoding="ascii").strip().split()
    if len(lock_parts) != 2 or lock_parts[1] != predictions_path.name:
        raise ValueError("prediction lock file is malformed or names a different CSV")
    actual = hashlib.sha256(predictions_path.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, lock_parts[0]):
        raise ValueError("predictions.csv hash does not match predictions.lock; refusing comparison")
    return actual


def _read_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def _validate_cells(frame: pd.DataFrame, name: str) -> pd.DataFrame:
    required = set(CELL_COLUMNS)
    if name == "predictions":
        required.add("runs")
        required.update(f"{measure}_mean" for measure in MEASURES)
        required.update(f"{measure}_ci_low" for measure in MEASURES)
        required.update(f"{measure}_ci_high" for measure in MEASURES)
    else:
        required.update(MEASURES)
        required.add("runs")
    missing = required - set(frame.columns)
    if missing:
        raise ValueError(f"{name} CSV is missing columns: {', '.join(sorted(missing))}")
    if frame.duplicated(CELL_COLUMNS).any():
        raise ValueError(f"{name} CSV has duplicate policy/traffic cells")
    if not set(frame["traffic"]).issubset(TRAFFIC_SCENARIOS):
        raise ValueError(f"{name} CSV contains an unknown traffic scenario")
    expected_cells = {
        (
            policy.threshold,
            policy.lockout,
            policy.fixed_lock_seconds,
            policy.mfa,
            policy.recovery,
            traffic,
        )
        for policy in all_policies()
        for traffic in TRAFFIC_SCENARIOS
    }
    actual_cells = set(frame[CELL_COLUMNS].itertuples(index=False, name=None))
    if len(frame) != 36 or actual_cells != expected_cells:
        raise ValueError(
            f"{name} CSV must contain exactly the 36 supported policy/traffic cells"
        )
    for column in required - set(CELL_COLUMNS):
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
        if frame[column].isna().any() or not np.isfinite(frame[column]).all():
            raise ValueError(f"{name} column {column} contains missing or non-finite values")
    return frame


def compare_cells(
    predictions: pd.DataFrame,
    observed: pd.DataFrame,
    expected_runs: int | None = None,
) -> pd.DataFrame:
    predictions = _validate_cells(predictions.copy(), "predictions")
    observed = _validate_cells(observed.copy(), "observed")
    if (observed["runs"] < 1).any() or observed["runs"].nunique() != 1:
        raise ValueError("observed CSV must report one consistent positive replica run count")
    if expected_runs is not None and not (observed["runs"] == expected_runs).all():
        raise ValueError(f"observed CSV must report exactly {expected_runs} replica runs per cell")
    if (predictions["runs"] < 1).any():
        raise ValueError("predictions CSV must report a positive simulator run count")

    keys = predictions[CELL_COLUMNS].merge(
        observed[CELL_COLUMNS], on=CELL_COLUMNS, how="outer", indicator=True
    )
    expected_cell_count = 36
    if (
        len(predictions) != expected_cell_count
        or len(observed) != expected_cell_count
        or not (keys["_merge"] == "both").all()
    ):
        raise ValueError(
            "predictions and observed CSVs must contain the same 36 policy/traffic cells"
        )

    merged = predictions.merge(
        observed,
        on=CELL_COLUMNS,
        how="inner",
        suffixes=("_predicted", "_observed"),
        validate="one_to_one",
    )
    rows = []
    for _, cell in merged.iterrows():
        for measure in MEASURES:
            predicted = float(cell[f"{measure}_mean"])
            observed_mean = float(cell[measure])
            scale = 100.0 if measure in RATE_MEASURES else 1.0
            rows.append(
                {
                    **{column: cell[column] for column in CELL_COLUMNS},
                    "measure": measure,
                    "unit": MEASURE_UNITS[measure],
                    "simulator_runs": int(cell["runs_predicted"]),
                    "replica_runs": int(cell["runs_observed"]),
                    "predicted_mean": predicted * scale,
                    "observed_mean": observed_mean * scale,
                    "predicted_ci_low": float(cell[f"{measure}_ci_low"]) * scale,
                    "predicted_ci_high": float(cell[f"{measure}_ci_high"]) * scale,
                    "signed_error": (observed_mean - predicted) * scale,
                    "absolute_error": abs(observed_mean - predicted) * scale,
                    "inside_95_ci": bool(
                        float(cell[f"{measure}_ci_low"]) <= observed_mean <= float(cell[f"{measure}_ci_high"])
                    ),
                }
            )
    return pd.DataFrame(rows)


def summarize_measures(cell_comparison: pd.DataFrame, thresholds: dict[str, Any]) -> pd.DataFrame:
    rows = []
    alpha = float(thresholds["alpha"])
    for measure, group in cell_comparison.groupby("measure", sort=False):
        errors = group["signed_error"].to_numpy(dtype=float)
        mae = float(np.mean(np.abs(errors)))
        rmse = float(np.sqrt(np.mean(np.square(errors))))
        statistic, p_value = _wilcoxon_statistic(errors)
        is_rate = measure in RATE_MEASURES
        rows.append(
            {
                "measure": measure,
                "unit": MEASURE_UNITS[measure],
                "mae": mae,
                "rmse": rmse,
                "inside_95_ci_share": float(group["inside_95_ci"].mean()),
                "mae_target": float(thresholds["mae_target_percentage_points"]) if is_rate else np.nan,
                "mae_target_pass": mae <= float(thresholds["mae_target_percentage_points"]) if is_rate else None,
                "wilcoxon_statistic": statistic,
                "wilcoxon_p_value": p_value,
                "alpha": alpha,
                "wilcoxon_significant": p_value < alpha,
            }
        )
    return pd.DataFrame(rows)


def _wilcoxon_statistic(differences: np.ndarray) -> tuple[float, float]:
    if np.allclose(differences, 0):
        return 0.0, 1.0
    result = wilcoxon(differences, zero_method="wilcox", alternative="two-sided", method="auto")
    return float(result.statistic), float(result.pvalue)


def policy_rankings(cell_comparison: pd.DataFrame, target: float) -> tuple[pd.DataFrame, dict[str, float | bool]]:
    scores = (
        cell_comparison[cell_comparison["measure"].isin(
            ["legitimate_lockout_rate", "attack_success_rate"]
        )]
        .assign(
            predicted_native=lambda frame: np.where(
                frame["measure"].isin(RATE_MEASURES), frame["predicted_mean"] / 100, frame["predicted_mean"]
            ),
            observed_native=lambda frame: np.where(
                frame["measure"].isin(RATE_MEASURES), frame["observed_mean"] / 100, frame["observed_mean"]
            ),
        )
        .groupby(POLICY_COLUMNS, as_index=False)[["predicted_native", "observed_native"]]
        .sum()
    )
    scores["simulator_rank"] = scores["predicted_native"].rank(method="average", ascending=True)
    scores["replica_rank"] = scores["observed_native"].rank(method="average", ascending=True)
    correlation = float(spearmanr(scores["predicted_native"], scores["observed_native"]).statistic)
    summary = {
        "spearman_rank_correlation": correlation,
        "target": target,
        "target_pass": bool(np.isfinite(correlation) and correlation >= target),
    }
    return scores.sort_values(
        ["simulator_rank", "threshold", "lockout", "fixed_lock_seconds", "mfa", "recovery"]
    ), summary


def build_issue_items(
    predictions: pd.DataFrame,
    observed: pd.DataFrame,
    thresholds: dict[str, Any],
) -> pd.DataFrame:
    pred = _validate_cells(predictions.copy(), "predictions")
    obs = _validate_cells(observed.copy(), "observed")
    merged = pred.merge(obs, on=CELL_COLUMNS, validate="one_to_one", suffixes=("_predicted", "_observed"))
    items = []
    policy_specs = merged[
        POLICY_COLUMNS
    ].drop_duplicates()
    for spec in policy_specs.itertuples(index=False):
        policy = Policy(
            int(spec.threshold),
            str(spec.lockout),
            str(spec.mfa),
            int(spec.fixed_lock_seconds),
            str(spec.recovery),
        )
        operational_pred = merged[
            (merged["threshold"] == policy.threshold)
            & (merged["lockout"] == policy.lockout)
            & (merged["fixed_lock_seconds"] == policy.fixed_lock_seconds)
            & (merged["mfa"] == policy.mfa)
            & (merged["recovery"] == policy.recovery)
            & (merged["traffic"] == "normal")
        ].iloc[0]
        cutoff = float(thresholds["operational_lockout_rate"])
        items.append(
            {
                "item_id": f"{policy.label}:operational:normal",
                "policy": policy.label,
                "issue_type": "operational",
                "traffic": "normal",
                "simulator_flag": operational_pred["legitimate_lockout_rate_mean"] > cutoff,
                "observed_issue": operational_pred["legitimate_lockout_rate"] > cutoff,
            }
        )
        for traffic in ("brute_force", "credential_stuffing"):
            cell = merged[
                (merged["threshold"] == policy.threshold)
                & (merged["lockout"] == policy.lockout)
                & (merged["fixed_lock_seconds"] == policy.fixed_lock_seconds)
                & (merged["mfa"] == policy.mfa)
                & (merged["recovery"] == policy.recovery)
                & (merged["traffic"] == traffic)
            ].iloc[0]
            cutoff = float(thresholds["attack_success_rate"])
            items.append(
                {
                    "item_id": f"{policy.label}:security:{traffic}",
                    "policy": policy.label,
                    "issue_type": "security",
                    "traffic": traffic,
                    "simulator_flag": cell["attack_success_rate_mean"] > cutoff,
                    "observed_issue": cell["attack_success_rate"] > cutoff,
                }
            )
    return pd.DataFrame(items)


def _yes_no(value: Any) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"yes", "y", "true", "1"}:
        return True
    if normalized in {"no", "n", "false", "0"}:
        return False
    raise ValueError(f"review answers must be yes/no; found {value!r}")


def compare_reviewers(issue_items: pd.DataFrame, reviews: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    required = {"item_id", *REVIEWERS}
    missing = required - set(reviews.columns)
    if missing:
        raise ValueError(f"review CSV is missing columns: {', '.join(sorted(missing))}")
    if reviews["item_id"].duplicated().any() or set(reviews["item_id"]) != set(issue_items["item_id"]):
        raise ValueError(
            f"review CSV must contain exactly one row for each of the {len(issue_items)} issue items"
        )
    review_values = reviews[["item_id", *REVIEWERS]].copy()
    for reviewer in REVIEWERS:
        review_values[reviewer] = review_values[reviewer].map(_yes_no)
    review_values["reviewer_majority_flag"] = review_values[REVIEWERS].sum(axis=1) >= 3
    scored = issue_items.merge(
        review_values[["item_id", "reviewer_majority_flag"]],
        on="item_id",
        validate="one_to_one",
    )

    def rates(flag_column: str, method: str) -> dict[str, Any]:
        predicted = scored[flag_column].astype(bool)
        truth = scored["observed_issue"].astype(bool)
        positives = int(truth.sum())
        negatives = int((~truth).sum())
        true_positive = int((predicted & truth).sum())
        false_positive = int((predicted & ~truth).sum())
        return {
            "method": method,
            "detection_rate": true_positive / positives if positives else np.nan,
            "false_alarm_rate": false_positive / negatives if negatives else np.nan,
            "true_issues": positives,
            "non_issue_items": negatives,
        }

    metrics = pd.DataFrame(
        [
            rates("simulator_flag", "simulator"),
            rates("reviewer_majority_flag", "reviewer majority"),
        ]
    )
    simulator = scored["simulator_flag"].astype(bool)
    reviewers = scored["reviewer_majority_flag"].astype(bool)
    b = int((simulator & ~reviewers).sum())
    c = int((~simulator & reviewers).sum())
    discordant = b + c
    p_value = float(binomtest(min(b, c), n=discordant, p=0.5, alternative="two-sided").pvalue) if discordant else 1.0
    mc_nemar = {
        "simulator_yes_reviewer_no": b,
        "simulator_no_reviewer_yes": c,
        "discordant_items": discordant,
        "exact_mcnemar_p_value": p_value,
    }
    return scored, metrics, mc_nemar


def score_sus(responses: pd.DataFrame, benchmark: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    required = {"respondent_id", *SUS_ITEMS}
    missing = required - set(responses.columns)
    if missing:
        raise ValueError(f"SUS CSV is missing columns: {', '.join(sorted(missing))}")
    if len(responses) != 10 or responses["respondent_id"].isna().any():
        raise ValueError("SUS CSV must contain exactly 10 identified responses")
    if responses["respondent_id"].duplicated().any():
        raise ValueError("SUS respondent_id values must be unique")
    values = responses[SUS_ITEMS].apply(pd.to_numeric, errors="coerce")
    if values.isna().any().any() or not values.isin([1, 2, 3, 4, 5]).all().all():
        raise ValueError("each SUS response must be an integer from 1 to 5")
    scores = ((values.iloc[:, ::2] - 1).sum(axis=1) + (5 - values.iloc[:, 1::2]).sum(axis=1)) * 2.5
    mean = float(scores.mean())
    sd = float(scores.std(ddof=1))
    margin = float(t.ppf(0.975, len(scores) - 1) * sd / np.sqrt(len(scores)))
    per_respondent = pd.DataFrame({"respondent_id": responses["respondent_id"], "sus_score": scores})
    summary = pd.DataFrame(
        [
            {
                "respondents": len(scores),
                "mean": mean,
                "sd": sd,
                "ci_95_low": mean - margin,
                "ci_95_high": mean + margin,
                "benchmark": benchmark,
                "difference_from_benchmark": mean - benchmark,
                "benchmark_inside_95_ci": mean - margin <= benchmark <= mean + margin,
            }
        ]
    )
    return per_respondent, summary


def run_comparison(
    predictions_path: Path,
    lock_path: Path,
    observed_path: Path,
    output_dir: Path,
    thresholds_path: Path,
    reviews_path: Path | None = None,
    sus_path: Path | None = None,
) -> dict[str, Any]:
    digest = verify_prediction_lock(predictions_path, lock_path)
    thresholds = _read_yaml(thresholds_path)
    predictions = pd.read_csv(predictions_path)
    observed = pd.read_csv(observed_path)
    cells = compare_cells(predictions, observed)
    metric_summary = summarize_measures(cells, thresholds)
    rankings, rank_summary = policy_rankings(
        cells, float(thresholds["rank_correlation_target"])
    )
    flags = build_issue_items(predictions, observed, thresholds)

    output_dir.mkdir(parents=True, exist_ok=True)
    cells.to_csv(output_dir / "cell_comparison.csv", index=False)
    metric_summary.to_csv(output_dir / "metric_summary.csv", index=False)
    rankings.to_csv(output_dir / "policy_rankings.csv", index=False)
    flags.to_csv(output_dir / "issue_flags.csv", index=False)
    review_template = flags[["item_id", "policy", "issue_type", "traffic"]].copy()
    for reviewer in REVIEWERS:
        review_template[reviewer] = ""
    review_template.to_csv(output_dir / "review_template.csv", index=False)

    result: dict[str, Any] = {
        "prediction_sha256": digest,
        "metric_summary": metric_summary.to_dict(orient="records"),
        "policy_ranking": rank_summary,
        "issue_flags": int(len(flags)),
    }
    if reviews_path is not None:
        reviews = pd.read_csv(reviews_path)
        scored, review_metrics, mcnemar = compare_reviewers(flags, reviews)
        scored.to_csv(output_dir / "manual_comparison.csv", index=False)
        review_metrics.to_csv(output_dir / "issue_detection_metrics.csv", index=False)
        result["review_metrics"] = review_metrics.to_dict(orient="records")
        result["exact_mcnemar"] = mcnemar
    if sus_path is not None:
        responses = pd.read_csv(sus_path)
        per_respondent, sus_summary = score_sus(responses, float(thresholds["sus_benchmark"]))
        per_respondent.to_csv(output_dir / "sus_scores.csv", index=False)
        sus_summary.to_csv(output_dir / "sus_summary.csv", index=False)
        result["sus"] = sus_summary.to_dict(orient="records")[0]
    (output_dir / "summary.json").write_text(
        json.dumps(_json_safe(result), indent=2, allow_nan=False),
        encoding="utf-8",
    )
    return result


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value) if np.isfinite(value) else None
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if pd.isna(value):
        return None
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare locked simulator predictions with replica observations.")
    parser.add_argument("--predictions", type=Path, default=PROJECT_ROOT / "data" / "predictions.csv")
    parser.add_argument("--lock", type=Path, default=PROJECT_ROOT / "data" / "predictions.lock")
    parser.add_argument("--observed", type=Path, required=True, help="36-row replica summary CSV.")
    parser.add_argument("--reviews", type=Path, help="Optional 36-item CSV with five reviewer columns.")
    parser.add_argument("--sus", type=Path, help="Optional 10-respondent SUS CSV.")
    parser.add_argument("--thresholds", type=Path, default=PROJECT_ROOT / "compare" / "thresholds.yaml")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "data" / "comparison")
    args = parser.parse_args()
    result = run_comparison(
        args.predictions,
        args.lock,
        args.observed,
        args.output,
        args.thresholds,
        args.reviews,
        args.sus,
    )
    print(f"Comparison written to {args.output}.")
    print(f"Policy ranking target passed: {result['policy_ranking']['target_pass']}")


if __name__ == "__main__":
    main()
