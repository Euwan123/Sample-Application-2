from __future__ import annotations

from dataclasses import replace
from io import BytesIO
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st
import yaml
from scipy.stats import t

from compare.run import MEASURE_UNITS
from simulator.calibrate import (
    fit_user_settings,
    prepare_heldout_for_replica,
    read_sessions,
    split_volunteers,
)
from simulator.model import (
    MFA_MODES,
    RECOVERY_MODES,
    RATE_MEASURES,
    TRAFFIC_SCENARIOS,
    Policy,
    SimulationSettings,
    load_policy,
    load_settings,
    simulate,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "policies" / "policy.yaml"
SETTINGS_PATH = PROJECT_ROOT / "simulator" / "settings.yaml"
THRESHOLDS_PATH = PROJECT_ROOT / "compare" / "thresholds.yaml"
OBSERVED_PATH = PROJECT_ROOT / "data" / "observed.csv"

TRAFFIC_LABELS = {
    "normal": "Normal users only",
    "brute_force": "Normal users + brute force",
    "credential_stuffing": "Normal users + credential stuffing",
}


def estimate_cell(
    policy: Policy,
    traffic: str,
    settings: SimulationSettings,
) -> dict[str, dict[str, float]]:
    samples = [
        simulate(policy, traffic, settings, settings.seed + index)
        for index in range(settings.runs)
    ]
    result: dict[str, dict[str, float]] = {}
    for measure in samples[0]:
        values = np.asarray([sample[measure] for sample in samples], dtype=float)
        mean = float(values.mean())
        if settings.runs == 1:
            margin = 0.0
        else:
            margin = float(
                t.ppf((1 + settings.confidence_level) / 2, settings.runs - 1)
                * values.std(ddof=1)
                / np.sqrt(settings.runs)
            )
        result[measure] = {
            "mean": mean,
            "ci_low": max(0.0, mean - margin),
            "ci_high": min(1.0, mean + margin) if measure in RATE_MEASURES else mean + margin,
        }
    return result


def calibrate_uploaded_sessions(contents: bytes, seed: int) -> tuple[dict[str, float | int], pd.DataFrame]:
    sessions = read_sessions(BytesIO(contents))
    fitting, heldout = split_volunteers(sessions, seed)
    fitted = fit_user_settings(fitting)
    return fitted, prepare_heldout_for_replica(heldout)


def _read_thresholds() -> dict[str, float]:
    with THRESHOLDS_PATH.open(encoding="utf-8") as stream:
        thresholds = yaml.safe_load(stream)
    if not isinstance(thresholds, dict):
        raise ValueError("compare thresholds file must contain a YAML mapping")
    return thresholds


def _replica_cell(policy: Policy, traffic: str) -> pd.Series | None:
    if not OBSERVED_PATH.is_file():
        return None
    observed = pd.read_csv(OBSERVED_PATH)
    required = {
        "threshold",
        "lockout",
        "fixed_lock_seconds",
        "mfa",
        "recovery",
        "traffic",
        *(
            "legitimate_lockout_rate",
            "legitimate_challenge_rate",
            "attack_success_rate",
            "peak_hourly_lockouts",
            "avg_added_login_delay_seconds",
            "attack_throughput_per_hour",
        ),
    }
    missing = required - set(observed.columns)
    if missing:
        raise ValueError(f"replica observations are missing columns: {', '.join(sorted(missing))}")
    selected = observed[
        (observed["threshold"] == policy.threshold)
        & (observed["lockout"] == policy.lockout)
        & (observed["fixed_lock_seconds"] == policy.fixed_lock_seconds)
        & (observed["mfa"] == policy.mfa)
        & (observed["recovery"] == policy.recovery)
        & (observed["traffic"] == traffic)
    ]
    if len(selected) > 1:
        raise ValueError("replica observations contain duplicate results for this policy and traffic")
    return None if selected.empty else selected.iloc[0]


def _format_measure(measure: str, value: float) -> str:
    if measure in RATE_MEASURES:
        return f"{value * 100:.1f}%"
    return f"{value:.1f} {MEASURE_UNITS[measure]}"


def main() -> None:
    st.set_page_config(page_title="Policy Rehearsal", layout="wide")
    st.title("Login policy rehearsal")
    st.write(
        "Try a login rule with synthetic accounts. The simulator estimates what could happen "
        "before the rule is used in a real system."
    )
    st.info("This is a teaching model. It uses synthetic data and does not test a real login service.")
    st.caption(
        "Attack hits are rare in some settings. Rates are shown to three decimal places; "
        "a particular run can still record no hits."
    )

    current_policy = load_policy(POLICY_PATH)
    settings = load_settings(SETTINGS_PATH)
    thresholds = _read_thresholds()

    with st.sidebar:
        st.header("Choose a rule")
        threshold = st.selectbox(
            "Failed attempts allowed",
            options=[10, 5, 3],
            index=[10, 5, 3].index(current_policy.threshold),
        )
        lockout = st.selectbox(
            "What happens after the limit?",
            options=["fixed", "progressive"],
            index=["fixed", "progressive"].index(current_policy.lockout),
            format_func=lambda value: (
                "Lock for 15 minutes" if value == "fixed" else "Wait gets longer after each failure"
            ),
        )
        fixed_lock_seconds = st.selectbox(
            "Fixed lock duration",
            options=[300, 900, 1800, 3600],
            format_func=lambda value: f"{value // 60} minutes",
            index=(
                [300, 900, 1800, 3600].index(current_policy.fixed_lock_seconds)
                if current_policy.fixed_lock_seconds in [300, 900, 1800, 3600]
                else 1
            ),
        )
        mfa = st.selectbox(
            "Second factor",
            options=list(MFA_MODES),
            index=list(MFA_MODES).index(current_policy.mfa),
            format_func=lambda value: {
                "none": "Off",
                "sensitive": "Sensitive accounts",
                "all": "All accounts",
            }[value],
        )
        recovery = st.selectbox(
            "Forgotten-password recovery",
            options=list(RECOVERY_MODES),
            index=list(RECOVERY_MODES).index(current_policy.recovery),
            format_func=lambda value: {
                "disabled": "Disabled",
                "self_service": "Self-service recovery",
            }[value],
        )
        traffic = st.selectbox(
            "Traffic in this rehearsal",
            options=list(TRAFFIC_SCENARIOS),
            format_func=lambda value: TRAFFIC_LABELS[value],
        )
        run_button = st.button("Run prediction", type="primary")
        st.caption(
            f"{settings.runs} simulator runs · {settings.accounts:,} synthetic accounts · "
            f"{settings.days} days"
        )
        st.divider()
        st.subheader("Use sample login sessions")
        st.caption(
            "Upload anonymized session summaries only. Never upload username/password lists, "
            "tokens, or raw credentials."
        )
        sample_path = PROJECT_ROOT / "data" / "sample_login_sessions.csv"
        use_sample = st.button("Use built-in synthetic sample")
        uploaded_sessions = st.file_uploader(
            "Or choose an anonymized session CSV",
            type=["csv"],
            help="The CSV must have the documented session-summary columns and at least 30 volunteers.",
        )
        save_calibration = st.checkbox(
            "Also save fitted settings and anonymized holdout for replica use",
            value=False,
        )
        calibrate_button = st.button("Fit settings from sample")
        if use_sample or calibrate_button:
            try:
                if use_sample:
                    contents = sample_path.read_bytes()
                elif uploaded_sessions is not None:
                    contents = uploaded_sessions.getvalue()
                else:
                    st.error("Choose a CSV file or use the built-in synthetic sample.")
                    contents = None
                if contents is not None:
                    fitted, heldout = calibrate_uploaded_sessions(contents, settings.seed)
                    calibrated = replace(settings, **fitted)
                    st.session_state["calibrated_settings"] = calibrated
                    st.session_state["calibration_summary"] = fitted
                    if save_calibration:
                        with SETTINGS_PATH.open(encoding="utf-8") as stream:
                            settings_yaml = yaml.safe_load(stream)
                        settings_yaml["users"].update(fitted)
                        SETTINGS_PATH.write_text(
                            yaml.safe_dump(settings_yaml, sort_keys=False),
                            encoding="utf-8",
                        )
                        heldout_path = PROJECT_ROOT / "data" / "heldout_sessions.csv"
                        heldout_path.parent.mkdir(parents=True, exist_ok=True)
                        heldout.to_csv(heldout_path, index=False)
                    st.success("Sample settings fitted. The next prediction uses them.")
            except (ValueError, OSError, pd.errors.ParserError) as exc:
                st.error(f"Could not use that session file: {exc}")

        calibration_summary = st.session_state.get("calibration_summary")
        if calibration_summary:
            st.caption(
                f"Fitted mistype rate: {calibration_summary['mistype_rate']:.3f}; "
                f"forgot rate: {calibration_summary['forget_rate']:.3f}; "
                f"retry cap: {calibration_summary['max_retries']}."
            )

    settings = st.session_state.get("calibrated_settings", settings)
    policy = Policy(
        threshold=threshold,
        lockout=lockout,
        mfa=mfa,
        fixed_lock_seconds=fixed_lock_seconds,
        recovery=recovery,
    )
    if run_button:
        st.session_state["selected_policy"] = policy
        st.session_state["selected_traffic"] = traffic
        st.session_state["prediction"] = estimate_cell(policy, traffic, settings)

    prediction = st.session_state.get("prediction")
    if prediction is None:
        st.subheader("Ready when you are")
        st.write("Choose a rule and traffic pattern on the left, then select **Run prediction**.")
        return

    selected_policy: Policy = st.session_state["selected_policy"]
    selected_traffic: str = st.session_state["selected_traffic"]
    st.subheader("What the simulator predicts")
    st.caption(
        f"Rule: {selected_policy.threshold} failed attempts, "
        f"{f'{selected_policy.fixed_lock_seconds // 60}-minute lock' if selected_policy.lockout == 'fixed' else 'increasing wait'}, "
        f"MFA {selected_policy.mfa} · recovery {selected_policy.recovery} · "
        f"{TRAFFIC_LABELS[selected_traffic]}"
    )

    lockouts = prediction["legitimate_lockout_rate"]["mean"]
    attack_success = prediction["attack_success_rate"]["mean"]
    challenges = prediction["legitimate_challenge_rate"]["mean"]
    delay = prediction["avg_added_login_delay_seconds"]["mean"]
    peak = prediction["peak_hourly_lockouts"]["mean"]
    throughput = prediction["attack_throughput_per_hour"]["mean"]
    operational_issue = lockouts > float(thresholds["operational_lockout_rate"])
    security_issue = attack_success > float(thresholds["attack_success_rate"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Users locked out at least once", f"{lockouts * 100:.1f}%")
    if selected_traffic == "normal":
        attack_label = "No attack traffic"
    elif attack_success == 0:
        attack_label = "0 observed (below display precision)"
    else:
        attack_label = f"{attack_success * 100:.3f}%"
    col2.metric("Targeted accounts broken into", attack_label)
    col3.metric("Added login delay", f"{delay:.1f} seconds")

    lockout_ci = prediction["legitimate_lockout_rate"]
    attack_ci = prediction["attack_success_rate"]
    challenge_ci = prediction["legitimate_challenge_rate"]
    st.write(
        f"Across {settings.runs} runs, the estimate is that **{lockouts * 100:.1f}%** of users "
        f"may be locked out at least once (95% range {lockout_ci['ci_low'] * 100:.1f}%–"
        f"{lockout_ci['ci_high'] * 100:.1f}%). "
        f"The simulator predicts MFA for **{challenges * 100:.1f}%** of legitimate logins "
        f"(95% range {challenge_ci['ci_low'] * 100:.1f}%–{challenge_ci['ci_high'] * 100:.1f}%)."
    )
    if selected_traffic != "normal":
        st.write(
            f"For the selected synthetic attack traffic, the estimated share of targeted accounts "
            f"broken into is **{attack_success * 100:.3f}%** "
            f"(95% range {attack_ci['ci_low'] * 100:.3f}%–{attack_ci['ci_high'] * 100:.3f}%). "
            f"The simulated attack makes about **{throughput:.1f} attempts per hour**."
        )
    st.write(f"The busiest hour averages **{peak:.1f} locked accounts**.")

    flags = []
    if operational_issue:
        flags.append("Operational issue: more than 5% of users are locked out.")
    if selected_traffic != "normal" and security_issue:
        flags.append("Security issue: more than 1% of targeted accounts are broken into.")
    if flags:
        for flag in flags:
            st.warning(flag)
    else:
        st.success("The simulator did not flag an operational or security issue for this scenario.")

    replica = _replica_cell(selected_policy, selected_traffic)
    if replica is None:
        st.subheader("Predicted vs. replica")
        st.info("No matching replica result is available yet. Run the local replica experiment to compare.")
    else:
        chart_rows = []
        for measure in sorted(RATE_MEASURES):
            chart_rows.append(
                {
                    "Measure": measure.replace("_", " ").title(),
                    "Simulator prediction (%)": prediction[measure]["mean"] * 100,
                    "Replica observed (%)": float(replica[measure]) * 100,
                }
            )
        st.subheader("Predicted vs. replica")
        st.bar_chart(pd.DataFrame(chart_rows).set_index("Measure"))
        with st.expander("See all six measures"):
            comparison = []
            for measure in prediction:
                comparison.append(
                    {
                        "Measure": measure.replace("_", " ").title(),
                        "Simulator prediction": _format_measure(measure, prediction[measure]["mean"]),
                        "Replica observed": _format_measure(measure, float(replica[measure])),
                    }
                )
            st.dataframe(pd.DataFrame(comparison), hide_index=True, use_container_width=True)


if __name__ == "__main__":
    main()
