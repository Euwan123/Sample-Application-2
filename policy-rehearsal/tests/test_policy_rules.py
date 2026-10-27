from pathlib import Path

import pytest

from dataclasses import replace

from simulator.model import Policy, all_policies, load_policy, load_settings, simulate


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_policy_file_loads_shared_default_policy():
    assert load_policy(PROJECT_ROOT / "policies" / "policy.yaml") == Policy(
        5, "fixed", "sensitive", 900, "self_service"
    )


def test_generation_contains_all_36_policy_combinations():
    policies = all_policies()
    assert len(policies) == 36
    assert len(
        {
            (
                policy.threshold,
                policy.lockout,
                policy.fixed_lock_seconds,
                policy.mfa,
                policy.recovery,
            )
            for policy in policies
        }
    ) == 36
    assert Policy(10, "fixed", "none") in policies


@pytest.mark.parametrize(
    ("policy", "failures", "expected_seconds"),
    [
        (Policy(5, "fixed", "none"), 4, 0),
        (Policy(5, "fixed", "none", 300), 5, 300),
        (Policy(5, "fixed", "none", 1800), 8, 1800),
        (Policy(3, "progressive", "none"), 3, 0),
        (Policy(3, "progressive", "none"), 4, 30),
        (Policy(3, "progressive", "none"), 5, 60),
        (Policy(3, "progressive", "none"), 10, 1920),
        (Policy(3, "progressive", "none"), 11, 3600),
    ],
)
def test_policy_lockout_rules_have_hand_computed_waits(policy, failures, expected_seconds):
    assert policy.lockout_seconds(failures) == expected_seconds


def test_recovery_policy_changes_forgotten_password_outcomes():
    settings = replace(
        load_settings(PROJECT_ROOT / "simulator" / "settings.yaml"),
        accounts=100,
        forget_rate=1.0,
        recovery_success_rate=1.0,
    )
    disabled = Policy(3, "fixed", "none", 300, "disabled")
    self_service = Policy(3, "fixed", "none", 300, "self_service")

    without_recovery = simulate(disabled, "normal", settings, seed=7)
    with_recovery = simulate(self_service, "normal", settings, seed=7)

    assert without_recovery["legitimate_lockout_rate"] == 1.0
    assert with_recovery["legitimate_lockout_rate"] == 0.0
    assert with_recovery["avg_added_login_delay_seconds"] > 0


def test_all_account_mfa_challenges_more_logins_than_sensitive_only():
    settings = replace(load_settings(PROJECT_ROOT / "simulator" / "settings.yaml"), accounts=100)
    sensitive = simulate(Policy(5, "fixed", "sensitive"), "normal", settings, seed=10)
    all_accounts = simulate(Policy(5, "fixed", "all"), "normal", settings, seed=10)

    assert all_accounts["legitimate_challenge_rate"] > sensitive["legitimate_challenge_rate"]


@pytest.mark.parametrize(
    ("threshold", "lockout", "mfa"),
    [(4, "fixed", "none"), (5, "unknown", "none"), (5, "fixed", "invalid")],
)
def test_invalid_policy_values_are_rejected(threshold, lockout, mfa):
    with pytest.raises(ValueError):
        Policy(threshold, lockout, mfa)
