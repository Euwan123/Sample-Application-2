from dataclasses import replace
from pathlib import Path

import pytest

from simulator.model import Policy, all_policies, load_policy, load_settings, simulate


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_policy_file_loads_shared_default_policy():
    assert load_policy(PROJECT_ROOT / "policies" / "policy.yaml") == Policy(
        10, "fixed", "none", 900, "self_service"
    )


def test_generation_contains_all_12_policy_combinations():
    policies = all_policies()
    assert len(policies) == 12
    assert len(
        {
            (
                policy.threshold,
                policy.lockout,
                policy.fixed_lock_seconds,
                policy.mfa,
            )
            for policy in policies
        }
    ) == 12
    assert Policy(10, "fixed", "none") in policies
    assert {policy.recovery for policy in policies} == {"self_service"}


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


def test_self_service_recovery_changes_forgotten_password_outcomes():
    settings = replace(
        load_settings(PROJECT_ROOT / "simulator" / "settings.yaml"),
        accounts=100,
        forget_rate=1.0,
        recovery_success_rate=1.0,
    )
    self_service = Policy(3, "fixed", "none", 900, "self_service")
    with_recovery = simulate(self_service, "normal", settings, seed=7)

    assert with_recovery["legitimate_lockout_rate"] == 0.0
    assert with_recovery["avg_added_login_delay_seconds"] > 0


def test_sensitive_mfa_challenges_some_logins():
    settings = replace(load_settings(PROJECT_ROOT / "simulator" / "settings.yaml"), accounts=100)
    sensitive = simulate(Policy(5, "fixed", "sensitive"), "normal", settings, seed=10)

    assert sensitive["legitimate_challenge_rate"] > 0


def test_attacker_lockouts_are_included_in_total_and_reported_separately():
    settings = replace(
        load_settings(PROJECT_ROOT / "simulator" / "settings.yaml"),
        accounts=20,
        sensitive_share=0.0,
        mistype_rate=0.0,
        forget_rate=0.0,
        brute_attempt_rate=100.0,
        brute_accounts_targeted=20,
        brute_credential_list_size=1_000_000_000,
    )
    policy = Policy(3, "fixed", "none")

    normal = simulate(policy, "normal", settings, seed=7)
    brute_force = simulate(policy, "brute_force", settings, seed=7)

    assert normal["legitimate_lockout_rate"] == 0
    assert normal["attacker_caused_lockout_rate"] == 0
    assert brute_force["attacker_caused_lockout_rate"] == 1
    assert brute_force["legitimate_lockout_rate"] == 1


@pytest.mark.parametrize(
    ("threshold", "lockout", "mfa"),
    [
        (4, "fixed", "none"),
        (5, "unknown", "none"),
        (5, "fixed", "invalid"),
    ],
)
def test_invalid_policy_values_are_rejected(threshold, lockout, mfa):
    with pytest.raises(ValueError):
        Policy(threshold, lockout, mfa)
