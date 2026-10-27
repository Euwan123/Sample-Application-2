from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any

import numpy as np
import yaml


LOCKOUT_TYPES = ("fixed", "progressive")
MFA_MODES = ("none", "sensitive", "all")
RECOVERY_MODES = ("disabled", "self_service")
THRESHOLDS = (10, 5, 3)
TRAFFIC_SCENARIOS = ("normal", "brute_force", "credential_stuffing")
MEASURES = (
    "legitimate_lockout_rate",
    "peak_hourly_lockouts",
    "legitimate_challenge_rate",
    "avg_added_login_delay_seconds",
    "attack_success_rate",
    "attack_throughput_per_hour",
)
RATE_MEASURES = {
    "legitimate_lockout_rate",
    "legitimate_challenge_rate",
    "attack_success_rate",
}


@dataclass(frozen=True)
class Policy:
    threshold: int
    lockout: str
    mfa: str
    fixed_lock_seconds: int = 900
    recovery: str = "disabled"

    def __post_init__(self) -> None:
        if self.threshold not in THRESHOLDS:
            raise ValueError(f"threshold must be one of {THRESHOLDS}")
        if self.lockout not in LOCKOUT_TYPES:
            raise ValueError(f"lockout must be one of {LOCKOUT_TYPES}")
        if self.mfa not in MFA_MODES:
            raise ValueError(f"mfa must be one of {MFA_MODES}")
        if self.fixed_lock_seconds < 1:
            raise ValueError("fixed_lock_seconds must be positive")
        if self.recovery not in RECOVERY_MODES:
            raise ValueError(f"recovery must be one of {RECOVERY_MODES}")

    def lockout_seconds(self, consecutive_failures: int) -> int:
        """Return the wait caused by this failure count; zero means no lockout."""
        if consecutive_failures < 1:
            return 0
        if self.lockout == "fixed":
            return self.fixed_lock_seconds if consecutive_failures >= self.threshold else 0
        if consecutive_failures <= self.threshold:
            return 0
        return min(30 * 2 ** (consecutive_failures - self.threshold - 1), 3600)

    @property
    def label(self) -> str:
        return (
            f"{self.threshold}-{self.lockout}-{self.fixed_lock_seconds}s-"
            f"{self.mfa}-{self.recovery}"
        )


@dataclass(frozen=True)
class SimulationSettings:
    days: int
    accounts: int
    sensitive_share: float
    runs: int
    replica_runs: int
    confidence_level: float
    seed: int
    mistype_rate: float
    forget_rate: float
    max_retries: int
    mfa_device_at_hand: float
    recovery_success_rate: float
    recovery_delay_seconds: float
    brute_attempt_rate: float
    brute_accounts_targeted: int
    brute_credential_list_size: int
    stuffing_attempt_rate: float
    stuffing_accounts_targeted: int
    stuffing_credential_list_size: int


def load_policy(path: Path) -> Policy:
    with path.open(encoding="utf-8") as stream:
        values = yaml.safe_load(stream)
    if not isinstance(values, dict):
        raise ValueError("policy YAML must contain a mapping")
    required = {"threshold", "lockout", "mfa"}
    optional = {"fixed_lock_seconds", "recovery"}
    if not required.issubset(values) or set(values) - required - optional:
        raise ValueError("policy YAML must contain threshold, lockout, mfa, and supported optional policy fields")
    return Policy(**values)


def load_settings(path: Path) -> SimulationSettings:
    with path.open(encoding="utf-8") as stream:
        raw: dict[str, Any] = yaml.safe_load(stream)
    try:
        sim, users, attackers = raw["simulation"], raw["users"], raw["attackers"]
        brute, stuffing = attackers["brute_force"], attackers["credential_stuffing"]
        settings = SimulationSettings(
            days=int(sim["days"]),
            accounts=int(sim["accounts"]),
            sensitive_share=float(sim["sensitive_share"]),
            runs=int(sim["runs"]),
            replica_runs=int(sim["replica_runs"]),
            confidence_level=float(sim["confidence_level"]),
            seed=int(sim["seed"]),
            mistype_rate=float(users["mistype_rate"]),
            forget_rate=float(users["forget_rate"]),
            max_retries=int(users["max_retries"]),
            mfa_device_at_hand=float(users["mfa_device_at_hand"]),
            recovery_success_rate=float(users["recovery_success_rate"]),
            recovery_delay_seconds=float(users["recovery_delay_seconds"]),
            brute_attempt_rate=float(brute["attempt_rate"]),
            brute_accounts_targeted=int(brute["accounts_targeted"]),
            brute_credential_list_size=int(brute["credential_list_size"]),
            stuffing_attempt_rate=float(stuffing["attempt_rate"]),
            stuffing_accounts_targeted=int(stuffing["accounts_targeted"]),
            stuffing_credential_list_size=int(stuffing["credential_list_size"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid simulator settings: {exc}") from exc

    for name in (
        "mistype_rate",
        "forget_rate",
        "sensitive_share",
        "mfa_device_at_hand",
        "recovery_success_rate",
    ):
        value = getattr(settings, name)
        if not 0 <= value <= 1:
            raise ValueError(f"{name} must be between 0 and 1")
    if settings.days < 1 or settings.accounts < 1 or settings.runs < 1 or settings.replica_runs < 1:
        raise ValueError("days, accounts, runs, and replica_runs must be positive")
    if not 0 < settings.confidence_level < 1:
        raise ValueError("confidence_level must be between 0 and 1")
    if settings.max_retries < 1 or settings.brute_credential_list_size < 1 or settings.stuffing_credential_list_size < 1:
        raise ValueError("retry and credential-list sizes must be positive")
    if settings.brute_attempt_rate < 0 or settings.stuffing_attempt_rate < 0:
        raise ValueError("attacker attempt rates cannot be negative")
    if settings.brute_accounts_targeted < 0 or settings.stuffing_accounts_targeted < 0:
        raise ValueError("targeted-account counts cannot be negative")
    if settings.recovery_delay_seconds < 0:
        raise ValueError("recovery_delay_seconds cannot be negative")
    return settings


def all_policies(fixed_lock_seconds: int = 900) -> list[Policy]:
    return [
        Policy(threshold, lockout, mfa, fixed_lock_seconds, recovery)
        for threshold, lockout, mfa, recovery in product(
            THRESHOLDS, LOCKOUT_TYPES, MFA_MODES, RECOVERY_MODES
        )
    ]


def simulate(
    policy: Policy,
    traffic: str,
    settings: SimulationSettings,
    seed: int,
) -> dict[str, float]:
    if traffic not in TRAFFIC_SCENARIOS:
        raise ValueError(f"traffic must be one of {TRAFFIC_SCENARIOS}")

    rng = np.random.default_rng(seed)
    accounts = settings.accounts
    sensitive_count = round(accounts * settings.sensitive_share)
    sensitive = np.arange(accounts) < sensitive_count
    lockout_seen = np.zeros(accounts, dtype=bool)
    hourly_lockouts = np.zeros(settings.days * 24, dtype=int)
    legit_login_count = 0
    challenged_count = 0
    added_delay = 0.0

    for day in range(settings.days):
        for account in range(accounts):
            if rng.random() >= 0.8:
                continue
            legit_login_count += 1
            hour = day * 24 + int(rng.integers(0, 24))
            requires_mfa = policy.mfa == "all" or (
                policy.mfa == "sensitive" and sensitive[account]
            )
            if requires_mfa:
                challenged_count += 1
                if not rng.random() < settings.mfa_device_at_hand:
                    added_delay += 30.0

            forgot_password = rng.random() < settings.forget_rate
            if forgot_password and policy.recovery == "self_service" and (
                rng.random() < settings.recovery_success_rate
            ):
                added_delay += settings.recovery_delay_seconds
                failures = 0
            elif forgot_password:
                failures = max(settings.max_retries, policy.threshold)
            else:
                failures = 0
                while failures < settings.max_retries and rng.random() < settings.mistype_rate:
                    failures += 1

            wait_seconds = policy.lockout_seconds(failures)
            if wait_seconds:
                added_delay += wait_seconds
                if not lockout_seen[account]:
                    lockout_seen[account] = True
                    hourly_lockouts[hour] += 1

    if traffic == "normal":
        targeted = 0
        attacker_attempts = 0.0
        compromised = 0
    else:
        is_brute = traffic == "brute_force"
        target_limit = settings.brute_accounts_targeted if is_brute else settings.stuffing_accounts_targeted
        targeted = min(accounts, target_limit)
        rate = settings.brute_attempt_rate if is_brute else settings.stuffing_attempt_rate
        list_size = settings.brute_credential_list_size if is_brute else settings.stuffing_credential_list_size
        attacker_attempts = rate * targeted * settings.days
        attempts_per_target = attacker_attempts / max(targeted, 1)
        guess_probability = min(0.25, attempts_per_target / list_size)
        policy_factor = 1.0 / (1.0 + max(policy.threshold - 1, 0) * 0.08)
        protected_share = (
            1.0
            if policy.mfa == "all"
            else settings.sensitive_share
            if policy.mfa == "sensitive"
            else 0.0
        )
        mfa_factor = 1.0 - protected_share * (1.0 - 0.03)
        compromised = int(np.count_nonzero(rng.random(targeted) < guess_probability * policy_factor * mfa_factor))

    return {
        "legitimate_lockout_rate": float(lockout_seen.sum() / accounts),
        "peak_hourly_lockouts": float(hourly_lockouts.max(initial=0)),
        "legitimate_challenge_rate": float(challenged_count / max(legit_login_count, 1)),
        "avg_added_login_delay_seconds": float(added_delay / max(legit_login_count, 1)),
        "attack_success_rate": float(compromised / max(targeted, 1)),
        "attack_throughput_per_hour": float(attacker_attempts / (settings.days * 24)),
    }
