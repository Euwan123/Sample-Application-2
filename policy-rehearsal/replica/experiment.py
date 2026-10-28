from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

import numpy as np
import pandas as pd

from attacks.common import synthetic_password_candidates
from attacks.replay_traffic import DEFAULT_HELDOUT_PATH, read_heldout_sessions
from replica.service import MFA_CODE, ReplicaService, synthetic_password, synthetic_recovery_code
from simulator.model import (
    MEASURES,
    TRAFFIC_SCENARIOS,
    Policy,
    all_policies,
    load_settings,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "simulator" / "settings.yaml"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "observed.csv"


class VirtualClock:
    def __init__(self) -> None:
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.hour = 0
        self.minute = 0

    def set(self, hour: int, minute: int) -> None:
        self.hour = hour
        self.minute = minute

    def __call__(self) -> datetime:
        return self.start + timedelta(hours=self.hour, minutes=self.minute)


class ReplicaRunner(Protocol):
    clock: Callable[[], datetime]

    def reset_account_state(self) -> None: ...

    def login(
        self,
        account_id: str,
        password: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
        now: datetime | None = None,
        policy_override: Policy | None = None,
    ) -> dict[str, object]: ...

    def mfa(
        self,
        account_id: str,
        code: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]: ...

    def recover(
        self,
        account_id: str,
        recovery_code: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]: ...


def _account_id(index: int) -> str:
    return f"acct-{index:05d}"


def _attempts_per_day(rng: np.random.Generator, rate: float) -> int:
    return int(rng.poisson(rate))


def run_replica_cell(
    service: ReplicaRunner,
    policy: Policy,
    traffic: str,
    settings: Any,
    heldout_sessions: pd.DataFrame,
    seed: int,
    run_index: int,
) -> dict[str, float]:
    if traffic not in TRAFFIC_SCENARIOS:
        raise ValueError(f"traffic must be one of {TRAFFIC_SCENARIOS}")
    rng = np.random.default_rng(seed)
    service.reset_account_state()
    clock = service.clock
    lockouts_by_hour = np.zeros(settings.days * 24, dtype=int)
    locked_accounts: set[str] = set()
    attacker_locked_accounts: set[str] = set()
    legitimate_sessions = 0
    challenged_sessions = 0
    added_delay = 0.0
    targeted_accounts: set[str] = set()
    compromised_accounts: set[str] = set()
    attacker_requests = 0
    attacker_finished: set[str] = set()
    candidates = synthetic_password_candidates(settings.accounts, seed)

    if traffic == "brute_force":
        target_count = min(settings.accounts, settings.brute_accounts_targeted)
        target_indexes = rng.choice(settings.accounts, size=target_count, replace=False)
        attempt_rate = settings.brute_attempt_rate
        candidate_pool = candidates
    elif traffic == "credential_stuffing":
        target_count = min(settings.accounts, settings.stuffing_accounts_targeted)
        target_indexes = rng.choice(settings.accounts, size=target_count, replace=False)
        attempt_rate = settings.stuffing_attempt_rate
        candidate_pool = candidates[: min(settings.accounts, settings.stuffing_credential_list_size)]
    else:
        target_indexes = np.array([], dtype=int)
        attempt_rate = 0.0
        candidate_pool = []
    targeted_accounts = {_account_id(int(index)) for index in target_indexes}

    guesses_by_account: dict[str, list[str]] = {}
    for account_id in targeted_accounts:
        guesses = list(candidate_pool)
        rng.shuffle(guesses)
        guesses_by_account[account_id] = guesses
    guess_index = {account_id: 0 for account_id in targeted_accounts}

    def record_lock(account_id: str, virtual_hour: int, *, actor: str = "legitimate") -> None:
        if actor == "attacker":
            attacker_locked_accounts.add(account_id)
        if account_id not in locked_accounts:
            locked_accounts.add(account_id)
            lockouts_by_hour[virtual_hour] += 1

    for day in range(settings.days):
        events: list[tuple[int, float, str, str, Any]] = []
        for account_index in range(settings.accounts):
            if rng.random() >= 0.8:
                continue
            session = heldout_sessions.iloc[int(rng.integers(0, len(heldout_sessions)))]
            hour = day * 24 + int(rng.integers(0, 24))
            events.append((hour, float(rng.random()), "legitimate", _account_id(account_index), session))

        for account_id in targeted_accounts:
            for _ in range(_attempts_per_day(rng, attempt_rate)):
                hour = day * 24 + int(rng.integers(0, 24))
                events.append((hour, float(rng.random()), "attacker", account_id, None))

        events.sort(key=lambda event: (event[0], event[1]))
        for virtual_hour, _, actor, account_id, session in events:
            minute = int(rng.integers(0, 60))
            if isinstance(clock, VirtualClock):
                clock.set(virtual_hour, minute)
            else:
                raise TypeError("replica experiment requires the virtual clock")

            if actor == "attacker":
                if account_id in attacker_finished:
                    continue
                guesses = guesses_by_account[account_id]
                index = guess_index[account_id]
                if not guesses:
                    continue
                guess = guesses[index % len(guesses)]
                guess_index[account_id] += 1
                result = service.login(
                    account_id,
                    guess,
                    actor="attacker",
                    traffic=traffic,
                    run_index=run_index,
                    virtual_hour=virtual_hour,
                    now=clock(),
                    policy_override=policy,
                )
                attacker_requests += 1
                if result["outcome"] == "locked":
                    if result.get("new_lockout"):
                        record_lock(account_id, virtual_hour, actor="attacker")
                    attacker_finished.add(account_id)
                elif result["outcome"] == "success":
                    compromised_accounts.add(account_id)
                    attacker_finished.add(account_id)
                elif result["outcome"] == "mfa_challenge":
                    attacker_finished.add(account_id)
                continue

            legitimate_sessions += 1
            forgot_password = bool(session["forgot_password"])
            recovery_succeeded = (
                forgot_password
                and policy.recovery == "self_service"
                and rng.random() < settings.recovery_success_rate
            )
            if forgot_password and policy.recovery == "self_service":
                recovery = service.recover(
                    account_id,
                    synthetic_recovery_code(account_id)
                    if recovery_succeeded
                    else "synthetic-invalid-recovery",
                    actor="legitimate",
                    traffic=traffic,
                    run_index=run_index,
                    virtual_hour=virtual_hour,
                )
                if recovery["outcome"] == "recovery_success":
                    added_delay += settings.recovery_delay_seconds
            failures = int(session["failed_attempts"])
            attempts = int(session["login_attempts"])
            if forgot_password and not recovery_succeeded:
                failures = max(settings.max_retries, policy.threshold)
                attempts = max(attempts, failures)
            session_locked = False
            session_delay = 0.0
            for _ in range(min(failures, attempts)):
                result = service.login(
                    account_id,
                    f"synthetic-invalid-{rng.integers(0, 2**31)}",
                    actor="legitimate",
                    traffic=traffic,
                    run_index=run_index,
                    virtual_hour=virtual_hour,
                    now=clock(),
                    policy_override=policy,
                )
                session_delay += float(result["delay"])
                if result["outcome"] == "locked":
                    record_lock(account_id, virtual_hour)
                    session_locked = True
                    break

            if not session_locked and (not forgot_password or recovery_succeeded):
                result = service.login(
                    account_id,
                    synthetic_password(account_id),
                    actor="legitimate",
                    traffic=traffic,
                    run_index=run_index,
                    virtual_hour=virtual_hour,
                    now=clock(),
                    policy_override=policy,
                )
                session_delay += float(result["delay"])
                if result["outcome"] == "locked":
                    record_lock(account_id, virtual_hour)
                    session_locked = True
                elif result["outcome"] == "mfa_challenge":
                    challenged_sessions += 1
                    device_available = (
                        settings.mfa_device_at_hand
                        if pd.isna(session["mfa_device_available"])
                        else bool(session["mfa_device_available"])
                    )
                    if device_available:
                        service.mfa(
                            account_id,
                            MFA_CODE,
                            actor="legitimate",
                            traffic=traffic,
                            run_index=run_index,
                            virtual_hour=virtual_hour,
                        )
                    else:
                        session_delay += 30.0
            if session_locked:
                record_lock(account_id, virtual_hour)
            added_delay += session_delay

    attack_success_rate = (
        len(compromised_accounts) / len(targeted_accounts) if targeted_accounts else 0.0
    )
    return {
        "legitimate_lockout_rate": len(locked_accounts) / settings.accounts,
        "attacker_caused_lockout_rate": len(attacker_locked_accounts) / settings.accounts,
        "peak_hourly_lockouts": float(lockouts_by_hour.max(initial=0)),
        "legitimate_challenge_rate": challenged_sessions / max(legitimate_sessions, 1),
        "avg_added_login_delay_seconds": added_delay / max(legitimate_sessions, 1),
        "attack_success_rate": attack_success_rate,
        "attack_throughput_per_hour": attacker_requests / (settings.days * 24),
    }


def run_experiments(
    heldout_path: Path = DEFAULT_HELDOUT_PATH,
    settings_path: Path = DEFAULT_SETTINGS_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    database_path: Path | None = None,
    runs: int | None = None,
    progress: Callable[[int, int, Policy, str], None] | None = None,
) -> tuple[pd.DataFrame, Path]:
    settings = load_settings(settings_path)
    runs = settings.replica_runs if runs is None else runs
    if runs < 1:
        raise ValueError("replica runs must be positive")
    heldout = read_heldout_sessions(heldout_path)
    heldout_volunteers = heldout["volunteer_id"].nunique()
    if heldout_volunteers != 10:
        raise ValueError(
            f"replica experiments require exactly 10 held-out volunteers; found {heldout_volunteers}"
        )
    if not output_path.parent.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
    if database_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        database_path = output_path.parent / f"replica_runs_{timestamp}.sqlite3"
    if database_path.exists():
        raise FileExistsError(f"refusing to overwrite existing replica log database: {database_path}")
    database_path.parent.mkdir(parents=True, exist_ok=True)

    policies = all_policies()
    initial_policy = policies[0]
    service = ReplicaService(
        database_path,
        settings_path=settings_path,
        account_count=settings.accounts,
        sensitive_share=settings.sensitive_share,
        clock=VirtualClock(),
        policy=initial_policy,
        reuse_connection=True,
        defer_commits=True,
        fast_mode=True,
    )
    service.flush_logs()
    rows = []
    completed_cells = 0
    total_cells = len(policies) * len(TRAFFIC_SCENARIOS)
    for policy_index, policy in enumerate(policies):
        service.policy = policy
        for traffic_index, traffic in enumerate(TRAFFIC_SCENARIOS):
            cell_index = policy_index * len(TRAFFIC_SCENARIOS) + traffic_index
            samples = []
            for run_index in range(runs):
                samples.append(run_replica_cell(
                    service,
                    policy,
                    traffic,
                    settings,
                    heldout,
                    settings.seed + cell_index * runs + run_index,
                    run_index,
                ))
                service.flush_logs()
            row: dict[str, object] = {
                "policy": policy.label,
                "threshold": policy.threshold,
                "lockout": policy.lockout,
                "fixed_lock_seconds": policy.fixed_lock_seconds,
                "mfa": policy.mfa,
                "recovery": policy.recovery,
                "traffic": traffic,
                "runs": runs,
            }
            for measure in MEASURES:
                row[measure] = float(np.mean([sample[measure] for sample in samples]))
            rows.append(row)
            completed_cells += 1
            if progress is not None:
                progress(completed_cells, total_cells, policy, traffic)

    frame = pd.DataFrame(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False, float_format="%.8f")
    service.close()
    return frame, database_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay held-out sessions and bounded synthetic attacks through the local replica."
    )
    parser.add_argument("--heldout", type=Path, default=DEFAULT_HELDOUT_PATH)
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--database", type=Path, help="SQLite request log path; must not already exist.")
    parser.add_argument("--runs", type=int, help="Override the configured replica runs per cell.")
    args = parser.parse_args()

    def show_progress(done: int, total: int, policy: Policy, traffic: str) -> None:
        print(f"[{done}/{total}] {policy.label}, {traffic}", flush=True)

    frame, database_path = run_experiments(
        args.heldout, args.settings, args.output, args.database, args.runs, show_progress
    )
    print(f"Wrote {len(frame)} replica observation cells to {args.output}.")
    print(f"Detailed request log: {database_path}")


if __name__ == "__main__":
    main()
