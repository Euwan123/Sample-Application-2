from __future__ import annotations

import argparse
from pathlib import Path

import httpx

from attacks.common import (
    DEFAULT_BASE_URL,
    DEFAULT_POLICY_PATH,
    DEFAULT_SETTINGS_PATH,
    MAX_TARGETS,
    attempt_budget,
    load_run_configuration,
    submit_login,
    synthetic_password_candidates,
    target_accounts,
    validate_local_target,
)


def synthetic_breached_credential_list(account_count: int, seed: int) -> list[str]:
    """Create a reproducible fake breach list from synthetic replica passwords."""
    return synthetic_password_candidates(account_count, seed)


def run_credential_stuffing(
    base_url: str,
    policy_path: Path = DEFAULT_POLICY_PATH,
    settings_path: Path = DEFAULT_SETTINGS_PATH,
    *,
    seed: int = 2,
    target_limit: int = MAX_TARGETS,
) -> dict[str, int]:
    base_url = validate_local_target(base_url)
    policy, settings = load_run_configuration(policy_path, settings_path)
    targets = target_accounts(settings.accounts, min(target_limit, settings.stuffing_accounts_targeted), seed)
    breached_credentials = synthetic_breached_credential_list(
        min(settings.accounts, settings.stuffing_credential_list_size), seed
    )
    budget = attempt_budget(settings.stuffing_attempt_rate, settings.days, policy.threshold)
    totals = {"requests": 0, "locked_accounts": 0, "compromised_accounts": 0}

    with httpx.Client(base_url=base_url, timeout=5.0) as client:
        for account_id in targets:
            for password in breached_credentials[:budget]:
                result = submit_login(
                    client,
                    account_id,
                    password,
                    actor="attacker",
                    traffic="credential_stuffing",
                )
                totals["requests"] += 1
                if result["outcome"] == "locked":
                    totals["locked_accounts"] += 1
                    break
                if result["outcome"] == "success":
                    totals["compromised_accounts"] += 1
                    break
                if result["outcome"] == "mfa_challenge":
                    break
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run bounded synthetic credential-stuffing traffic against the local replica."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS_PATH)
    parser.add_argument("--seed", type=int, default=2)
    parser.add_argument("--target-limit", type=int, default=MAX_TARGETS)
    args = parser.parse_args()
    try:
        validate_local_target(args.base_url)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        run_credential_stuffing(
            args.base_url, args.policy, args.settings, seed=args.seed, target_limit=args.target_limit
        )
    )


if __name__ == "__main__":
    main()
