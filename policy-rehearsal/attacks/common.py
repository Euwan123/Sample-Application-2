from __future__ import annotations

import math
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from replica.service import synthetic_password
from simulator.model import Policy, SimulationSettings, load_policy, load_settings


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "policies" / "policy.yaml"
DEFAULT_SETTINGS_PATH = PROJECT_ROOT / "simulator" / "settings.yaml"
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "replica"})
ALLOWED_PORT = 8000
MAX_TARGETS = 100


def validate_local_target(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.port != ALLOWED_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Refusing to run: target must be plain HTTP on localhost or the replica container at port 8000."
        )
    return base_url.rstrip("/")


def load_run_configuration(
    policy_path: Path, settings_path: Path
) -> tuple[Policy, SimulationSettings]:
    return load_policy(policy_path), load_settings(settings_path)


def attempt_budget(attempt_rate: float, days: int, threshold: int) -> int:
    if attempt_rate <= 0:
        return 0
    return min(threshold, math.ceil(attempt_rate * days))


def target_accounts(account_count: int, requested: int, seed: int) -> list[str]:
    if account_count < 1:
        raise ValueError("account_count must be positive")
    if requested < 0 or requested > MAX_TARGETS:
        raise ValueError(f"target count must be between 0 and {MAX_TARGETS}")
    if requested == 0:
        return []
    import random

    indexes = random.Random(seed).sample(range(account_count), min(account_count, requested))
    return [f"acct-{index:05d}" for index in indexes]


def parse_response(response: httpx.Response) -> dict[str, object]:
    payload = response.json()
    result = payload.get("detail", payload)
    if not isinstance(result, dict) or "outcome" not in result:
        raise RuntimeError(f"replica returned an unexpected response ({response.status_code})")
    return result


def submit_login(
    client: httpx.Client,
    account_id: str,
    password: str,
    *,
    actor: str = "legitimate",
    traffic: str = "normal",
) -> dict[str, object]:
    response = client.post(
        "/login",
        json={"account_id": account_id, "password": password},
        headers={"X-Traffic-Actor": actor, "X-Traffic-Scenario": traffic},
    )
    return parse_response(response)


def synthetic_password_candidates(account_count: int, seed: int) -> list[str]:
    import random

    candidates = [
        synthetic_password(f"acct-{index:05d}")
        for index in range(account_count)
    ]
    random.Random(seed).shuffle(candidates)
    return candidates
