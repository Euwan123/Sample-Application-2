import sqlite3

import pytest
from fastapi.testclient import TestClient

from attacks.common import validate_local_target
from compare.http_check import selected_http_cells, validate_replica_database
from replica.main import create_app
from simulator.model import Policy, all_policies


def test_http_check_selects_two_policies_across_all_three_scenarios():
    cells = selected_http_cells()

    assert len(cells) == 6
    assert len({policy for _, policy, _ in cells}) == 2
    assert {traffic for _, _, traffic in cells} == {
        "normal",
        "brute_force",
        "credential_stuffing",
    }
    assert {policy for _, policy, _ in cells} == {
        all_policies()[0],
        all_policies()[-1],
    }


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8000",
        "http://example.com:8000",
        "http://127.0.0.1:8001",
        "http://127.0.0.1:8000/path",
    ],
)
def test_http_check_rejects_non_local_or_unapproved_targets(url):
    with pytest.raises(ValueError, match="Refusing to run"):
        validate_local_target(url)


def test_http_check_accepts_local_replica_container_url():
    assert validate_local_target("http://replica:8000/") == "http://replica:8000"


def test_http_experiment_policy_override_uses_virtual_clock(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "threshold: 10\nlockout: fixed\nfixed_lock_seconds: 900\n"
        "mfa: none\nrecovery: self_service\n",
        encoding="utf-8",
    )
    settings_path = tmp_path / "settings.yaml"
    settings_path.write_text(
        """
simulation:
  days: 7
  accounts: 4
  sensitive_share: 0.5
  runs: 1
  replica_runs: 1
  confidence_level: 0.95
  seed: 1
users:
  mistype_rate: 0.1
  forget_rate: 0.004
  max_retries: 8
  mfa_device_at_hand: 0.9
  recovery_success_rate: 0.9
  recovery_delay_seconds: 300
attackers:
  brute_force:
    attempt_rate: 2
    accounts_targeted: 2
    credential_list_size: 10
  credential_stuffing:
    attempt_rate: 2
    accounts_targeted: 2
    credential_list_size: 10
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("REPLICA_EXPERIMENT_MODE", "1")
    app = create_app(
        tmp_path / "replica.sqlite3",
        policy_path,
        settings_path,
        account_count=4,
        sensitive_share=0.5,
    )
    policy = next(
        policy
        for policy in all_policies()
        if policy == Policy(3, "fixed", "none")
    )

    with TestClient(app) as client:
        results = [
            client.post(
                "/login",
                json={"account_id": "acct-00002", "password": "wrong"},
                headers={
                    "X-Experiment-Policy": policy.label,
                    "X-Virtual-Hour": "24",
                    "X-Virtual-Minute": "15",
                },
            )
            for _ in range(3)
        ]

    assert [response.status_code for response in results] == [401, 401, 423]
    assert results[-1].json()["detail"]["new_lockout"] is True


def test_http_check_database_rejects_mismatched_account_settings(tmp_path):
    database_path = tmp_path / "replica.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE accounts (account_id TEXT, sensitive INTEGER, failure_count INTEGER, "
            "locked_until TEXT, mfa_pending INTEGER)"
        )
        connection.executemany(
            "INSERT INTO accounts VALUES (?, ?, 0, NULL, 0)",
            [("acct-00000", 1), ("acct-00001", 0)],
        )

    with pytest.raises(ValueError, match="does not match simulator settings"):
        validate_replica_database(database_path, account_count=4, sensitive_share=0.5)
