from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from replica.main import create_app
from replica.service import MFA_CODE, ReplicaService, synthetic_password


class FakeClock:
    def __init__(self):
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


def create_test_files(tmp_path, policy_text):
    policy_path = tmp_path / "policy.yaml"
    settings_path = tmp_path / "settings.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
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
    return policy_path, settings_path


def create_service(tmp_path, policy_text, clock):
    policy_path, settings_path = create_test_files(tmp_path, policy_text)
    return ReplicaService(
tmp_path / "replica.sqlite3",
        policy_path,
        settings_path,
        clock=clock,
    )


def test_fixed_lockout_and_sqlite_request_logging(tmp_path):
    clock = FakeClock()
    service = create_service(tmp_path, "threshold: 3\nlockout: fixed\nmfa: none\n", clock)
    account = "acct-00002"

    assert service.login(account, "wrong")["outcome"] == "bad_credentials"
    assert service.login(account, "wrong")["outcome"] == "bad_credentials"
    locked = service.login(account, "wrong")
    assert locked["outcome"] == "locked"
    assert locked["delay"] == 900
    assert service.login(account, synthetic_password(account))["outcome"] == "locked"
    clock.advance(900)
    assert service.login(account, synthetic_password(account))["outcome"] == "success"

    with service._connect() as connection:
        rows = connection.execute(
            "SELECT account, outcome, delay, locked, mfa_challenged FROM request_log ORDER BY id"
        ).fetchall()
    assert len(rows) == 5
    assert rows[2]["locked"] == 1
    assert rows[3]["outcome"] == "locked"


def test_progressive_lockout_starts_after_threshold_free_failures(tmp_path):
    clock = FakeClock()
    service = create_service(tmp_path, "threshold: 3\nlockout: progressive\nmfa: none\n", clock)
    account = "acct-00002"

    for _ in range(3):
        assert service.login(account, "wrong")["outcome"] == "bad_credentials"
    first_wait = service.login(account, "wrong")
    assert first_wait["delay"] == 30
    clock.advance(30)
    second_wait = service.login(account, "wrong")
    assert second_wait["delay"] == 60


def test_sensitive_account_requires_mfa(tmp_path):
    clock = FakeClock()
    service = create_service(tmp_path, "threshold: 5\nlockout: fixed\nmfa: sensitive\n", clock)
    sensitive_account = "acct-00000"
    normal_account = "acct-00002"

    challenge = service.login(sensitive_account, synthetic_password(sensitive_account))
    assert challenge["outcome"] == "mfa_challenge"
    assert challenge["mfa_challenged"] is True
    assert service.mfa(sensitive_account, MFA_CODE)["outcome"] == "mfa_success"
    assert service.login(normal_account, synthetic_password(normal_account))["outcome"] == "success"


def test_all_accounts_mfa_and_self_service_recovery(tmp_path):
    clock = FakeClock()
    policy_text = (
        "threshold: 3\nlockout: fixed\nfixed_lock_seconds: 300\n"
        "mfa: all\nrecovery: self_service\n"
    )
    service = create_service(tmp_path, policy_text, clock)
    normal_account = "acct-00002"

    assert service.login(normal_account, synthetic_password(normal_account))["outcome"] == "mfa_challenge"
    for _ in range(3):
        service.login(normal_account, "wrong")
    assert service.recover(normal_account, "wrong")["outcome"] == "recovery_failed"
    from replica.service import synthetic_recovery_code

    assert service.recover(
        normal_account, synthetic_recovery_code(normal_account)
    )["outcome"] == "recovery_success"
    result = service.login(normal_account, synthetic_password(normal_account))
    assert result["outcome"] == "mfa_challenge"


def test_recovery_is_disabled_when_policy_says_disabled(tmp_path):
    clock = FakeClock()
    service = create_service(
        tmp_path,
        "threshold: 5\nlockout: fixed\nmfa: none\nrecovery: disabled\n",
        clock,
    )

    assert service.recover("acct-00002", "anything")["outcome"] == "recovery_disabled"


def test_configured_fixed_lock_duration_is_enforced(tmp_path):
    clock = FakeClock()
    service = create_service(
        tmp_path,
        "threshold: 3\nlockout: fixed\nfixed_lock_seconds: 300\nmfa: none\nrecovery: disabled\n",
        clock,
    )
    account = "acct-00002"
    for _ in range(2):
        assert service.login(account, "wrong")["outcome"] == "bad_credentials"
    assert service.login(account, "wrong")["delay"] == 300
    clock.advance(300)
    assert service.login(account, synthetic_password(account))["outcome"] == "success"


def test_http_recovery_endpoint_enforces_policy_and_resets_account(tmp_path):
    policy_path, settings_path = create_test_files(
        tmp_path,
        "threshold: 3\nlockout: fixed\nmfa: none\nrecovery: self_service\n",
    )
    app = create_app(
        tmp_path / "recovery-api.sqlite3",
        policy_path=policy_path,
        settings_path=settings_path,
        account_count=4,
        sensitive_share=0.5,
    )

    from replica.service import synthetic_recovery_code

    with TestClient(app) as client:
        for _ in range(3):
            client.post("/login", json={"account_id": "acct-00002", "password": "wrong"})
        response = client.post(
            "/recover",
            json={
                "account_id": "acct-00002",
                "recovery_code": synthetic_recovery_code("acct-00002"),
            },
        )
        assert response.status_code == 200
        assert response.json()["outcome"] == "recovery_success"
        response = client.post(
            "/login",
            json={
                "account_id": "acct-00002",
                "password": synthetic_password("acct-00002"),
            },
        )
        assert response.status_code == 200
        assert response.json()["outcome"] == "success"


def test_http_endpoints_return_expected_outcomes(tmp_path):
    policy_path, settings_path = create_test_files(
        tmp_path, "threshold: 5\nlockout: fixed\nmfa: sensitive\n"
    )
    app = create_app(
        tmp_path / "api.sqlite3",
        policy_path=policy_path,
        settings_path=settings_path,
        account_count=4,
        sensitive_share=0.5,
    )

    with TestClient(app) as client:
        response = client.post(
            "/login",
            json={"account_id": "acct-00000", "password": synthetic_password("acct-00000")},
            headers={
                "X-Traffic-Actor": "attacker",
                "X-Traffic-Scenario": "brute_force",
                "X-Run-Index": "2",
                "X-Virtual-Hour": "19",
            },
        )
        assert response.status_code == 200
        assert response.json()["outcome"] == "mfa_challenge"
        response = client.post("/mfa", json={"account_id": "acct-00000", "code": MFA_CODE})
        assert response.status_code == 200
        assert response.json()["outcome"] == "mfa_success"
        with app.state.replica_service._connect() as connection:
            row = connection.execute(
                "SELECT actor, traffic, run_index, virtual_hour FROM request_log ORDER BY id LIMIT 1"
            ).fetchone()
        assert tuple(row) == ("attacker", "brute_force", 2, 19)
