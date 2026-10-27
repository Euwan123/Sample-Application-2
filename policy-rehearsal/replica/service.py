from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from simulator.model import Policy, load_policy, load_settings


DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "policy.yaml"
DEFAULT_SETTINGS_PATH = Path(__file__).resolve().parents[1] / "simulator" / "settings.yaml"
MFA_CODE = "246810"


def synthetic_recovery_code(account_id: str) -> str:
    return f"synthetic-recovery-{account_id}"


class _DeferredConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def __enter__(self) -> _DeferredConnection:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            self._connection.rollback()
        return False

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        self._connection.rollback()


def synthetic_password(account_id: str) -> str:
    return f"synthetic-password-{account_id}"


class ReplicaService:
    def __init__(
        self,
        database_path: Path,
        policy_path: Path = DEFAULT_POLICY_PATH,
        settings_path: Path = DEFAULT_SETTINGS_PATH,
        *,
        account_count: int | None = None,
        sensitive_share: float | None = None,
        clock: Callable[[], datetime] | None = None,
        policy: Policy | None = None,
        reuse_connection: bool = False,
        defer_commits: bool = False,
        fast_mode: bool = False,
    ) -> None:
        self.database_path = database_path
        self.policy = policy or load_policy(policy_path)
        settings = load_settings(settings_path)
        self.account_count = account_count if account_count is not None else settings.accounts
        self.sensitive_share = sensitive_share if sensitive_share is not None else settings.sensitive_share
        if self.account_count < 1:
            raise ValueError("account_count must be positive")
        if not 0 <= self.sensitive_share <= 1:
            raise ValueError("sensitive_share must be between 0 and 1")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._defer_commits = defer_commits
        self._shared_connection = None
        self._fast_mode = fast_mode
        self._memory_accounts: dict[str, dict[str, object]] | None = None
        self._memory_pepper: str | None = None
        self._log_buffer: list[tuple[object, ...]] = []
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if reuse_connection:
            self._shared_connection = sqlite3.connect(self.database_path)
            self._shared_connection.row_factory = sqlite3.Row
        self._initialize()
        if self._fast_mode:
            with self._connect() as connection:
                self._memory_pepper = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'password_pepper'"
                ).fetchone()["value"]
                rows = connection.execute(
                    """
                    SELECT account_id, sensitive, password_digest, failure_count,
                           locked_until, mfa_pending
                    FROM accounts
                    """
                ).fetchall()
            self._memory_accounts = {
                row["account_id"]: {
                    "sensitive": bool(row["sensitive"]),
                    "password_digest": row["password_digest"],
                    "failure_count": int(row["failure_count"]),
                    "locked_until": datetime.fromisoformat(row["locked_until"])
                    if row["locked_until"]
                    else None,
                    "mfa_pending": bool(row["mfa_pending"]),
                }
                for row in rows
            }

    def _connect(self) -> sqlite3.Connection | _DeferredConnection:
        if self._shared_connection is not None:
            if self._defer_commits:
                return _DeferredConnection(self._shared_connection)
            return self._shared_connection
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    sensitive INTEGER NOT NULL,
                    password_digest TEXT NOT NULL,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    locked_until TEXT,
                    mfa_pending INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS request_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT NOT NULL,
                    account TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    delay REAL NOT NULL,
                    locked INTEGER NOT NULL,
                    mfa_challenged INTEGER NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'legitimate',
                    traffic TEXT NOT NULL DEFAULT 'normal',
                    policy TEXT NOT NULL DEFAULT '',
                    run_index INTEGER NOT NULL DEFAULT 0,
                    virtual_hour INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            existing_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(request_log)")
            }
            additions = {
                "actor": "TEXT NOT NULL DEFAULT 'legitimate'",
                "traffic": "TEXT NOT NULL DEFAULT 'normal'",
                "policy": "TEXT NOT NULL DEFAULT ''",
                "run_index": "INTEGER NOT NULL DEFAULT 0",
                "virtual_hour": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, definition in additions.items():
                if name not in existing_columns:
                    connection.execute(f"ALTER TABLE request_log ADD COLUMN {name} {definition}")
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'password_pepper'"
            ).fetchone()
            if row is None:
                pepper = secrets.token_hex(32)
                connection.execute(
                    "INSERT INTO metadata (key, value) VALUES ('password_pepper', ?)",
                    (pepper,),
                )
            else:
                pepper = row["value"]

            existing = connection.execute("SELECT COUNT(*) AS count FROM accounts").fetchone()["count"]
            if existing == 0:
                sensitive_count = round(self.account_count * self.sensitive_share)
                accounts = []
                for index in range(self.account_count):
                    account_id = f"acct-{index:05d}"
                    password_digest = self._password_digest(synthetic_password(account_id), pepper)
                    accounts.append((account_id, int(index < sensitive_count), password_digest))
                connection.executemany(
                    "INSERT INTO accounts (account_id, sensitive, password_digest) VALUES (?, ?, ?)",
                    accounts,
                )

    @staticmethod
    def _password_digest(password: str, pepper: str) -> str:
        return hmac.new(pepper.encode("ascii"), password.encode("utf-8"), hashlib.sha256).hexdigest()

    def _log(
        self,
        account_id: str,
        outcome: str,
        delay: float = 0.0,
        locked: bool = False,
        mfa_challenged: bool = False,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        policy_label: str | None = None,
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]:
        timestamp = self.clock().astimezone(timezone.utc).isoformat()
        policy_value = policy_label or self.policy.label
        log_entry = (
            timestamp,
            account_id,
            outcome,
            delay,
            int(locked),
            int(mfa_challenged),
            actor,
            traffic,
            policy_value,
            run_index,
            virtual_hour,
        )
        if self._fast_mode:
            self._log_buffer.append(log_entry)
        else:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO request_log (
                        time, account, outcome, delay, locked, mfa_challenged,
                        actor, traffic, policy, run_index, virtual_hour
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    log_entry,
                )
        return {
            "time": timestamp,
            "account": account_id,
            "outcome": outcome,
            "delay": delay,
            "locked": locked,
            "mfa_challenged": mfa_challenged,
            "actor": actor,
            "traffic": traffic,
            "policy": policy_value,
            "run_index": run_index,
            "virtual_hour": virtual_hour,
        }

    def login(
        self,
        account_id: str,
        password: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]:
        def record(
            outcome: str,
            delay: float = 0.0,
            locked: bool = False,
            mfa_challenged: bool = False,
        ) -> dict[str, object]:
            return self._log(
                account_id,
                outcome,
                delay,
                locked,
                mfa_challenged,
                actor=actor,
                traffic=traffic,
                run_index=run_index,
                virtual_hour=virtual_hour,
            )

        now = self.clock().astimezone(timezone.utc)
        if self._memory_accounts is not None:
            account = self._memory_accounts.get(account_id)
            if account is None:
                return record("unknown_account")
            locked_until = account["locked_until"]
            if isinstance(locked_until, datetime):
                remaining = max(0.0, (locked_until - now).total_seconds())
                if remaining > 0:
                    return record("locked", remaining, locked=True)
                account["locked_until"] = None
            if self._memory_pepper is None:
                raise RuntimeError("fast-mode credential key has not been initialized")
            if not hmac.compare_digest(
                self._password_digest(password, self._memory_pepper),
                str(account["password_digest"]),
            ):
                failures = int(account["failure_count"]) + 1
                wait_seconds = self.policy.lockout_seconds(failures)
                account["failure_count"] = failures
                account["locked_until"] = (
                    now + timedelta(seconds=wait_seconds) if wait_seconds else None
                )
                return record(
                    "locked" if wait_seconds else "bad_credentials",
                    float(wait_seconds),
                    locked=bool(wait_seconds),
                )
            account["failure_count"] = 0
            account["locked_until"] = None
            requires_mfa = self.policy.mfa == "all" or (
                self.policy.mfa == "sensitive" and bool(account["sensitive"])
            )
            if requires_mfa:
                account["mfa_pending"] = True
                return record("mfa_challenge", mfa_challenged=True)
            account["mfa_pending"] = False
            return record("success")

        with self._connect() as connection:
            account = connection.execute(
                """
                SELECT account_id, sensitive, password_digest, failure_count, locked_until
                FROM accounts WHERE account_id = ?
                """,
                (account_id,),
            ).fetchone()
            if account is None:
                connection.commit()
                return record("unknown_account")

            if account["locked_until"]:
                locked_until = datetime.fromisoformat(account["locked_until"])
                remaining = max(0.0, (locked_until - now).total_seconds())
                if remaining > 0:
                    connection.commit()
                    return record("locked", remaining, locked=True)
                connection.execute(
                    "UPDATE accounts SET locked_until = NULL WHERE account_id = ?", (account_id,)
                )

            pepper = connection.execute(
                "SELECT value FROM metadata WHERE key = 'password_pepper'"
            ).fetchone()["value"]
            expected = account["password_digest"]
            actual = self._password_digest(password, pepper)
            if not hmac.compare_digest(actual, expected):
                failures = account["failure_count"] + 1
                wait_seconds = self.policy.lockout_seconds(failures)
                locked_until = (
                    (now + timedelta(seconds=wait_seconds)).isoformat() if wait_seconds else None
                )
                connection.execute(
                    """
                    UPDATE accounts
                    SET failure_count = ?, locked_until = ?
                    WHERE account_id = ?
                    """,
                    (failures, locked_until, account_id),
                )
                connection.commit()
                return record(
                    "locked" if wait_seconds else "bad_credentials",
                    float(wait_seconds),
                    locked=bool(wait_seconds),
                )

            connection.execute(
                "UPDATE accounts SET failure_count = 0, locked_until = NULL WHERE account_id = ?",
                (account_id,),
            )
            requires_mfa = self.policy.mfa == "all" or (
                self.policy.mfa == "sensitive" and account["sensitive"]
            )
            if requires_mfa:
                connection.execute(
                    "UPDATE accounts SET mfa_pending = 1 WHERE account_id = ?", (account_id,)
                )
                connection.commit()
                return record("mfa_challenge", mfa_challenged=True)

            connection.execute(
                "UPDATE accounts SET mfa_pending = 0 WHERE account_id = ?", (account_id,)
            )
            connection.commit()
            return record("success")

    def mfa(
        self,
        account_id: str,
        code: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]:
        def record(outcome: str) -> dict[str, object]:
            return self._log(
                account_id,
                outcome,
                mfa_challenged=True,
                actor=actor,
                traffic=traffic,
                run_index=run_index,
                virtual_hour=virtual_hour,
            )

        if self._memory_accounts is not None:
            account = self._memory_accounts.get(account_id)
            if account is None:
                return record("unknown_account")
            if not bool(account["mfa_pending"]):
                return record("mfa_not_pending")
            outcome = "mfa_success" if hmac.compare_digest(code, MFA_CODE) else "mfa_failed"
            if outcome == "mfa_success":
                account["mfa_pending"] = False
            return record(outcome)

        with self._connect() as connection:
            account = connection.execute(
                "SELECT mfa_pending FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            if account is None:
                connection.commit()
                return record("unknown_account")
            if not account["mfa_pending"]:
                connection.commit()
                return record("mfa_not_pending")
            outcome = "mfa_success" if hmac.compare_digest(code, MFA_CODE) else "mfa_failed"
            if outcome == "mfa_success":
                connection.execute(
                    "UPDATE accounts SET mfa_pending = 0 WHERE account_id = ?", (account_id,)
                )
            connection.commit()
            return record(outcome)

    def recover(
        self,
        account_id: str,
        recovery_code: str,
        *,
        actor: str = "legitimate",
        traffic: str = "normal",
        run_index: int = 0,
        virtual_hour: int = 0,
    ) -> dict[str, object]:
        def record(outcome: str) -> dict[str, object]:
            return self._log(
                account_id,
                outcome,
                actor=actor,
                traffic=traffic,
                run_index=run_index,
                virtual_hour=virtual_hour,
            )

        if self.policy.recovery != "self_service":
            return record("recovery_disabled")
        if not hmac.compare_digest(recovery_code, synthetic_recovery_code(account_id)):
            return record("recovery_failed")
        if self._memory_accounts is not None:
            account = self._memory_accounts.get(account_id)
            if account is None:
                return record("unknown_account")
            account["failure_count"] = 0
            account["locked_until"] = None
            account["mfa_pending"] = False
            return record("recovery_success")
        with self._connect() as connection:
            account = connection.execute(
                "SELECT account_id FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            if account is None:
                connection.commit()
                return record("unknown_account")
            connection.execute(
                """
                UPDATE accounts
                SET failure_count = 0, locked_until = NULL, mfa_pending = 0
                WHERE account_id = ?
                """,
                (account_id,),
            )
            connection.commit()
        return record("recovery_success")

    def reset_account_state(self) -> None:
        if self._memory_accounts is not None:
            for account in self._memory_accounts.values():
                account["failure_count"] = 0
                account["locked_until"] = None
                account["mfa_pending"] = False
            return
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE accounts
                SET failure_count = 0, locked_until = NULL, mfa_pending = 0
                """
            )

    def commit(self) -> None:
        if self._shared_connection is not None:
            self._shared_connection.commit()

    def flush_logs(self) -> None:
        if not self._fast_mode:
            self.commit()
            return
        if self._shared_connection is None or self._memory_accounts is None:
            raise RuntimeError("fast mode requires an initialized shared SQLite connection")
        if self._log_buffer:
            self._shared_connection.executemany(
                """
                INSERT INTO request_log (
                    time, account, outcome, delay, locked, mfa_challenged,
                    actor, traffic, policy, run_index, virtual_hour
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._log_buffer,
            )
        self._shared_connection.executemany(
            """
            UPDATE accounts
            SET failure_count = ?, locked_until = ?, mfa_pending = ?
            WHERE account_id = ?
            """,
            [
                (
                    int(account["failure_count"]),
                    account["locked_until"].isoformat()
                    if isinstance(account["locked_until"], datetime)
                    else None,
                    int(bool(account["mfa_pending"])),
                    account_id,
                )
                for account_id, account in self._memory_accounts.items()
            ],
        )
        self._shared_connection.commit()
        self._log_buffer.clear()

    def close(self) -> None:
        if self._shared_connection is not None:
            if self._fast_mode and self._log_buffer:
                self.flush_logs()
            else:
                self._shared_connection.commit()
            self._shared_connection.close()
            self._shared_connection = None
