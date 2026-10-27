from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from replica.service import DEFAULT_POLICY_PATH, DEFAULT_SETTINGS_PATH, ReplicaService


class LoginRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class MFARequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=1, max_length=32)

class RecoveryRequest(BaseModel):
    account_id: str = Field(min_length=1, max_length=64)
    recovery_code: str = Field(min_length=1, max_length=128)


def create_app(
    database_path: Path | None = None,
    policy_path: Path = DEFAULT_POLICY_PATH,
    settings_path: Path = DEFAULT_SETTINGS_PATH,
    *,
    account_count: int | None = None,
    sensitive_share: float | None = None,
) -> FastAPI:
    default_database = Path(__file__).resolve().parents[1] / "data" / "replica.sqlite3"
    database_path = database_path or Path(os.environ.get("REPLICA_DB", default_database))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.replica_service = ReplicaService(
            database_path,
            policy_path,
            settings_path,
            account_count=account_count,
            sensitive_share=sensitive_share,
        )
        yield

    app = FastAPI(title="Policy Rehearsal Replica", version="1.0.0", lifespan=lifespan)

    @app.post("/login")
    def login(
        payload: LoginRequest,
        request: Request,
        actor: str = Header(default="legitimate", alias="X-Traffic-Actor"),
        traffic: str = Header(default="normal", alias="X-Traffic-Scenario"),
        run_index: int = Header(default=0, alias="X-Run-Index"),
        virtual_hour: int = Header(default=0, alias="X-Virtual-Hour"),
    ) -> dict[str, object]:
        service: ReplicaService = request.app.state.replica_service
        result = service.login(
            payload.account_id,
            payload.password,
            actor=actor,
            traffic=traffic,
            run_index=run_index,
            virtual_hour=virtual_hour,
        )
        if result["outcome"] in {"unknown_account", "bad_credentials"}:
            raise HTTPException(status_code=401, detail=result)
        if result["outcome"] == "locked":
            raise HTTPException(status_code=423, detail=result)
        return result

    @app.post("/mfa")
    def mfa(
        payload: MFARequest,
        request: Request,
        actor: str = Header(default="legitimate", alias="X-Traffic-Actor"),
        traffic: str = Header(default="normal", alias="X-Traffic-Scenario"),
        run_index: int = Header(default=0, alias="X-Run-Index"),
        virtual_hour: int = Header(default=0, alias="X-Virtual-Hour"),
    ) -> dict[str, object]:
        service: ReplicaService = request.app.state.replica_service
        result = service.mfa(
            payload.account_id,
            payload.code,
            actor=actor,
            traffic=traffic,
            run_index=run_index,
            virtual_hour=virtual_hour,
        )
        if result["outcome"] == "unknown_account":
            raise HTTPException(status_code=401, detail=result)
        if result["outcome"] == "mfa_not_pending":
            raise HTTPException(status_code=400, detail=result)
        if result["outcome"] == "mfa_failed":
            raise HTTPException(status_code=401, detail=result)
        return result

    @app.post("/recover")
    def recover(
        payload: RecoveryRequest,
        request: Request,
        actor: str = Header(default="legitimate", alias="X-Traffic-Actor"),
        traffic: str = Header(default="normal", alias="X-Traffic-Scenario"),
        run_index: int = Header(default=0, alias="X-Run-Index"),
        virtual_hour: int = Header(default=0, alias="X-Virtual-Hour"),
    ) -> dict[str, object]:
        service: ReplicaService = request.app.state.replica_service
        result = service.recover(
            payload.account_id,
            payload.recovery_code,
            actor=actor,
            traffic=traffic,
            run_index=run_index,
            virtual_hour=virtual_hour,
        )
        if result["outcome"] == "unknown_account":
            raise HTTPException(status_code=401, detail=result)
        if result["outcome"] == "recovery_disabled":
            raise HTTPException(status_code=403, detail=result)
        if result["outcome"] == "recovery_failed":
            raise HTTPException(status_code=401, detail=result)
        return result

    return app


app = create_app()
