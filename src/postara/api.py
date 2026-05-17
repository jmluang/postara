from __future__ import annotations

import asyncio
import contextlib
import secrets
import string
import inspect
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, text

from postara.accounts import AccountNotFoundError, AccountService, DuplicateEmailError
from postara.config import Settings
from postara.database import (
    create_app_session_factory,
    create_audit_session_factory,
    create_repository_account_service,
    create_repository_user_service,
)
from postara.errors import ErrorResponse
from postara.mailbox import MailboxRuntime
from postara.models import AuditEventORM, AuditOutboxORM
from postara.providers.base import AuthenticationError, MessageNotFoundError, MessageQuery, ProviderError, UnsupportedProviderFeature
from postara.providers.registry import ProviderRegistry
from postara.rate_limit import InMemoryRateLimiter, RateLimitExceeded
from postara.security import TokenFormatError, parse_api_key
from postara.users import (
    ApiKeyNotFoundError,
    DuplicateUserEmailError,
    InvalidUserCredentialsError,
    SessionNotFoundError,
    UserService,
)
from postara.web import brand_icon_path, default_frontend_dist, index_html


BASE62 = string.ascii_letters + string.digits


def _request_id() -> str:
    return "req_" + "".join(secrets.choice(BASE62) for _ in range(16))


def error_response(
    *,
    request_id: str,
    status_code: int,
    code: str,
    message: str,
    details: dict | None = None,
) -> JSONResponse:
    response = JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            code=code,
            message=message,
            request_id=request_id,
            details=details or {},
        ).to_body(),
    )
    response.headers["X-Request-Id"] = request_id
    return response


def rate_limit_response(request_id: str) -> JSONResponse:
    return error_response(
        request_id=request_id,
        status_code=429,
        code="rate_limited",
        message="Rate limit exceeded.",
    )


def _validation_details(errors: list[dict]) -> dict:
    fields = []
    for error in errors:
        loc = [str(part) for part in error.get("loc", []) if part not in {"body", "query", "path", "header"}]
        fields.append(
            {
                "field": ".".join(loc) if loc else "request",
                "message": error.get("msg", "Invalid value."),
                "type": error.get("type", "value_error"),
            }
        )
    return {"fields": fields}


async def require_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
) -> str:
    request_id = request.state.request_id
    if not x_api_key:
        raise AuthError(
            error_response(
                request_id=request_id,
                status_code=401,
                code="auth_missing",
                message="Authentication failed.",
            )
        )
    try:
        parse_api_key(x_api_key)
    except TokenFormatError as exc:
        raise AuthError(
            error_response(
                request_id=request_id,
                status_code=401,
                code="auth_malformed",
                message="Authentication failed.",
            )
        ) from exc
    return x_api_key


class AuthError(Exception):
    def __init__(self, response: JSONResponse) -> None:
        self.response = response


class AccountCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    provider: str = "gmail"
    password: str = Field(min_length=1)


class CredentialUpdateRequest(BaseModel):
    password: str = Field(min_length=1)


class UserRegisterRequest(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=8)
    name: str = Field(min_length=1)


class UserLoginRequest(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=1)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class UserProfileUpdateRequest(BaseModel):
    name: str = Field(min_length=1)


class OwnerPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=8)


class UserStatusUpdateRequest(BaseModel):
    status: Literal["active", "disabled"]


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    mailbox_id: int | None = None
    scopes: list[Literal["read", "mark_seen"]] = Field(default_factory=lambda: ["read"])


class ApiKeyStatusUpdateRequest(BaseModel):
    status: Literal["active", "disabled"]


class SeenRequest(BaseModel):
    seen: bool = True


async def _resolve(value):
    if inspect.isawaitable(value):
        return await value
    return value


class _LazyAccountService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._service = None

    def _get(self):
        if self._service is None:
            self._service = create_repository_account_service(self._settings)
        return self._service

    async def create_for_user(
        self,
        *,
        user_id: int,
        name: str,
        email: str,
        provider: str,
        password: str,
        audit_context: dict | None = None,
    ):
        return await self._get().create_for_user(
            user_id=user_id,
            name=name,
            email=email,
            provider=provider,
            password=password,
            audit_context=audit_context,
        )

    async def list(self):
        return await self._get().list()

    async def list_for_user(self, user_id: int):
        return await self._get().list_for_user(user_id)

    async def get_for_user(self, user_id: int, account_id: int):
        return await self._get().get_for_user(user_id, account_id)

    async def update_credentials_for_user(
        self,
        user_id: int,
        account_id: int,
        password: str,
        audit_context: dict | None = None,
    ):
        return await self._get().update_credentials_for_user(
            user_id,
            account_id,
            password,
            audit_context=audit_context,
        )

    async def delete_for_user(self, user_id: int, account_id: int, audit_context: dict | None = None):
        return await self._get().delete_for_user(user_id, account_id, audit_context=audit_context)

    async def get_password_for_imap(self, account_id: int):
        return await self._get().get_password_for_imap(account_id)

    async def record_message_seen(
        self,
        account_id: int,
        uid: str,
        seen: bool,
        audit_context: dict | None = None,
    ):
        return await self._get().record_message_seen(account_id, uid, seen, audit_context=audit_context)


class _LazyUserService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._service = None

    def _get(self):
        if self._service is None:
            self._service = create_repository_user_service(self._settings)
        return self._service

    async def register(self, **kwargs):
        return await self._get().register(**kwargs)

    async def login(self, **kwargs):
        return await self._get().login(**kwargs)

    async def authenticate_session(self, raw_token: str):
        return await self._get().authenticate_session(raw_token)

    async def revoke_session(self, raw_token: str):
        return await self._get().revoke_session(raw_token)

    async def change_password(self, user_id: int, *, current_password: str, new_password: str):
        return await self._get().change_password(
            user_id,
            current_password=current_password,
            new_password=new_password,
        )

    async def update_profile(self, user_id: int, *, name: str):
        return await self._get().update_profile(user_id, name=name)

    async def list_users(self):
        return await self._get().list_users()

    async def update_user_status(self, user_id: int, status: str):
        return await self._get().update_user_status(user_id, status)

    async def reset_password(self, user_id: int, *, new_password: str):
        return await self._get().reset_password(user_id, new_password=new_password)

    async def list_api_keys(self, user_id: int):
        return await self._get().list_api_keys(user_id)

    async def create_api_key(
        self,
        user_id: int,
        *,
        name: str,
        mailbox_id: int | None = None,
        scopes: list[str] | None = None,
    ):
        return await self._get().create_api_key(user_id, name=name, mailbox_id=mailbox_id, scopes=scopes)

    async def update_api_key_status(self, user_id: int, api_key_id: int, status: str):
        return await self._get().update_api_key_status(user_id, api_key_id, status)

    async def revoke_api_key(self, user_id: int, api_key_id: int):
        return await self._get().revoke_api_key(user_id, api_key_id)

    async def authenticate_api_key(self, raw_key: str):
        return await self._get().authenticate_api_key(raw_key)


def _message_summary_body(message) -> dict:
    return {
        "uid": message.uid,
        "subject": message.subject,
        "from_address": message.from_address,
        "date": message.date.isoformat() if message.date else None,
        "seen": message.seen,
        "has_attachments": message.has_attachments,
    }


def _message_body(message) -> dict:
    return {
        "uid": message.uid,
        "subject": message.subject,
        "from_address": message.from_address,
        "date": message.date.isoformat() if message.date else None,
        "text": message.text,
        "html": message.html,
        "seen": message.seen,
        "attachments": message.attachments,
    }


def _audit_context(request: Request, *, actor_type: str, actor_id: str | None = None) -> dict:
    return {
        "actor_type": actor_type,
        "actor_id": actor_id,
        "client_ip": request.client.host if request.client else "0.0.0.0",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "request_id": request.state.request_id,
    }


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"


def _next_cursor(messages: list, limit: int) -> str | None:
    if len(messages) < limit or not messages:
        return None
    return str(messages[-1].uid)


def _forbidden_scope(request_id: str, scope: str) -> JSONResponse:
    return error_response(
        request_id=request_id,
        status_code=403,
        code="scope_forbidden",
        message="API key scope does not allow this operation.",
        details={"scope": scope},
    )


async def _service_call(service, method_name: str, *args, audit_context: dict | None = None, **kwargs):
    method = getattr(service, method_name)
    if audit_context is not None and "audit_context" in inspect.signature(method).parameters:
        kwargs["audit_context"] = audit_context
    return await _resolve(method(*args, **kwargs))


def create_app(
    accounts: AccountService | None = None,
    users: UserService | None = None,
    mailbox_runtime: MailboxRuntime | None = None,
    frontend_dist: Path | None = None,
) -> FastAPI:
    settings = Settings()
    registry = ProviderRegistry.default()
    account_service = accounts or _LazyAccountService(settings)
    user_service = users or _LazyUserService(settings)
    runtime = mailbox_runtime or MailboxRuntime(registry=registry, settings=settings)
    app_session_factory = create_app_session_factory(settings)
    audit_session_factory = create_audit_session_factory(settings)
    rate_limiter = InMemoryRateLimiter()
    frontend_dist = frontend_dist or default_frontend_dist()
    frontend_assets = frontend_dist / "assets"

    async def require_user_session(
        request: Request,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ):
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthError(
                error_response(
                    request_id=request.state.request_id,
                    status_code=401,
                    code="auth_missing",
                    message="Authentication failed.",
                )
            )
        raw_token = authorization.removeprefix("Bearer ").strip()
        try:
            return await _resolve(user_service.authenticate_session(raw_token))
        except (SessionNotFoundError, TokenFormatError) as exc:
            raise AuthError(
                error_response(
                    request_id=request.state.request_id,
                    status_code=401,
                    code="auth_invalid",
                    message="Authentication failed.",
                )
            ) from exc

    async def require_user_api_key(
        request: Request,
        x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
    ):
        raw_key = await require_api_key(request, x_api_key)
        try:
            parts = parse_api_key(raw_key)
            rate_limiter.check_api_key(parts.prefix)
            return await _resolve(user_service.authenticate_api_key(raw_key))
        except RateLimitExceeded as exc:
            raise AuthError(rate_limit_response(request.state.request_id)) from exc
        except (ApiKeyNotFoundError, TokenFormatError) as exc:
            raise AuthError(
                error_response(
                    request_id=request.state.request_id,
                    status_code=401,
                    code="auth_invalid",
                    message="Authentication failed.",
                )
            ) from exc

    async def require_mailbox_access(
        request: Request,
        mailbox_id: int,
        *,
        authorization: str | None,
        x_api_key: str | None,
        required_scope: Literal["read", "mark_seen"],
    ):
        if authorization and authorization.startswith("Bearer "):
            user = await require_user_session(request, authorization)
            return await _resolve(account_service.get_for_user(user.id, mailbox_id))
        api_key = await require_user_api_key(request, x_api_key)
        if api_key.mailbox_id is not None and api_key.mailbox_id != mailbox_id:
            raise AccountNotFoundError(mailbox_id)
        if required_scope not in set(api_key.scopes or []):
            raise AuthError(_forbidden_scope(request.state.request_id, required_scope))
        return await _resolve(account_service.get_for_user(api_key.user_id, mailbox_id))

    async def audit_outbox_loop() -> None:
        from postara.repositories import dispatch_audit_outbox

        while True:
            with contextlib.suppress(Exception):
                await dispatch_audit_outbox(app_session_factory, audit_session_factory)
            await asyncio.sleep(60)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(audit_outbox_loop())
        app.state.audit_outbox_task = task
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(
        title="Postara",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    if frontend_assets.exists():
        app.mount("/assets", StaticFiles(directory=frontend_assets), name="frontend-assets")

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = request.headers.get("X-Request-Id") or _request_id()
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        return response

    @app.exception_handler(AuthError)
    async def auth_error_handler(_request: Request, exc: AuthError):
        return exc.response

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return error_response(
            request_id=request.state.request_id,
            status_code=422,
            code="validation_error",
            message="Request validation failed.",
            details=_validation_details(exc.errors()),
        )

    @app.get("/app", include_in_schema=False)
    async def console():
        return HTMLResponse(index_html(frontend_dist))

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/app")

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon():
        return FileResponse(brand_icon_path("favicon.svg"), media_type="image/svg+xml")

    @app.get("/icon-app.svg", include_in_schema=False)
    async def app_icon():
        return FileResponse(brand_icon_path("icon-app.svg"), media_type="image/svg+xml")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/auth/register", status_code=201)
    async def register_user(payload: UserRegisterRequest, request: Request):
        client_ip = _client_ip(request)
        try:
            rate_limiter.check_auth_failures(client_ip)
            user, session_token = await _resolve(
                user_service.register(
                    email=str(payload.email),
                    password=payload.password,
                    name=payload.name,
                )
            )
        except DuplicateUserEmailError:
            try:
                rate_limiter.record_auth_failure(client_ip)
            except RateLimitExceeded:
                return rate_limit_response(request.state.request_id)
            return error_response(
                request_id=request.state.request_id,
                status_code=409,
                code="user_email_already_exists",
                message="User email already exists.",
                details={"field": "email"},
            )
        except RateLimitExceeded:
            return rate_limit_response(request.state.request_id)
        return {"user": user.to_dto(), "session_token": session_token}

    @app.post("/auth/login")
    async def login_user(payload: UserLoginRequest, request: Request):
        client_ip = _client_ip(request)
        try:
            rate_limiter.check_auth_failures(client_ip)
            user, session_token = await _resolve(
                user_service.login(email=str(payload.email), password=payload.password)
            )
        except InvalidUserCredentialsError:
            try:
                rate_limiter.record_auth_failure(client_ip)
            except RateLimitExceeded:
                return rate_limit_response(request.state.request_id)
            return error_response(
                request_id=request.state.request_id,
                status_code=401,
                code="auth_invalid",
                message="Authentication failed.",
            )
        except RateLimitExceeded:
            return rate_limit_response(request.state.request_id)
        return {"user": user.to_dto(), "session_token": session_token}

    @app.post("/auth/logout", status_code=204)
    async def logout_user(
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        _user=Depends(require_user_session),
    ):
        if authorization:
            await _resolve(user_service.revoke_session(authorization.removeprefix("Bearer ").strip()))
        return Response(status_code=204)

    @app.get("/me")
    async def me(user=Depends(require_user_session)):
        return {"user": user.to_dto()}

    @app.patch("/me")
    async def update_me(payload: UserProfileUpdateRequest, user=Depends(require_user_session)):
        updated = await _resolve(user_service.update_profile(user.id, name=payload.name))
        return {"user": updated.to_dto()}

    @app.put("/me/password", status_code=204)
    async def change_own_password(payload: PasswordChangeRequest, request: Request, user=Depends(require_user_session)):
        try:
            await _resolve(
                user_service.change_password(
                    user.id,
                    current_password=payload.current_password,
                    new_password=payload.new_password,
                )
            )
        except InvalidUserCredentialsError:
            return error_response(
                request_id=request.state.request_id,
                status_code=401,
                code="auth_invalid",
                message="Authentication failed.",
            )
        return Response(status_code=204)

    def owner_not_found(request: Request) -> JSONResponse:
        return error_response(
            request_id=request.state.request_id,
            status_code=404,
            code="not_found",
            message="Not found.",
        )

    @app.get("/owner/health/detailed")
    async def detailed_health(request: Request, user=Depends(require_user_session)):
        if user.role != "owner":
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="not_found",
                message="Not found.",
            )
        status = "ok"
        checks = {"database": "ok", "audit_outbox": "ok"}
        try:
            async with app_session_factory() as session:
                await session.execute(text("SELECT 1"))
                pending = (
                    await session.scalar(
                        select(AuditOutboxORM.id)
                        .where(AuditOutboxORM.delivered_at.is_(None))
                        .order_by(AuditOutboxORM.id)
                        .limit(1)
                    )
                ) is not None
                if pending:
                    status = "degraded"
                    checks["audit_outbox"] = "pending"
        except Exception:
            status = "degraded"
            checks["database"] = "failed"
        return {"status": status, "checks": checks}

    @app.get("/owner/users")
    async def owner_list_users(request: Request, user=Depends(require_user_session)):
        if user.role != "owner":
            return owner_not_found(request)
        users = await _resolve(user_service.list_users())
        return {"users": [item.to_dto() for item in users]}

    @app.patch("/owner/users/{user_id}/status")
    async def owner_update_user_status(
        user_id: int,
        payload: UserStatusUpdateRequest,
        request: Request,
        user=Depends(require_user_session),
    ):
        if user.role != "owner":
            return owner_not_found(request)
        try:
            target = await _resolve(user_service.update_user_status(user_id, payload.status))
        except SessionNotFoundError:
            return owner_not_found(request)
        return {"user": target.to_dto()}

    @app.put("/owner/users/{user_id}/password", status_code=204)
    async def owner_reset_user_password(
        user_id: int,
        payload: OwnerPasswordResetRequest,
        request: Request,
        user=Depends(require_user_session),
    ):
        if user.role != "owner":
            return owner_not_found(request)
        try:
            await _resolve(user_service.reset_password(user_id, new_password=payload.new_password))
        except SessionNotFoundError:
            return owner_not_found(request)
        return Response(status_code=204)

    @app.get("/owner/mailboxes")
    async def owner_list_mailboxes(request: Request, user=Depends(require_user_session)):
        if user.role != "owner":
            return owner_not_found(request)
        accounts = await _resolve(account_service.list())
        return {"mailboxes": [account.to_dto() for account in accounts]}

    @app.get("/owner/audit/events")
    async def owner_list_audit_events(request: Request, user=Depends(require_user_session), limit: int = 50):
        if user.role != "owner":
            return owner_not_found(request)
        limit = max(1, min(limit, 200))
        events = []
        try:
            async with audit_session_factory() as session:
                result = await session.scalars(select(AuditEventORM).order_by(AuditEventORM.id.desc()).limit(limit))
                for event in result:
                    events.append(
                        {
                            "id": event.id,
                            "timestamp": event.timestamp,
                            "actor_type": event.actor_type,
                            "actor_id": event.actor_id,
                            "action": event.action,
                            "target_account_id": event.target_account_id,
                            "status": event.status,
                            "extra": event.extra,
                            "request_id": event.request_id,
                        }
                    )
        except Exception:
            events = []
        return {"events": events}

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json(_user=Depends(require_user_session)):
        return get_openapi(title=app.title, version=app.version, routes=app.routes)

    @app.get("/docs", include_in_schema=False)
    async def docs(_user=Depends(require_user_session)):
        return get_swagger_ui_html(openapi_url="/openapi.json", title="Postara API")

    @app.get("/mailboxes")
    async def list_mailboxes(user=Depends(require_user_session)):
        accounts = await _resolve(account_service.list_for_user(user.id))
        return {"mailboxes": [account.to_dto() for account in accounts]}

    @app.post("/mailboxes", status_code=201)
    async def create_mailbox(payload: AccountCreateRequest, request: Request, user=Depends(require_user_session)):
        try:
            defaults = registry.defaults_for(payload.provider)
            await _resolve(
                runtime.validate_credentials(
                    email=str(payload.email),
                    password=payload.password,
                    imap_host=defaults.imap_host,
                    imap_port=defaults.imap_port,
                )
            )
            account = await _service_call(
                account_service,
                "create_for_user",
                user_id=user.id,
                name=payload.name,
                email=str(payload.email),
                provider=payload.provider,
                password=payload.password,
                audit_context=_audit_context(request, actor_type="user", actor_id=str(user.id)),
            )
        except DuplicateEmailError:
            return error_response(
                request_id=request.state.request_id,
                status_code=409,
                code="email_already_exists",
                message="Email already exists.",
                details={"field": "email"},
            )
        except ValueError:
            return error_response(
                request_id=request.state.request_id,
                status_code=400,
                code="invalid_provider",
                message="Invalid provider.",
                details={"provider": payload.provider},
            )
        except (AuthenticationError, ProviderError):
            return error_response(
                request_id=request.state.request_id,
                status_code=422,
                code="credentials_invalid",
                message="Mailbox credentials could not be verified.",
            )
        return {"mailbox": account.to_dto()}

    @app.get("/mailboxes/{mailbox_id}")
    async def get_mailbox(mailbox_id: int, request: Request, user=Depends(require_user_session)):
        try:
            account = await _resolve(account_service.get_for_user(user.id, mailbox_id))
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        return {"mailbox": account.to_dto()}

    @app.put("/mailboxes/{mailbox_id}/credentials")
    async def update_mailbox_credentials(
        mailbox_id: int,
        payload: CredentialUpdateRequest,
        request: Request,
        user=Depends(require_user_session),
    ):
        try:
            account = await _resolve(account_service.get_for_user(user.id, mailbox_id))
            await _resolve(
                runtime.validate_credentials(
                    email=account.email,
                    password=payload.password,
                    imap_host=account.imap_host,
                    imap_port=account.imap_port,
                )
            )
            account = await _service_call(
                account_service,
                "update_credentials_for_user",
                user.id,
                mailbox_id,
                payload.password,
                audit_context=_audit_context(request, actor_type="user", actor_id=str(user.id)),
            )
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        except (AuthenticationError, ProviderError):
            return error_response(
                request_id=request.state.request_id,
                status_code=422,
                code="credentials_invalid",
                message="Mailbox credentials could not be verified.",
            )
        return {"mailbox": account.to_dto()}

    @app.delete("/mailboxes/{mailbox_id}", status_code=204)
    async def delete_mailbox(mailbox_id: int, request: Request, user=Depends(require_user_session)):
        try:
            await _service_call(
                account_service,
                "delete_for_user",
                user.id,
                mailbox_id,
                audit_context=_audit_context(request, actor_type="user", actor_id=str(user.id)),
            )
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        return Response(status_code=204)

    @app.get("/api-keys")
    async def list_api_keys(user=Depends(require_user_session)):
        keys = await _resolve(user_service.list_api_keys(user.id))
        return {"api_keys": [key.to_dto() for key in keys]}

    @app.post("/api-keys", status_code=201)
    async def create_api_key(payload: ApiKeyCreateRequest, request: Request, user=Depends(require_user_session)):
        try:
            if payload.mailbox_id is not None:
                await _resolve(account_service.get_for_user(user.id, payload.mailbox_id))
            key, raw_key = await _resolve(
                user_service.create_api_key(
                    user.id,
                    name=payload.name,
                    mailbox_id=payload.mailbox_id,
                    scopes=list(payload.scopes),
                )
            )
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        return {"api_key_record": key.to_dto(), "api_key": raw_key}

    @app.patch("/api-keys/{api_key_id}/status")
    async def update_api_key_status(
        api_key_id: int,
        payload: ApiKeyStatusUpdateRequest,
        request: Request,
        user=Depends(require_user_session),
    ):
        try:
            key = await _resolve(user_service.update_api_key_status(user.id, api_key_id, payload.status))
        except ApiKeyNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="api_key_not_found",
                message="API key not found.",
            )
        return {"api_key": key.to_dto()}

    @app.delete("/api-keys/{api_key_id}", status_code=204)
    async def revoke_api_key(api_key_id: int, request: Request, user=Depends(require_user_session)):
        try:
            await _resolve(user_service.revoke_api_key(user.id, api_key_id))
        except ApiKeyNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="api_key_not_found",
                message="API key not found.",
            )
        return Response(status_code=204)

    @app.get("/mailboxes/{mailbox_id}/folders")
    async def list_mailbox_folders(
        mailbox_id: int,
        request: Request,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
    ):
        try:
            account = await require_mailbox_access(
                request,
                mailbox_id,
                authorization=authorization,
                x_api_key=x_api_key,
                required_scope="read",
            )
            password = await _resolve(account_service.get_password_for_imap(account.id))
            folders = await _resolve(runtime.list_folders(account, password))
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        except ProviderError:
            return error_response(
                request_id=request.state.request_id,
                status_code=502,
                code="provider_error",
                message="Mailbox provider request failed.",
            )
        return {"mailbox_id": mailbox_id, "folders": [folder.__dict__ for folder in folders]}

    @app.get("/mailboxes/{mailbox_id}/messages")
    async def list_mailbox_messages(
        request: Request,
        mailbox_id: int,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
        folder: str = "INBOX",
        limit: int = 20,
        cursor: str | None = None,
        unread_only: bool = False,
        since: datetime | None = None,
        before: datetime | None = None,
        from_address: str | None = None,
        subject_contains: str | None = None,
        text_contains: str | None = None,
        has_attachment: bool | None = None,
    ):
        query = MessageQuery(
            limit=limit,
            cursor=cursor,
            unread_only=unread_only,
            since=since,
            before=before,
            from_address=from_address,
            subject_contains=subject_contains,
            text_contains=text_contains,
            has_attachment=has_attachment,
        )
        try:
            account = await require_mailbox_access(
                request,
                mailbox_id,
                authorization=authorization,
                x_api_key=x_api_key,
                required_scope="read",
            )
            password = await _resolve(account_service.get_password_for_imap(account.id))
            registry.get(account.provider).validate_query(query)
            messages = await _resolve(runtime.list_messages(account, password, folder, query))
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        except UnsupportedProviderFeature as exc:
            return error_response(
                request_id=request.state.request_id,
                status_code=400,
                code="unsupported_provider_feature",
                message="The provider does not support one or more requested filters.",
                details={"fields": exc.fields},
            )
        except MessageNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="message_not_found",
                message="Message not found.",
            )
        except ProviderError:
            return error_response(
                request_id=request.state.request_id,
                status_code=502,
                code="provider_error",
                message="Mailbox provider request failed.",
            )
        return {
            "mailbox_id": mailbox_id,
            "folder": folder,
            "messages": [_message_summary_body(message) for message in messages],
            "next_cursor": _next_cursor(messages, limit),
        }

    @app.get("/mailboxes/{mailbox_id}/messages/{uid}")
    async def fetch_mailbox_message(
        request: Request,
        mailbox_id: int,
        uid: str,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
        folder: str = "INBOX",
    ):
        try:
            account = await require_mailbox_access(
                request,
                mailbox_id,
                authorization=authorization,
                x_api_key=x_api_key,
                required_scope="read",
            )
            password = await _resolve(account_service.get_password_for_imap(account.id))
            message = await _resolve(runtime.fetch_message(account, password, folder, uid))
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        except MessageNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="message_not_found",
                message="Message not found.",
            )
        except ProviderError:
            return error_response(
                request_id=request.state.request_id,
                status_code=502,
                code="provider_error",
                message="Mailbox provider request failed.",
            )
        if message is None:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="message_not_found",
                message="Message not found.",
            )
        return {"mailbox_id": mailbox_id, "message": _message_body(message)}

    @app.post("/mailboxes/{mailbox_id}/messages/{uid}/seen")
    async def mark_mailbox_message_seen(
        request: Request,
        mailbox_id: int,
        uid: str,
        payload: SeenRequest,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
        x_api_key: Annotated[str | None, Header(alias="X-Api-Key")] = None,
        folder: str = "INBOX",
    ):
        try:
            account = await require_mailbox_access(
                request,
                mailbox_id,
                authorization=authorization,
                x_api_key=x_api_key,
                required_scope="mark_seen",
            )
            password = await _resolve(account_service.get_password_for_imap(account.id))
            await _resolve(runtime.mark_seen(account, password, folder, uid, payload.seen))
            await _service_call(
                account_service,
                "record_message_seen",
                account.id,
                uid,
                payload.seen,
                audit_context=_audit_context(request, actor_type="user", actor_id=str(account.user_id)),
            )
        except AccountNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="account_not_found",
                message="Account not found.",
            )
        except MessageNotFoundError:
            return error_response(
                request_id=request.state.request_id,
                status_code=404,
                code="message_not_found",
                message="Message not found.",
            )
        except ProviderError:
            return error_response(
                request_id=request.state.request_id,
                status_code=502,
                code="provider_error",
                message="Mailbox provider request failed.",
            )
        return {"mailbox_id": mailbox_id, "uid": uid, "seen": payload.seen}

    return app


app = create_app()
