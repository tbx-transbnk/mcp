"""Per-user OAuth for HTTP mode, opt-in via LMS_MCP_OAUTH_BASE_URL - see get_session()
in server.py. State lives in Redis when REDIS_HOST is set, else an in-process dict
(correct only for a single, long-lived replica)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from urllib.parse import urlparse

from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE, RequestBodyLimitMiddleware
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, request_response

from fastmcp.server.auth import AccessToken, OAuthProvider

from .redis_client import async_redis_client

_logger = logging.getLogger("lms_mcp")

_CODE_TTL = 300
_PENDING_TTL = 600
_ACCESS_TOKEN_TTL = 3600
_REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30
_CLIENT_TTL = 60 * 60 * 24 * 90

# Claude's published connector callbacks; override with a comma-separated LMS_MCP_ALLOWED_REDIRECT_URIS.
DEFAULT_ALLOWED_REDIRECT_URIS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_CLIENT_NAME_LENGTH = 128
MAX_REDIRECT_URIS = 5
MAX_REDIRECT_URI_LENGTH = 512
MAX_REGISTRATION_BODY_BYTES = 8 * 1024

BROWSER_COOKIE = "__Host-lmsmcp_req"
_LOGIN_PREFIX = "/login?request_id="


def allowed_redirect_uris() -> frozenset[str]:
    raw = os.environ.get("LMS_MCP_ALLOWED_REDIRECT_URIS", "")
    return frozenset(u.strip() for u in raw.split(",") if u.strip()) or frozenset(DEFAULT_ALLOWED_REDIRECT_URIS)


def is_allowlisted_redirect_uri(uri: str) -> bool:
    return uri in allowed_redirect_uris()


def is_loopback_redirect_uri(uri: str) -> bool:
    """RFC 8252 native-app redirect - the code can only land on the user's own machine."""
    parsed = urlparse(uri)
    return parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS and not parsed.username and not parsed.password


def _client_problem(client: OAuthClientInformationFull) -> RegistrationError | None:
    name = client.client_name
    if name is not None and (len(name) > MAX_CLIENT_NAME_LENGTH or not name.isprintable()):
        return RegistrationError(
            "invalid_client_metadata", f"client_name must be at most {MAX_CLIENT_NAME_LENGTH} printable characters"
        )
    uris = [str(u) for u in client.redirect_uris or []]
    if not uris or len(uris) > MAX_REDIRECT_URIS:
        return RegistrationError("invalid_redirect_uri", f"between 1 and {MAX_REDIRECT_URIS} redirect_uris are required")
    for uri in uris:
        if len(uri) > MAX_REDIRECT_URI_LENGTH or not (is_allowlisted_redirect_uri(uri) or is_loopback_redirect_uri(uri)):
            return RegistrationError("invalid_redirect_uri", f"redirect_uri {uri[:MAX_REDIRECT_URI_LENGTH]!r} is not allowed")
    return None


def _token_key(token: str) -> str:
    """Store key for a bearer credential - a Redis dump/MONITOR must not yield usable tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


class _SessionCode(AuthorizationCode):
    sid: str | None = None


class _SessionRefreshToken(RefreshToken):
    sid: str | None = None


class _Store:
    """Minimal async key-value store with per-key TTL, Redis or in-process dict."""

    def __init__(self, namespace: str) -> None:
        self._namespace = namespace
        self._redis = async_redis_client()
        self._local: dict[str, tuple[str, float | None]] = {}

    def _key(self, key: str) -> str:
        return f"lms-mcp:oauth:{self._namespace}:{key}"

    async def get(self, key: str) -> str | None:
        if self._redis is not None:
            return await self._redis.get(self._key(key))
        entry = self._local.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and expires_at < time.time():
            self._local.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        if self._redis is not None:
            await self._redis.set(self._key(key), value, ex=int(ttl_seconds))
            return
        self._local[key] = (value, time.time() + ttl_seconds)

    async def delete(self, key: str) -> None:
        if self._redis is not None:
            await self._redis.delete(self._key(key))
            return
        self._local.pop(key, None)

    async def add_members(self, key: str, members: set[str], ttl_seconds: float) -> None:
        if self._redis is not None:
            async with self._redis.pipeline(transaction=True) as pipe:
                await pipe.sadd(self._key(key), *members).expire(self._key(key), int(ttl_seconds)).execute()
            return
        self._local[key] = ((await self.members(key)) | members, time.time() + ttl_seconds)

    async def members(self, key: str) -> set[str]:
        if self._redis is not None:
            return set(await self._redis.smembers(self._key(key)))
        return set(await self.get(key) or ())


class LmsOAuthProvider(OAuthProvider):
    def __init__(self, base_url: str) -> None:
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        )
        self._clients = _Store("clients")
        self._pending = _Store("pending")
        self._codes = _Store("codes")
        self._access_tokens = _Store("access")
        self._refresh_tokens = _Store("refresh")
        self._session_tokens = _Store("session-tokens")
        self._browser_bindings = _Store("browser-bindings")

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = []
        for route in super().get_routes(mcp_path):
            if isinstance(route, Route) and route.path == "/authorize":
                endpoint = RequestBodyLimitMiddleware(
                    request_response(self._authorize_and_bind_browser), DEFAULT_MAX_REQUEST_BODY_SIZE
                )
                route = Route(route.path, endpoint=endpoint, methods=route.methods)
            elif isinstance(route, Route) and route.path == "/register":
                endpoint = RequestBodyLimitMiddleware(route.endpoint, MAX_REGISTRATION_BODY_BYTES)
                route = Route(route.path, endpoint=endpoint, methods=route.methods)
            routes.append(route)
        return routes

    async def _authorize_and_bind_browser(self, request: Request) -> Response:
        """Ties request_id to the browser that hit /authorize, so a /login link
        mailed to someone else is useless in their browser."""
        response = await AuthorizationHandler(self).handle(request)
        location = response.headers.get("location", "")
        if location.startswith(_LOGIN_PREFIX):
            binding = secrets.token_urlsafe(32)
            await self._browser_bindings.set(location.removeprefix(_LOGIN_PREFIX), binding, ttl_seconds=_PENDING_TTL)
            response.set_cookie(
                BROWSER_COOKIE, binding, max_age=_PENDING_TTL, path="/", secure=True, httponly=True, samesite="lax"
            )
        return response

    async def browser_matches(self, request_id: str, cookie_value: str | None) -> bool:
        expected = await self._browser_bindings.get(request_id)
        return bool(expected and cookie_value and secrets.compare_digest(expected, cookie_value))

    @staticmethod
    def csrf_token(request_id: str, cookie_value: str) -> str:
        return hmac.new(cookie_value.encode(), f"login-continue:{request_id}".encode(), hashlib.sha256).hexdigest()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = await self._clients.get(client_id)
        if not raw:
            return None
        client = OAuthClientInformationFull.model_validate_json(raw)
        # Re-checked on read so pre-allowlist registrations (and a tightened env allowlist) stop working too.
        problem = _client_problem(client)
        if problem is not None:
            _logger.warning("stored client %s rejected: %s", client_id, problem.error_description)
            return None
        await self._clients.set(client_id, raw, ttl_seconds=_CLIENT_TTL)
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        problem = _client_problem(client_info)
        if problem is not None:
            _logger.warning("client registration rejected: %s", problem.error_description)
            raise problem
        await self._clients.set(client_info.client_id, client_info.model_dump_json(), ttl_seconds=_CLIENT_TTL)

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        request_id = secrets.token_urlsafe(24)
        payload = json.dumps({"client": client.model_dump(mode="json"), "params": params.model_dump(mode="json")})
        await self._pending.set(request_id, payload, ttl_seconds=_PENDING_TTL)
        return f"/login?request_id={request_id}"

    async def peek_pending_client(self, request_id: str) -> dict[str, str] | None:
        """What /login shows before the password field - closes login-CSRF. Non-consuming."""
        raw = await self._pending.get(request_id)
        if raw is None:
            return None
        data = json.loads(raw)
        client = data["client"]
        redirect_uri = data["params"].get("redirect_uri") or ""
        parsed = urlparse(redirect_uri)
        destination = parsed.hostname or "unknown"
        if parsed.port:
            destination = f"{destination}:{parsed.port}"
        return {
            "client_name": client.get("client_name") or client.get("client_id", "unknown app"),
            "redirect_uri": redirect_uri,
            "destination": destination,
            "verified": is_allowlisted_redirect_uri(redirect_uri),
        }

    async def complete_authorization(self, request_id: str, email: str, sid: str) -> str | None:
        """Called by /callback after a successful TrustHub sign-in; `sid` names the
        exact TrustHub session every token from this login is bound to.
        Returns the URL to redirect the browser to, or None if request_id is stale."""
        raw = await self._pending.get(request_id)
        if raw is None:
            return None
        await self._pending.delete(request_id)
        await self._browser_bindings.delete(request_id)
        data = json.loads(raw)
        params = AuthorizationParams.model_validate(data["params"])
        code = secrets.token_urlsafe(32)
        auth_code = _SessionCode(
            code=code,
            scopes=params.scopes or [],  # no-scope request sends None, not [] - SDK requires a list
            expires_at=time.time() + _CODE_TTL,
            client_id=data["client"]["client_id"],
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=email,
            sid=sid,
        )
        await self._codes.set(_token_key(code), auth_code.model_dump_json(exclude={"code"}), ttl_seconds=_CODE_TTL)
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        raw = await self._codes.get(_token_key(authorization_code))
        if raw is None:
            return None
        code = _SessionCode.model_validate({**json.loads(raw), "code": authorization_code})
        if code.client_id != client.client_id:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        await self._codes.delete(_token_key(authorization_code.code))
        return await self._issue_tokens(
            client, authorization_code.scopes, authorization_code.subject, getattr(authorization_code, "sid", None)
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        raw = await self._refresh_tokens.get(_token_key(refresh_token))
        if raw is None:
            return None
        token = _SessionRefreshToken.model_validate({**json.loads(raw), "token": refresh_token})
        if token.client_id != client.client_id:
            return None
        return token

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        await self._refresh_tokens.delete(_token_key(refresh_token.token))
        return await self._issue_tokens(
            client, scopes or refresh_token.scopes, refresh_token.subject, getattr(refresh_token, "sid", None)
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        raw = await self._access_tokens.get(_token_key(token))
        return AccessToken.model_validate({**json.loads(raw), "token": token}) if raw else None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            await self._access_tokens.delete(_token_key(token.token))
        else:
            await self._refresh_tokens.delete(_token_key(token.token))

    async def revoke_session(self, sid: str) -> None:
        """Kills every lms-mcp token ever issued from this login (incl. superseded
        pre-refresh ones) - called when its TrustHub session dies, so Claude's next
        call gets a real 401 and reconnects."""
        members = await self._session_tokens.members(sid)
        for member in members:
            kind, _, key = member.partition(":")
            store = self._access_tokens if kind == "access" else self._refresh_tokens
            await store.delete(key)
        await self._session_tokens.delete(sid)
        _logger.info("revoked session %s: %d tokens", sid, len(members))

    async def _issue_tokens(
        self, client: OAuthClientInformationFull, scopes: list[str], subject: str | None, sid: str | None
    ) -> OAuthToken:
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        now = time.time()
        access = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(now + _ACCESS_TOKEN_TTL),
            subject=subject,
            claims={"email": subject, "sid": sid} if subject else {},
        )
        refresh = _SessionRefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(now + _REFRESH_TOKEN_TTL),
            subject=subject,
            sid=sid,
        )
        access_key, refresh_key = _token_key(access_token), _token_key(refresh_token)
        if sid:
            # Tracked before written: a Redis failure mid-issue can't leave a live token revoke_session can't reach.
            # ponytail: stale members accumulate until revoke/TTL (~2 per refresh), prune if sessions run for months
            members = {f"access:{access_key}", f"refresh:{refresh_key}"}
            await self._session_tokens.add_members(sid, members, ttl_seconds=_REFRESH_TOKEN_TTL)
        await self._access_tokens.set(access_key, access.model_dump_json(exclude={"token"}), ttl_seconds=_ACCESS_TOKEN_TTL)
        await self._refresh_tokens.set(refresh_key, refresh.model_dump_json(exclude={"token"}), ttl_seconds=_REFRESH_TOKEN_TTL)
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=_ACCESS_TOKEN_TTL,
            refresh_token=refresh_token,
            scope=" ".join(scopes) if scopes else None,
        )
