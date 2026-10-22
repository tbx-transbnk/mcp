"""Fault-injection checks: upstream errors, Redis outages, partial Redis writes, master outages and malformed master responses."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import logging
import socket
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp import Client
from starlette.testclient import TestClient

from src.oauth import _token_key
from src.session import Session
from test_session import make_token, two_scope_master_handler
from test_trusthub_oauth_login import (  # noqa: F401 - oauth_server is a fixture
    CLAUDE_CALLBACK,
    _continue,
    _register_and_authorize,
    oauth_server,
)


def _dead_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _jwt(email: str = "a@b.c", exp_in: float = 3600) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'HS512'})}.{b64({'exp': int(time.time() + exp_in), 'email': email})}.sig"


def _no_leak(text: str) -> None:
    assert "Traceback" not in text
    assert "master.test" not in text and "lms.test" not in text and "127.0.0.1" not in text


# ---------- upstream 404/429 must not leak the LMS URL ----------


def _lms_session(lms_status: int) -> Session:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "lms.test":
            return httpx.Response(lms_status, json={"message": "nope"})
        return two_scope_master_handler(request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Session(
        token=make_token(time.time() + 3600), master_base_url="https://master.test",
        lms_base_url="https://lms.test", client=client,
    )


async def _call_tool(server, name, args):
    async with Client(server.mcp) as c:
        return await c.call_tool(name, args, raise_on_error=False)


@pytest.mark.parametrize("status", [404, 429])
@pytest.mark.parametrize("tool", ["list_accounts", "dashboard_stats"])
def test_upstream_4xx_error_in_scopes_failed_is_masked(monkeypatch, status, tool):
    import src.server as server

    session = _lms_session(status)
    monkeypatch.setattr(server, "get_session", lambda: session)
    result = asyncio.run(_call_tool(server, tool, {"scope": "all"}))
    errors = [f["error"] for f in result.structured_content["scopes_failed"]]
    print(f"\n[02-01] {tool} {status} scopes_failed[0].error = {errors[0]!r}")
    assert len(errors) == 2
    for e in errors:
        assert "lms.test" not in e and "entityId" not in e and "programId" not in e


def test_upstream_404_single_scope_tool_error_is_masked(monkeypatch):
    import src.server as server

    session = _lms_session(404)
    monkeypatch.setattr(server, "get_session", lambda: session)
    result = asyncio.run(_call_tool(server, "list_accounts", {"scope": "transbnk-general"}))
    text = result.content[0].text
    print(f"\n[02-01] single-scope tool error = {text!r}")
    assert result.is_error
    assert "lms.test" not in text


# ---------- Redis unreachable -> fail closed, fast, no trace ----------


@pytest.fixture
def dead_redis_server(monkeypatch):
    monkeypatch.setenv("LMS_MCP_OAUTH_BASE_URL", "https://test-deploy.example")
    monkeypatch.setenv("TRUSTHUB_OAUTH_CLIENT_ID", "test-oauth-client")
    monkeypatch.setenv("TRUSTHUB_OAUTH_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv("TRUSTHUB_LOGIN_URL", "https://trusthub-login.test/login")
    monkeypatch.setenv("MASTER_BASE_URL", "https://master.test")
    monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
    monkeypatch.setenv("REDIS_PORT", str(_dead_port()))
    import src.server as server

    importlib.reload(server)
    try:
        with TestClient(server.mcp.http_app(), base_url="https://testserver", raise_server_exceptions=False) as c:
            yield server, c
    finally:
        for var in ("LMS_MCP_OAUTH_BASE_URL", "TRUSTHUB_OAUTH_CLIENT_ID", "TRUSTHUB_OAUTH_CLIENT_SECRET", "REDIS_HOST", "REDIS_PORT"):
            monkeypatch.delenv(var, raising=False)
        importlib.reload(server)


_MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}


def _redis_down_requests():
    return {
        "register": ("POST", "/register", {"json": {
            "client_name": "Claude", "redirect_uris": [CLAUDE_CALLBACK], "token_endpoint_auth_method": "none"}}),
        "authorize": ("GET", "/authorize", {"params": {
            "response_type": "code", "client_id": "c", "redirect_uri": CLAUDE_CALLBACK,
            "code_challenge": "c" * 43, "code_challenge_method": "S256"}}),
        "token": ("POST", "/token", {"data": {
            "grant_type": "authorization_code", "code": "x", "client_id": "c", "code_verifier": "v" * 43,
            "redirect_uri": CLAUDE_CALLBACK}}),
        "login": ("GET", "/login", {"params": {"request_id": "r"}}),
        "callback": ("GET", "/callback", {"params": {"code": "x", "state": "s"}, "cookies": {"th_state": "s"}}),
        "mcp": ("POST", "/mcp", {"json": _INIT, "headers": {**_MCP_HEADERS, "Authorization": "Bearer abc"}}),
    }


@pytest.mark.parametrize("route", list(_redis_down_requests()))
def test_redis_down_fails_closed_fast(dead_redis_server, route):
    _, c = dead_redis_server
    method, path, kw = _redis_down_requests()[route]
    cookies = kw.pop("cookies", None)
    if cookies:
        c.cookies.update(cookies)
    start = time.monotonic()
    resp = c.request(method, path, follow_redirects=False, **kw)
    elapsed = time.monotonic() - start
    print(f"\n[10-01] {route}: {resp.status_code} in {elapsed:.2f}s body={resp.text[:120]!r}")
    assert elapsed < 15  # redis-py default: 10 retries, jittered backoff capped at 1s - slow but bounded
    assert resp.status_code >= 500
    assert "access_token" not in resp.text and "location" not in resp.headers and "set-cookie" not in resp.headers
    _no_leak(resp.text)


def test_valid_bearer_rejected_once_redis_goes_down(oauth_server, monkeypatch):
    provider = oauth_server._oauth_provider
    token = asyncio.run(_issue_for_sid(provider, "sid-1"))
    headers = {**_MCP_HEADERS, "Authorization": f"Bearer {token.access_token}"}

    with TestClient(oauth_server.mcp.http_app(), base_url="https://testserver", raise_server_exceptions=False) as c:
        assert c.post("/mcp", json=_INIT, headers=headers).status_code == 200
        _kill_redis(monkeypatch, provider)
        start = time.monotonic()
        resp = c.post("/mcp", json=_INIT, headers=headers)
        elapsed = time.monotonic() - start
    print(f"\n[10-01] /mcp valid bearer, redis down: {resp.status_code} in {elapsed:.2f}s body={resp.text[:120]!r}")
    assert resp.status_code >= 500 or resp.status_code == 401
    assert elapsed < 15
    _no_leak(resp.text)


# ---------- Redis fails partway through a multi-step write ----------


def _client_info():
    from mcp.shared.auth import OAuthClientInformationFull

    return OAuthClientInformationFull(
        client_id="test-client", redirect_uris=[CLAUDE_CALLBACK], grant_types=["authorization_code"],
        response_types=["code"], token_endpoint_auth_method="none",
    )


class _Boom(ConnectionError):
    pass


def _fail_on_call(monkeypatch, obj, name, n):
    real = getattr(obj, name)
    calls = {"n": 0}

    async def wrapper(*a, **kw):
        calls["n"] += 1
        if calls["n"] == n:
            raise _Boom("redis went away")
        return await real(*a, **kw)

    monkeypatch.setattr(obj, name, wrapper)


@pytest.mark.parametrize("failing", ["session_members", "access_set", "refresh_set"])
def test_issue_tokens_partial_write_leaves_nothing_revoke_session_misses(monkeypatch, failing):
    from src.oauth import LmsOAuthProvider

    monkeypatch.delenv("REDIS_HOST", raising=False)
    provider = LmsOAuthProvider(base_url="https://test-deploy.example")
    store, method = {
        "session_members": (provider._session_tokens, "add_members"),
        "access_set": (provider._access_tokens, "set"),
        "refresh_set": (provider._refresh_tokens, "set"),
    }[failing]
    _fail_on_call(monkeypatch, store, method, 1)

    async def run():
        with pytest.raises(_Boom):
            await provider._issue_tokens(_client_info(), [], "a@b.c", "sid-1")
        await provider.revoke_session("sid-1")

    asyncio.run(run())
    print(f"\n[10-02] {failing} fails: tokens left after revoke_session = "
          f"{len(provider._access_tokens._local) + len(provider._refresh_tokens._local)}")
    assert provider._access_tokens._local == {} and provider._refresh_tokens._local == {}


def test_revoke_session_partial_failure_leaves_some_tokens_live(monkeypatch):
    from src.oauth import LmsOAuthProvider

    monkeypatch.delenv("REDIS_HOST", raising=False)
    provider = LmsOAuthProvider(base_url="https://test-deploy.example")

    async def run():
        tokens = [await provider._issue_tokens(_client_info(), [], "a@b.c", "sid-1") for _ in range(2)]
        # Only access deletes fail: members iterate in hash order, so failing refresh too made this flaky.
        _fail_on_call(monkeypatch, provider._access_tokens, "delete", 2)
        with pytest.raises(_Boom):
            await provider.revoke_session("sid-1")
        live = [t.access_token for t in tokens if await provider.load_access_token(t.access_token)]
        return tokens, live, await provider._session_tokens.members("sid-1")

    tokens, live, members = asyncio.run(run())
    print(f"\n[10-02] revoke_session half-done: {len(live)}/2 access tokens still valid, session set kept={bool(members)}")
    assert len(live) == 1
    assert members  # set survives, so a retry could still finish the job - nothing retries automatically


async def _issue_for_sid(provider, sid):
    client_info = _client_info()
    await provider.register_client(client_info)
    return await provider._issue_tokens(client_info, [], "a@b.c", sid)


def _signed_in_sid(oauth_server, client, monkeypatch, handler):
    real_client_cls = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda *a, **kw: real_client_cls(transport=httpx.MockTransport(handler)))
    request_id = _register_and_authorize(oauth_server, client)
    state = parse_qs(urlparse(_continue(client, request_id).headers["location"]).query)["state"][0]
    resp = client.get(f"/callback?code=abc&state={state}", follow_redirects=False)
    assert resp.status_code in (302, 307), resp.text
    [sid] = oauth_server._user_sessions
    return sid


def _master(token_body=None, token_raw=None, entities=None, programs=None, refresh=None):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/v1/auth/oauth/token"):
            if token_raw is not None:
                return httpx.Response(200, content=token_raw)
            return httpx.Response(200, json=token_body or {"access_token": _jwt(), "expires_in": 900})
        if path.endswith("/v1/users/entities"):
            return httpx.Response(200, json=[{"entityId": "E1", "entityName": "Acme"}] if entities is None else entities)
        if path.endswith("/v1/users/programs"):
            return httpx.Response(200, json=[{"programId": 1, "programName": "General"}] if programs is None else programs)
        if path.endswith("/v1/auth/refresh") and refresh is not None:
            return refresh()
        if request.url.host == "lms.test":
            return httpx.Response(200, json={"totalAccount": 1, "totalBalance": "1"})
        return httpx.Response(404)

    return handler


@pytest.fixture
def cb_client(oauth_server):
    with TestClient(oauth_server.mcp.http_app(), base_url="https://testserver", raise_server_exceptions=False) as c:
        yield c


def test_signed_out_hook_from_real_sync_tool_call_revokes_not_warns(oauth_server, cb_client, monkeypatch, caplog):
    """Refresh returning 5xx mid-session = sign-out, whole sid revoked."""
    sid = _signed_in_sid(oauth_server, cb_client, monkeypatch, _master(refresh=lambda: httpx.Response(503)))
    provider = oauth_server._oauth_provider
    token = asyncio.run(_issue_for_sid(provider, sid))
    _, session = oauth_server._user_sessions[sid]
    session._set_token(_jwt(exp_in=30))
    _bearer(monkeypatch, oauth_server, sid)

    with caplog.at_level(logging.WARNING, logger="lms_mcp"):
        result = asyncio.run(_call_tool(oauth_server, "dashboard_stats", {}))
    print(f"\n[10-03] refresh 503 mid-session: tool error={result.structured_content['scopes_failed'][0]['error']!r}, "
          f"warnings={[r.message for r in caplog.records]}")
    assert "could not revoke" not in caplog.text
    assert sid not in oauth_server._user_sessions
    assert asyncio.run(provider.load_access_token(token.access_token)) is None
    assert asyncio.run(provider.load_refresh_token(_client_info(), token.refresh_token)) is None


def test_signed_out_hook_on_event_loop_hits_runtimeerror_branch(oauth_server, caplog):
    async def from_loop():
        oauth_server._mark_trusthub_signed_out("sid-x", "a@b.c")

    with caplog.at_level(logging.WARNING, logger="lms_mcp"):
        asyncio.run(from_loop())
    assert "could not revoke" in caplog.text


def _kill_redis(monkeypatch, provider):
    import redis.asyncio as aioredis

    dead = aioredis.Redis(host="127.0.0.1", port=_dead_port(), decode_responses=True)
    for store in vars(provider).values():
        if hasattr(store, "_redis"):
            monkeypatch.setattr(store, "_redis", dead)


def test_revoke_failure_during_sign_out_surfaces_clean_error(oauth_server, cb_client, monkeypatch):
    sid = _signed_in_sid(oauth_server, cb_client, monkeypatch, _master(refresh=lambda: httpx.Response(503)))
    provider = oauth_server._oauth_provider
    token = asyncio.run(_issue_for_sid(provider, sid))
    local = {name: dict(store._local) for name, store in vars(provider).items() if hasattr(store, "_local")}
    _, session = oauth_server._user_sessions[sid]
    session._set_token(_jwt(exp_in=30))
    _bearer(monkeypatch, oauth_server, sid)
    _kill_redis(monkeypatch, provider)

    result = asyncio.run(_call_tool(oauth_server, "list_accounts", {}))
    text = result.content[0].text
    print(f"\n[10-02] revoke failure during sign-out -> tool error {text!r}; session evicted={sid not in oauth_server._user_sessions}; "
          f"access token still stored={_token_key(token.access_token) in local['_access_tokens']}")
    assert result.is_error
    assert "reconnect" in text and "127.0.0.1" not in text


def _bearer(monkeypatch, server, sid):
    from fastmcp.server.auth import AccessToken

    token = AccessToken(token="t", client_id="c", scopes=[], claims={"email": "a@b.c", "sid": sid})
    monkeypatch.setattr(server, "get_access_token", lambda: token)


# ---------- master unreachable during /callback ----------


def _raiser(exc):
    def handler(request):
        raise exc

    return handler


def _callback(oauth_server, c, monkeypatch, handler=None):
    if handler is not None:
        real_client_cls = httpx.Client
        monkeypatch.setattr(httpx, "Client", lambda *a, **kw: real_client_cls(transport=httpx.MockTransport(handler)))
    request_id = _register_and_authorize(oauth_server, c)
    state = parse_qs(urlparse(_continue(c, request_id).headers["location"]).query)["state"][0]
    start = time.monotonic()
    resp = c.get(f"/callback?code=abc&state={state}", follow_redirects=False)
    return resp, time.monotonic() - start


@pytest.mark.parametrize("exc", [
    httpx.ConnectError("[Errno 111] Connection refused"),
    httpx.ConnectError("[Errno -2] Name or service not known"),
    httpx.ConnectTimeout("timed out"),
    httpx.ReadTimeout("timed out"),
], ids=["refused", "dns", "connect-timeout", "read-timeout"])
@pytest.mark.parametrize("step", ["token", "entities"])
def test_callback_master_down_is_clean_400(oauth_server, cb_client, monkeypatch, exc, step):
    ok = _master()

    def handler(request):
        if (step == "token" and request.url.path.endswith("/oauth/token")) or (
            step == "entities" and request.url.path.endswith("/entities")):
            raise exc
        return ok(request)

    resp, elapsed = _callback(oauth_server, cb_client, monkeypatch, handler)
    print(f"\n[10-03] {step} {type(exc).__name__}: {resp.status_code} in {elapsed:.2f}s {resp.text!r}")
    assert resp.status_code == 400
    assert "Sign-in failed" in resp.text
    assert oauth_server._user_sessions == {}
    _no_leak(resp.text)


def test_callback_real_connection_refused_is_fast_clean_400(oauth_server, cb_client, monkeypatch):
    monkeypatch.setenv("MASTER_BASE_URL", f"http://127.0.0.1:{_dead_port()}")
    resp, elapsed = _callback(oauth_server, cb_client, monkeypatch)
    print(f"\n[10-03] real socket refused: {resp.status_code} in {elapsed:.2f}s")
    assert resp.status_code == 400 and elapsed < 5
    _no_leak(resp.text)


# ---------- malformed master responses through /callback ----------

_MALFORMED = {
    "token-non-json": dict(token_raw=b"<html>oops</html>"),
    "token-json-array": dict(token_body=[{"access_token": "x"}]),
    "token-not-a-jwt": dict(token_body={"access_token": "garbage"}),
    "token-int-access-token": dict(token_body={"access_token": 12345}),
    "token-jwt-array-payload": dict(token_body={"access_token": "e30.WzFd.sig"}),
    "entities-missing-entityId": dict(entities=[{"entityName": "Acme"}]),
    "entities-missing-entityName": dict(entities=[{"entityId": "E1"}]),
    "entities-object-not-array": dict(entities={"entityId": "E1", "entityName": "Acme"}),
    "entities-array-of-strings": dict(entities=["Acme"]),
    "programs-missing-programId": dict(programs=[{"programName": "General"}]),
    "programs-missing-programName": dict(programs=[{"programId": 1}]),
    "programs-array-of-strings": dict(programs=["General"]),
}


@pytest.mark.parametrize("case", list(_MALFORMED))
def test_callback_malformed_master_response(oauth_server, cb_client, monkeypatch, case):
    resp, _ = _callback(oauth_server, cb_client, monkeypatch, _master(**_MALFORMED[case]))
    print(f"\n[10-04] {case}: {resp.status_code} {resp.text[:100]!r}")
    assert resp.status_code == 400 and "Sign-in failed" in resp.text
    assert oauth_server._user_sessions == {}
    assert "location" not in resp.headers
    _no_leak(resp.text)


def test_callback_entities_non_json_is_clean_400(oauth_server, cb_client, monkeypatch):
    ok = _master()

    def handler(request):
        if request.url.path.endswith("/entities"):
            return httpx.Response(200, content=b"not json")
        return ok(request)

    resp, _ = _callback(oauth_server, cb_client, monkeypatch, handler)
    assert resp.status_code == 400


@pytest.mark.parametrize("body", [
    b"<html>gateway</html>", b'[{"accessToken": "x"}]', b'{"accessToken": 12345}', b'{"accessToken": "garbage"}',
], ids=["non-json", "json-array", "int-token", "not-a-jwt"])
def test_callback_malformed_refresh_response(oauth_server, cb_client, monkeypatch, body):
    # Token from oauth/token expires inside the 60s skew, so Session() refreshes during /callback.
    handler = _master(token_body={"access_token": _jwt(exp_in=30)}, refresh=lambda: httpx.Response(200, content=body))
    resp, _ = _callback(oauth_server, cb_client, monkeypatch, handler)
    print(f"\n[10-04] refresh {body!r}: {resp.status_code} {resp.text[:100]!r}")
    assert resp.status_code == 400
    assert oauth_server._user_sessions == {}
    _no_leak(resp.text)
