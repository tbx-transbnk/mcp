"""lms-mcp as an OAuth 2.1 + PKCE client of TrustHub's master API - the only browser sign-in path. Flow under test: GET /authorize -> GET /login -> POST /login/continue -> GET /callback."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import logging
import re
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.testclient import TestClient

from src import trusthub_oauth


def _jwt(email: str = "a@b.c") -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS512"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": int(time.time()) + 3600, "email": email}).encode()
    ).decode().rstrip("=")
    return f"{header}.{payload}.aJ62MhlENiY8latX064xOBQqfBgd_qRbEdLANyGSd56"


def test_generate_pkce_challenge_matches_verifier():
    import base64 as b64
    import hashlib

    verifier, challenge = trusthub_oauth._generate_pkce()
    assert 43 <= len(verifier) <= 128
    expected = b64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected


@pytest.fixture
def oauth_server(monkeypatch, tmp_path):
    monkeypatch.setenv("LMS_MCP_OAUTH_BASE_URL", "https://test-deploy.example")
    monkeypatch.setenv("TRUSTHUB_OAUTH_CLIENT_ID", "test-oauth-client")
    monkeypatch.setenv("TRUSTHUB_OAUTH_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv("TRUSTHUB_LOGIN_URL", "https://trusthub-login.test/login")
    monkeypatch.setenv("MASTER_BASE_URL", "https://master.test")
    monkeypatch.setenv("LMS_BASE_URL", "https://lms.test")
    monkeypatch.delenv("REDIS_HOST", raising=False)

    import src.server as server

    importlib.reload(server)
    try:
        yield server
    finally:
        monkeypatch.delenv("LMS_MCP_OAUTH_BASE_URL", raising=False)
        monkeypatch.delenv("TRUSTHUB_OAUTH_CLIENT_SECRET", raising=False)
        importlib.reload(server)


@pytest.fixture
def client(oauth_server):
    # https:// base_url - the state cookie is Secure, so a plain http:// test client
    # would (correctly) never resend it, same as a real browser wouldn't either.
    with TestClient(oauth_server.mcp.http_app(), base_url="https://testserver") as c:
        yield c


@pytest.fixture
def unconfigured_client(monkeypatch, tmp_path):
    # OAuth mode on (Claude connector flow exists) but TRUSTHUB_OAUTH_CLIENT_SECRET
    # not set - a real misconfiguration, not "no OAuth at all" (see test_static_routes.py
    # for that case, where _oauth_provider itself is None).
    monkeypatch.setenv("LMS_MCP_OAUTH_BASE_URL", "https://test-deploy.example")
    monkeypatch.delenv("TRUSTHUB_OAUTH_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("REDIS_HOST", raising=False)

    import src.server as server

    importlib.reload(server)
    try:
        with TestClient(server.mcp.http_app()) as c:
            yield c, server
    finally:
        monkeypatch.delenv("LMS_MCP_OAUTH_BASE_URL", raising=False)
        importlib.reload(server)


CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def _register_and_authorize(oauth_server, client, redirect_uri=CLAUDE_CALLBACK, client_name=None):
    """Goes through the real /authorize so the TestClient's jar picks up the browser-binding cookie."""
    from mcp.shared.auth import OAuthClientInformationFull

    client_info = OAuthClientInformationFull(
        client_id="test-client", client_name=client_name, redirect_uris=[redirect_uri],
        grant_types=["authorization_code"], response_types=["code"],
        token_endpoint_auth_method="none",
    )
    asyncio.run(oauth_server._oauth_provider.register_client(client_info))
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code", "client_id": "test-client", "redirect_uri": redirect_uri,
            "code_challenge": "c" * 43, "code_challenge_method": "S256", "state": "claude-state",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.text
    return resp.headers["location"].split("request_id=")[1]


def _csrf_from_consent(client, request_id):
    page = client.get(f"/login?request_id={request_id}")
    assert page.status_code == 200, page.text
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def _continue(client, request_id, csrf=None, accept_disclaimer="on"):
    if csrf is None:
        csrf = _csrf_from_consent(client, request_id)
    data = {"request_id": request_id, "csrf_token": csrf}
    if accept_disclaimer is not None:
        data["accept_disclaimer"] = accept_disclaimer
    return client.post("/login/continue", data=data, follow_redirects=False)


def test_oauth_routes_exist_when_configured(client):
    # Generic OAuth-provider (Claude <-> lms-mcp) endpoint mounting - unrelated to
    # whether TrustHub sign-in itself is configured. Moved from the now-deleted
    # test_oauth_login_flow.py (which tested the removed password+OTP browser page).
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    assert "authorization_endpoint" in resp.json()


def test_login_page_shows_consent_notice_without_redirecting(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    resp = client.get(f"/login?request_id={request_id}", follow_redirects=False)
    assert resp.status_code == 200
    assert "test-client" in resp.text
    assert 'method="post" action="/login/continue"' in resp.text
    assert "claude.ai" in resp.text
    assert "Unverified" not in resp.text


def test_authorize_sets_browser_binding_cookie(oauth_server, client):
    _register_and_authorize(oauth_server, client)
    cookie = client.cookies.get("__Host-lmsmcp_req")
    assert cookie and len(cookie) > 30


def test_authorize_response_cookie_flags(oauth_server, client):
    from mcp.shared.auth import OAuthClientInformationFull

    asyncio.run(oauth_server._oauth_provider.register_client(OAuthClientInformationFull(
        client_id="c", redirect_uris=[CLAUDE_CALLBACK], token_endpoint_auth_method="none",
    )))
    resp = client.get("/authorize", params={
        "response_type": "code", "client_id": "c", "redirect_uri": CLAUDE_CALLBACK,
        "code_challenge": "c" * 43, "code_challenge_method": "S256",
    }, follow_redirects=False)
    set_cookie = resp.headers["set-cookie"]
    assert set_cookie.startswith("__Host-lmsmcp_req=")
    for flag in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert flag in set_cookie


def test_login_page_refuses_a_link_opened_in_another_browser(oauth_server, client, caplog):
    # The phishing case: attacker's /login link opened by a victim who never hit /authorize.
    request_id = _register_and_authorize(oauth_server, client)
    client.cookies.clear()
    resp = client.get(f"/login?request_id={request_id}")
    assert resp.status_code == 403
    assert "wasn't started in this browser" in resp.text
    assert "/login rejected" in caplog.text


def test_login_continue_fails_without_browser_binding_cookie(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    csrf = _csrf_from_consent(client, request_id)
    client.cookies.clear()
    resp = _continue(client, request_id, csrf)
    assert resp.status_code == 403
    assert "location" not in resp.headers


def test_login_continue_fails_with_another_browsers_cookie(oauth_server, client):
    attacker_request = _register_and_authorize(oauth_server, client)
    client.cookies.clear()
    _register_and_authorize(oauth_server, client)
    victim_cookie = client.cookies.get("__Host-lmsmcp_req")
    csrf = oauth_server._oauth_provider.csrf_token(attacker_request, victim_cookie)
    assert client.get(f"/login?request_id={attacker_request}").status_code == 403
    assert _continue(client, attacker_request, csrf).status_code == 403


def test_login_continue_rejects_bad_csrf_token(oauth_server, client, caplog):
    request_id = _register_and_authorize(oauth_server, client)
    resp = _continue(client, request_id, csrf="0" * 64)
    assert resp.status_code == 403
    assert "location" not in resp.headers
    assert "/login/continue rejected" in caplog.text


def test_login_continue_rejects_get(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    resp = client.get(f"/login/continue?request_id={request_id}", follow_redirects=False)
    assert resp.status_code == 405
    assert "location" not in resp.headers


def test_disclaimer_html_and_plain_text_share_the_same_source(oauth_server):
    html = oauth_server._disclaimer_html("Acme App")
    plain = oauth_server._disclaimer_plain_text("Acme App")
    for point in oauth_server._DISCLAIMER_POINTS:
        expected = point.format(client_name="Acme App")
        assert expected in html
        assert expected in plain


def test_consent_page_shows_data_sharing_disclaimer_and_gates_checkbox(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    page = client.get(f"/login?request_id={request_id}")
    assert "shall be governed by the privacy policy of the application" in page.text
    assert "AI-generated responses may contain errors or omissions" in page.text
    assert "expressly consent to the foregoing" in page.text
    assert 'name="accept_disclaimer"' in page.text
    assert 'id="connect_btn" disabled' in page.text


def test_login_continue_rejects_without_accepting_disclaimer(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    resp = _continue(client, request_id, accept_disclaimer=None)
    assert resp.status_code == 400
    assert "location" not in resp.headers


def test_consent_marks_loopback_client_unverified_and_shows_destination(oauth_server, client):
    request_id = _register_and_authorize(
        oauth_server, client, redirect_uri="http://127.0.0.1:33418/callback", client_name="Claude"
    )
    resp = client.get(f"/login?request_id={request_id}")
    assert resp.status_code == 200
    assert "Unverified" in resp.text
    assert "127.0.0.1:33418" in resp.text


def test_register_endpoint_rejects_non_allowlisted_redirect_uri(client, caplog):
    resp = client.post("/register", json={
        "client_name": "Claude", "redirect_uris": ["https://evil.example/callback"],
        "token_endpoint_auth_method": "none",
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_redirect_uri"
    assert "client registration rejected" in caplog.text


def test_register_endpoint_accepts_claude_callback(client):
    resp = client.post("/register", json={
        "client_name": "Claude", "redirect_uris": [CLAUDE_CALLBACK], "token_endpoint_auth_method": "none",
    })
    assert resp.status_code == 201


def test_register_endpoint_caps_body_size(client):
    resp = client.post("/register", json={
        "client_name": "x", "redirect_uris": [CLAUDE_CALLBACK], "client_uri": "https://a.example/" + "a" * 9000,
    })
    assert resp.status_code == 413


def test_login_page_rejects_unknown_request_id(oauth_server, client):
    resp = client.get("/login?request_id=not-a-real-one")
    assert resp.status_code == 400


def test_login_continue_redirects_to_trusthub_and_sets_state_cookie(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    resp = _continue(client, request_id)
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("https://trusthub-login.test/login?")
    params = parse_qs(urlparse(location).query)
    assert params["client_id"] == ["test-oauth-client"]
    assert params["redirect_uri"] == ["https://test-deploy.example/callback"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["consent"] == ["true"]
    assert "test-client" in params["consent_content"][0]
    assert "shall be governed by the privacy policy" in params["consent_content"][0]
    assert len(params["state"][0]) > 10
    assert len(params["code_challenge"][0]) == 43
    set_cookie = resp.headers["set-cookie"]
    assert "th_state=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert params["state"][0] in set_cookie


def test_login_page_errors_clearly_when_trusthub_not_configured(unconfigured_client):
    client, server = unconfigured_client
    request_id = _register_and_authorize(server, client)
    resp = client.get(f"/login?request_id={request_id}")
    assert resp.status_code == 500
    assert "TRUSTHUB_OAUTH_CLIENT_SECRET" in resp.text


def _mock_exchange(monkeypatch, server, email="a@b.c", token_status=200, record_into=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v1/auth/oauth/token"):
            if record_into is not None:
                record_into.append(request)
            if token_status != 200:
                return httpx.Response(token_status, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={"access_token": _jwt(email), "token_type": "Bearer", "expires_in": 900},
                headers={"Set-Cookie": "refresh_token=abc123; Path=/master/v1/auth/refresh; HttpOnly"},
            )
        if request.url.path.endswith("/v1/users/entities"):
            return httpx.Response(200, json=[{"entityId": "E1", "entityName": "Acme"}])
        if request.url.path.endswith("/v1/users/programs"):
            return httpx.Response(200, json=[{"programId": 1, "programName": "General"}])
        return httpx.Response(404)

    real_client_cls = httpx.Client
    monkeypatch.setattr(
        server.httpx, "Client", lambda *a, **kw: real_client_cls(transport=httpx.MockTransport(handler))
    )


def _start_pending(client, oauth_server, request_id):
    """Drives /login/continue through the real TestClient so its cookie jar
    actually picks up the th_state cookie, the same way a real browser would."""
    resp = _continue(client, request_id)
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    return state


def test_callback_exchanges_code_and_completes_authorization(oauth_server, client, monkeypatch):
    requests_seen: list[httpx.Request] = []
    _mock_exchange(monkeypatch, oauth_server, record_into=requests_seen)
    request_id = _register_and_authorize(oauth_server, client)
    state = _start_pending(client, oauth_server, request_id)

    resp = client.get(f"/callback?code=abc&state={state}", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"].startswith(f"{CLAUDE_CALLBACK}?code=")
    assert resp.headers["cache-control"] == "no-store"
    [(_, session)] = oauth_server._user_sessions.values()
    assert session._client.cookies.get("refresh_token") == "abc123"
    assert "a@b.c" not in oauth_server._user_sessions

    # Protocol-level assertions (finding #14): Basic auth, form-encoded body, exact fields.
    assert len(requests_seen) == 1
    token_request = requests_seen[0]
    expected_auth = "Basic " + base64.b64encode(b"test-oauth-client:s3cret").decode()
    assert token_request.headers["authorization"] == expected_auth
    assert token_request.headers["content-type"] == "application/x-www-form-urlencoded"
    body = parse_qs(token_request.content.decode())
    assert body["grant_type"] == ["authorization_code"]
    assert body["code"] == ["abc"]
    assert body["redirect_uri"] == ["https://test-deploy.example/callback"]
    assert len(body["code_verifier"][0]) >= 43


def test_callback_rejects_without_state_cookie(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    # Started the attempt (so the state exists server-side) but the request carries
    # no th_state cookie at all - simulates a code+state pair reaching a different
    # browser than the one /login/continue sent them to.
    resp = _continue(client, request_id)
    state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
    client.cookies.clear()

    resp = client.get(f"/callback?code=abc&state={state}")
    assert resp.status_code == 400
    assert "expired" in resp.text


def test_callback_rejects_mismatched_state_cookie(oauth_server, client, caplog):
    request_id = _register_and_authorize(oauth_server, client)
    _start_pending(client, oauth_server, request_id)
    client.cookies.set("th_state", "something-else-entirely")

    resp = client.get("/callback?code=abc&state=not-the-cookie-value")
    assert resp.status_code == 400
    assert "expired" in resp.text
    assert "/callback rejected: state/cookie mismatch" in caplog.text


def test_callback_rejects_unknown_state(client):
    resp = client.get("/callback?code=abc&state=not-a-real-one")
    assert resp.status_code == 400
    assert "expired" in resp.text


def test_callback_rejects_state_replay(oauth_server, client, monkeypatch):
    _mock_exchange(monkeypatch, oauth_server)
    request_id = _register_and_authorize(oauth_server, client)
    state = _start_pending(client, oauth_server, request_id)

    first = client.get(f"/callback?code=abc&state={state}", follow_redirects=False)
    assert first.status_code in (302, 307)

    second = client.get(f"/callback?code=abc&state={state}")
    assert second.status_code == 400


def test_callback_surfaces_trusthub_error_query_param(oauth_server, client):
    request_id = _register_and_authorize(oauth_server, client)
    state = _start_pending(client, oauth_server, request_id)

    resp = client.get(f"/callback?error=invalid_request&state={state}")
    assert resp.status_code == 400
    assert "invalid_request" in resp.text


def test_callback_surfaces_token_exchange_failure(oauth_server, client, monkeypatch):
    _mock_exchange(monkeypatch, oauth_server, token_status=400)
    request_id = _register_and_authorize(oauth_server, client)
    state = _start_pending(client, oauth_server, request_id)

    resp = client.get(f"/callback?code=abc&state={state}")
    assert resp.status_code == 400
    assert "Sign-in failed" in resp.text
    # Master's raw error body must not leak to the user (finding #9).
    assert "invalid_grant" not in resp.text


def _bearer_claims(monkeypatch, server, claims):
    from fastmcp.server.auth import AccessToken

    token = AccessToken(token="t", client_id="c", scopes=[], claims=claims)
    monkeypatch.setattr(server, "get_access_token", lambda: token)


def test_get_session_is_keyed_by_sid_not_email(oauth_server, client, monkeypatch):
    _mock_exchange(monkeypatch, oauth_server)
    request_id = _register_and_authorize(oauth_server, client)
    state = _start_pending(client, oauth_server, request_id)
    assert client.get(f"/callback?code=abc&state={state}", follow_redirects=False).status_code in (302, 307)
    [(sid, (_, session))] = oauth_server._user_sessions.items()

    _bearer_claims(monkeypatch, oauth_server, {"email": "a@b.c", "sid": sid})
    assert oauth_server.get_session() is session

    # Same email, someone else's (or a pre-fix, email-only) bearer - must not reach this session.
    from src.session import SessionError

    for claims in ({"email": "a@b.c", "sid": "another-login"}, {"email": "a@b.c"}):
        _bearer_claims(monkeypatch, oauth_server, claims)
        with pytest.raises(SessionError):
            oauth_server.get_session()


def test_trusthub_sign_out_revokes_every_token_from_that_login(oauth_server, client, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="lms_mcp")
    _mock_exchange(monkeypatch, oauth_server)
    request_id = _register_and_authorize(oauth_server, client)
    state = _start_pending(client, oauth_server, request_id)
    redirect = client.get(f"/callback?code=abc&state={state}", follow_redirects=False).headers["location"]
    [sid] = oauth_server._user_sessions
    provider = oauth_server._oauth_provider

    async def issue():
        claude = await provider.get_client("test-client")
        code = await provider.load_authorization_code(claude, parse_qs(urlparse(redirect).query)["code"][0])
        first = await provider.exchange_authorization_code(claude, code)
        second = await provider.exchange_refresh_token(
            claude, await provider.load_refresh_token(claude, first.refresh_token), []
        )
        return first, second

    first, second = asyncio.run(issue())

    import anyio.from_thread

    monkeypatch.setattr(anyio.from_thread, "run", lambda fn, *args: asyncio.run(fn(*args)))
    oauth_server._mark_trusthub_signed_out(sid, "a@b.c")

    assert sid not in oauth_server._user_sessions
    for token in (first.access_token, second.access_token):
        assert asyncio.run(provider.load_access_token(token)) is None
    assert f"sign-in complete for a@b.c (session {sid})" in caplog.text
    assert f"TrustHub refresh failed for a@b.c (session {sid})" in caplog.text
    assert f"revoked session {sid}: 4 tokens" in caplog.text
    assert first.access_token not in caplog.text and first.refresh_token not in caplog.text


def test_stale_user_sessions_are_pruned_on_next_login(oauth_server, client, monkeypatch):
    _mock_exchange(monkeypatch, oauth_server)
    for _ in range(2):
        state = _start_pending(client, oauth_server, _register_and_authorize(oauth_server, client))
        assert client.get(f"/callback?code=abc&state={state}", follow_redirects=False).status_code in (302, 307)
    old_sid, fresh_sid = oauth_server._user_sessions
    _, session = oauth_server._user_sessions[old_sid]
    oauth_server._user_sessions[old_sid] = (time.time() - oauth_server._REFRESH_TOKEN_TTL - 1, session)

    _bearer_claims(monkeypatch, oauth_server, {"email": "a@b.c", "sid": fresh_sid})
    oauth_server.get_session()

    assert list(oauth_server._user_sessions) == [fresh_sid]
