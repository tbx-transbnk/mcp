"""_OriginValidationMiddleware and _RateLimitMiddleware."""

from __future__ import annotations

import asyncio

from starlette.middleware import Middleware
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient

import src.server as server


def _client(*middleware_classes):
    app = server.mcp.http_app(middleware=[Middleware(m) for m in middleware_classes])
    return TestClient(app, follow_redirects=False)


def test_no_origin_header_passes_through():
    with _client(server._OriginValidationMiddleware) as c:
        resp = c.get("/login")
    assert resp.status_code != 403


def test_allowed_origin_passes_through():
    with _client(server._OriginValidationMiddleware) as c:
        resp = c.get("/login", headers={"origin": "https://claude.ai"})
    assert resp.status_code != 403


def test_disallowed_origin_rejected():
    with _client(server._OriginValidationMiddleware) as c:
        resp = c.get("/login", headers={"origin": "https://evil.example"})
    assert resp.status_code == 403


def test_own_oauth_base_url_origin_is_allowed(monkeypatch):
    monkeypatch.setattr(server, "_oauth_base_url", "https://test-deploy.example")
    with _client(server._OriginValidationMiddleware) as c:
        resp = c.get("/login", headers={"origin": "https://test-deploy.example"})
    assert resp.status_code != 403


def test_rate_limit_allows_requests_under_the_cap(monkeypatch):
    monkeypatch.setenv("LMS_MCP_RATE_LIMIT_PER_MINUTE", "5")
    with _client(server._RateLimitMiddleware) as c:
        for _ in range(5):
            assert c.get("/login").status_code != 429


def test_rate_limit_rejects_requests_over_the_cap(monkeypatch):
    monkeypatch.setenv("LMS_MCP_RATE_LIMIT_PER_MINUTE", "3")
    with _client(server._RateLimitMiddleware) as c:
        for _ in range(3):
            assert c.get("/login").status_code != 429
        assert c.get("/login").status_code == 429


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, host: str) -> None:
        self.client = _FakeClient(host)


async def _ok(_request):
    return PlainTextResponse("ok")


def test_rate_limit_tracks_ips_independently(monkeypatch):
    monkeypatch.setenv("LMS_MCP_RATE_LIMIT_PER_MINUTE", "1")
    middleware = server._RateLimitMiddleware(app=None)
    asyncio.run(middleware.dispatch(_FakeRequest("1.2.3.4"), _ok))
    capped = asyncio.run(middleware.dispatch(_FakeRequest("1.2.3.4"), _ok))
    other_ip = asyncio.run(middleware.dispatch(_FakeRequest("9.9.9.9"), _ok))
    assert capped.status_code == 429
    assert other_ip.status_code != 429
