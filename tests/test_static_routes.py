"""Routes that exist regardless of login flow: the favicon (needed for claude.ai's
connector list), and OAuth/registration endpoints staying unmounted by default
(LMS_MCP_OAUTH_BASE_URL unset). Moved from the now-deleted test_login_http_surface.py,
which otherwise tested the removed password+OTP browser page."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

import src.server as server


@pytest.fixture
def client():
    with TestClient(server.mcp.http_app()) as c:
        yield c


def test_favicon_serves_the_icon(client):
    resp = client.get("/favicon.ico")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/jpeg"


def test_oauth_and_registration_routes_unmounted_by_default(client):
    for path in ("/authorize", "/register", "/token", "/.well-known/oauth-authorization-server"):
        resp = client.get(path)
        assert resp.status_code == 404, f"{path} should not exist - no OAuth surface"


def test_healthz_always_returns_200_for_probes(client):
    # Unlike /login (400 without a request_id), this must never fail so a k8s
    # liveness/readiness probe can't crash-loop an otherwise-healthy pod.
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.text == "ok"
