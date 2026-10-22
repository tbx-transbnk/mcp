"""_ForceHTTPSMiddleware only sets HSTS, never redirects. A conditional
http->https redirect was tried and pulled twice in production: first it 308'd
k8s health probes (no X-Forwarded-Proto at all, in-cluster traffic bypasses
the ELB) into a crash loop; then, even restricted to an exact "http" match, it
308'd real external HTTPS traffic into an infinite self-redirect, because this
deployment's ELB/ingress chain doesn't reliably report the original scheme in
that header. Confirmed from live pod logs and a real curl against prod.
"""

from __future__ import annotations

from starlette.middleware import Middleware
import pytest
from starlette.testclient import TestClient

import src.server as server


def _client():
    app = server.mcp.http_app(middleware=[Middleware(server._ForceHTTPSMiddleware)])
    return TestClient(app, follow_redirects=False)


def test_never_redirects_regardless_of_forwarded_proto():
    # /login with no request_id is a 400 (nothing to do here without one), not a
    # redirect - that status itself is incidental here; what matters is no 3xx.
    with _client() as c:
        no_header = c.get("/login")
        says_http = c.get("/login", headers={"x-forwarded-proto": "http"})
        says_https = c.get("/login", headers={"x-forwarded-proto": "https"})
    assert no_header.status_code == 400
    assert says_http.status_code == 400
    assert says_https.status_code == 400


def test_always_sets_hsts():
    with _client() as c:
        resp = c.get("/login")
    assert "Strict-Transport-Security" in resp.headers


def test_serve_refuses_to_start_without_oauth(monkeypatch):
    monkeypatch.setattr(server, "_oauth_provider", None)
    with pytest.raises(SystemExit, match="LMS_MCP_OAUTH_BASE_URL"):
        server.serve()
