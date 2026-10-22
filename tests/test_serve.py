"""serve() only ever runs as an OAuth-protected HTTP connector - no host or env var bypasses that."""

from __future__ import annotations

import pytest

import src.server as server


@pytest.fixture
def runs(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(server, "_oauth_provider", None)
    monkeypatch.setattr(server.mcp, "run", lambda **kw: calls.append(kw))
    return calls


@pytest.mark.parametrize("host", ["0.0.0.0", "127.0.0.1", "localhost"])
def test_refuses_without_oauth_on_any_bind(runs, monkeypatch, host):
    monkeypatch.setenv("LMS_MCP_HOST", host)
    with pytest.raises(SystemExit) as exc:
        server.serve()
    assert "LMS_MCP_OAUTH_BASE_URL" in str(exc.value)
    assert runs == []


def test_removed_unauthenticated_opt_in_has_no_effect(runs, monkeypatch):
    monkeypatch.setenv("LMS_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("LMS_MCP_ALLOW_UNAUTHENTICATED_HTTP", "1")
    with pytest.raises(SystemExit):
        server.serve()
    assert runs == []


def test_oauth_configured_starts_on_a_public_bind(runs, monkeypatch):
    monkeypatch.setattr(server, "_oauth_provider", object())
    monkeypatch.setattr(server, "_oauth_base_url", "https://test-deploy.example")
    monkeypatch.setenv("LMS_MCP_HOST", "0.0.0.0")
    server.serve()
    assert runs[0]["host"] == "0.0.0.0"
    assert runs[0]["transport"] == "http"


def test_refuses_redis_without_password(runs, monkeypatch):
    monkeypatch.setattr(server, "_oauth_provider", object())
    monkeypatch.setattr(server, "_oauth_base_url", "https://test-deploy.example")
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    monkeypatch.delenv("LMS_MCP_ALLOW_UNAUTHENTICATED_REDIS", raising=False)
    with pytest.raises(SystemExit) as exc:
        server.serve()
    assert "REDIS_PASSWORD" in str(exc.value)
    assert runs == []


def test_refuses_redis_without_password_even_with_wrong_optout_value(runs, monkeypatch):
    monkeypatch.setattr(server, "_oauth_provider", object())
    monkeypatch.setattr(server, "_oauth_base_url", "https://test-deploy.example")
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    monkeypatch.setenv("LMS_MCP_ALLOW_UNAUTHENTICATED_REDIS", "true")  # only "1" counts
    with pytest.raises(SystemExit) as exc:
        server.serve()
    assert "REDIS_PASSWORD" in str(exc.value)
    assert runs == []


def test_unauthenticated_redis_opt_out_starts(runs, monkeypatch):
    monkeypatch.setattr(server, "_oauth_provider", object())
    monkeypatch.setattr(server, "_oauth_base_url", "https://test-deploy.example")
    monkeypatch.setenv("LMS_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)
    monkeypatch.setenv("LMS_MCP_ALLOW_UNAUTHENTICATED_REDIS", "1")
    server.serve()
    assert runs[0]["host"] == "0.0.0.0"


def test_redis_password_set_needs_no_optout(runs, monkeypatch):
    monkeypatch.setattr(server, "_oauth_provider", object())
    monkeypatch.setattr(server, "_oauth_base_url", "https://test-deploy.example")
    monkeypatch.setenv("LMS_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.setenv("REDIS_PASSWORD", "hunter2")
    monkeypatch.delenv("LMS_MCP_ALLOW_UNAUTHENTICATED_REDIS", raising=False)
    server.serve()
    assert runs[0]["host"] == "0.0.0.0"
