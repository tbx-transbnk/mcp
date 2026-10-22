"""LmsOAuthProvider in isolation - the parts the HTTP-level OAuth tests don't
exercise directly. revoke_session backs Session.on_signed_out (see server.py's
_mark_trusthub_signed_out)."""

from __future__ import annotations

import asyncio
import time

import pytest
from mcp.server.auth.provider import AuthorizationParams, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull

from src import oauth
from src.oauth import LmsOAuthProvider

CLAUDE_CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def _provider() -> LmsOAuthProvider:
    return LmsOAuthProvider(base_url="https://test-deploy.example")


def _client_info(redirect_uri: str = CLAUDE_CALLBACK, client_name: str | None = None) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="test-client", client_name=client_name, redirect_uris=[redirect_uri],
        grant_types=["authorization_code"], response_types=["code"],
        token_endpoint_auth_method="none",
    )


def _registration_error(provider: LmsOAuthProvider, client: OAuthClientInformationFull) -> RegistrationError | None:
    # RegistrationError is a frozen dataclass, so it can't propagate out through asyncio.run's frames.
    async def attempt():
        try:
            await provider.register_client(client)
        except RegistrationError as e:
            return e
        return None

    return asyncio.run(attempt())


def test_revoke_session_kills_both_tokens():
    provider = _provider()
    client = _client_info()

    async def issue_and_revoke():
        await provider.register_client(client)
        token = await provider._issue_tokens(client, [], subject="a@b.c", sid="sid-1")
        assert await provider.load_access_token(token.access_token) is not None
        await provider.revoke_session("sid-1")
        return (
            await provider.load_access_token(token.access_token),
            await provider.load_refresh_token(client, token.refresh_token),
        )

    assert asyncio.run(issue_and_revoke()) == (None, None)


def test_revoke_session_is_a_noop_for_unknown_sid():
    asyncio.run(_provider().revoke_session("nobody"))


def test_revocation_kills_every_outstanding_token_not_just_the_latest_pair():
    provider = _provider()
    client = _client_info()

    async def scenario():
        await provider.register_client(client)
        first = await provider._issue_tokens(client, [], subject="a@b.c", sid="sid-1")
        second = await provider.exchange_refresh_token(
            client, await provider.load_refresh_token(client, first.refresh_token), []
        )
        third = await provider._issue_tokens(client, [], subject="a@b.c", sid="sid-1")
        # The pre-refresh access token is still live until revoked - the old index lost track of it.
        assert await provider.load_access_token(first.access_token) is not None
        await provider.revoke_session("sid-1")
        return [await provider.load_access_token(t.access_token) for t in (first, second, third)] + [
            await provider.load_refresh_token(client, t.refresh_token) for t in (second, third)
        ]

    assert asyncio.run(scenario()) == [None] * 5


def test_revocation_is_scoped_to_one_login():
    provider = _provider()
    client = _client_info()

    async def scenario():
        await provider.register_client(client)
        laptop = await provider._issue_tokens(client, [], subject="a@b.c", sid="sid-laptop")
        phone = await provider._issue_tokens(client, [], subject="a@b.c", sid="sid-phone")
        await provider.revoke_session("sid-laptop")
        return await provider.load_access_token(laptop.access_token), await provider.load_access_token(phone.access_token)

    laptop_after, phone_after = asyncio.run(scenario())
    assert laptop_after is None
    assert phone_after is not None and phone_after.claims == {"email": "a@b.c", "sid": "sid-phone"}


def test_sid_survives_code_exchange_and_refresh():
    provider = _provider()
    client = _client_info()

    async def scenario():
        await provider.register_client(client)
        params = AuthorizationParams(
            state=None, scopes=None, code_challenge="c" * 43,
            redirect_uri=CLAUDE_CALLBACK, redirect_uri_provided_explicitly=True,
        )
        request_id = (await provider.authorize(client, params)).split("request_id=")[1]
        redirect = await provider.complete_authorization(request_id, "a@b.c", "sid-xyz")
        code = await provider.load_authorization_code(client, redirect.split("code=")[1].split("&")[0])
        issued = await provider.exchange_authorization_code(client, code)
        refreshed = await provider.exchange_refresh_token(
            client, await provider.load_refresh_token(client, issued.refresh_token), []
        )
        return await provider.load_access_token(refreshed.access_token)

    assert asyncio.run(scenario()).claims == {"email": "a@b.c", "sid": "sid-xyz"}


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://evil.example/callback",
        "https://claude.ai/api/mcp/auth_callback/../../evil",
        "https://claude.ai.evil.example/api/mcp/auth_callback",
        "https://claude.ai/api/mcp/auth_callback?next=https://evil.example",
        "http://claude.ai/api/mcp/auth_callback",
        "https://localhost/callback",
        "http://localhost.evil.example/callback",
        "http://user@localhost/callback",
    ],
)
def test_register_rejects_non_allowlisted_redirect_uri(redirect_uri):
    error = _registration_error(_provider(), _client_info(redirect_uri))
    assert error is not None and error.error == "invalid_redirect_uri"


@pytest.mark.parametrize(
    "redirect_uri",
    [CLAUDE_CALLBACK, "https://claude.com/api/mcp/auth_callback", "http://localhost:6274/cb", "http://127.0.0.1:33418/"],
)
def test_register_accepts_claude_and_loopback_redirect_uris(redirect_uri):
    assert _registration_error(_provider(), _client_info(redirect_uri)) is None


def test_allowlist_is_env_overridable(monkeypatch):
    monkeypatch.setenv("LMS_MCP_ALLOWED_REDIRECT_URIS", "https://partner.example/cb")
    provider = _provider()
    assert _registration_error(provider, _client_info("https://partner.example/cb")) is None
    assert _registration_error(provider, _client_info(CLAUDE_CALLBACK)) is not None


@pytest.mark.parametrize("name", ["C" * 129, "Claude\nadmin", "Claude‮edualC"])
def test_register_rejects_long_or_control_char_client_name(name):
    error = _registration_error(_provider(), _client_info(client_name=name))
    assert error is not None and error.error == "invalid_client_metadata"


def test_get_client_ignores_a_pre_allowlist_registration():
    provider = _provider()
    legacy = _client_info("https://evil.example/callback")
    asyncio.run(provider._clients.set(legacy.client_id, legacy.model_dump_json(), ttl_seconds=60))
    assert asyncio.run(provider.get_client(legacy.client_id)) is None


def test_client_registration_has_a_real_ttl_refreshed_on_read():
    provider = _provider()
    asyncio.run(provider.register_client(_client_info()))
    raw, expires_at = provider._clients._local["test-client"]
    assert expires_at - time.time() <= oauth._CLIENT_TTL
    provider._clients._local["test-client"] = (raw, time.time() + 5)
    assert asyncio.run(provider.get_client("test-client")) is not None
    assert provider._clients._local["test-client"][1] - time.time() > oauth._CLIENT_TTL - 60


def test_stored_keys_and_values_never_contain_raw_tokens(monkeypatch):
    monkeypatch.delenv("REDIS_HOST", raising=False)
    provider = LmsOAuthProvider(base_url="https://test-deploy.example")
    client = OAuthClientInformationFull(client_id="c", redirect_uris=["https://claude.ai/api/mcp/auth_callback"])

    async def run():
        issued = await provider._issue_tokens(client, [], "a@b.c", "sid-1")
        access = await provider.load_access_token(issued.access_token)
        refresh = await provider.load_refresh_token(client, issued.refresh_token)
        dump = repr([vars(s)["_local"] for s in vars(provider).values() if hasattr(s, "_local")])
        await provider.revoke_session("sid-1")
        gone = await provider.load_access_token(issued.access_token), await provider.load_refresh_token(client, issued.refresh_token)
        return issued, access, refresh, dump, gone

    issued, access, refresh, dump, gone = asyncio.run(run())
    assert access.token == issued.access_token and refresh.token == issued.refresh_token
    assert issued.access_token not in dump and issued.refresh_token not in dump
    assert gone == (None, None)
