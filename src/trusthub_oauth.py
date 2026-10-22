"""lms-mcp as an OAuth 2.1 + PKCE client of TrustHub's master API - active only when TRUSTHUB_OAUTH_CLIENT_ID, TRUSTHUB_OAUTH_CLIENT_SECRET, and TRUSTHUB_LOGIN_URL are all set."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode

import httpx

from .oauth import _Store

_PENDING_TTL = 600  # long enough to type a password and an OTP on TrustHub's page

def client_id() -> str:
    """No deployment's OAuth client identifier is baked into this open-source codebase."""
    return os.environ.get("TRUSTHUB_OAUTH_CLIENT_ID", "")


def client_secret() -> str | None:
    return os.environ.get("TRUSTHUB_OAUTH_CLIENT_SECRET")


def enabled() -> bool:
    return bool(client_id()) and bool(client_secret()) and bool(login_url())


def login_url() -> str:
    """No TrustHub host is baked into this open-source codebase."""
    return os.environ.get("TRUSTHUB_LOGIN_URL", "")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _generate_pkce() -> tuple[str, str]:
    """(code_verifier, code_challenge) - verifier is 43 chars, within RFC 7636's
    43-128 range; challenge is BASE64URL(SHA256(verifier)), per S256."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


class PendingAuth:
    """One `state` -> {our own request_id, PKCE verifier, redirect_uri} record,
    alive just long enough for the user to finish TrustHub's hosted login."""

    def __init__(self) -> None:
        self._store = _Store("trusthub-pkce")

    async def start(self, request_id: str, redirect_uri: str, consent: bool, consent_content: str) -> tuple[str, str]:
        """Stores the pending attempt, returns (redirect URL, state) - `consent`/`consent_content` record on master's side that our own disclaimer was accepted, and exactly what it said."""
        state = secrets.token_urlsafe(24)
        verifier, challenge = _generate_pkce()
        await self._store.set(
            state,
            json.dumps({"request_id": request_id, "verifier": verifier, "redirect_uri": redirect_uri}),
            ttl_seconds=_PENDING_TTL,
        )
        params = {
            "client_id": client_id(),
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "consent": "true" if consent else "false",
            "consent_content": consent_content,
        }
        return f"{login_url()}?{urlencode(params)}", state

    async def consume(self, state: str) -> dict[str, str] | None:
        """Looks up and deletes the pending record - a `state` is usable once."""
        raw = await self._store.get(state)
        if raw is None:
            return None
        await self._store.delete(state)
        return json.loads(raw)


def exchange_code(master_base_url: str, code: str, code_verifier: str, redirect_uri: str, client: httpx.Client) -> tuple[str, int]:
    """POSTs /v1/auth/oauth/token with the *same* httpx.Client the caller will keep -
    its cookie jar then holds the rotating refresh_token cookie, exactly what
    Session._refresh() already expects to find there. Returns (access_token, expires_in)."""
    resp = client.post(
        f"{master_base_url.rstrip('/')}/v1/auth/oauth/token",
        auth=(client_id(), client_secret() or ""),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        },
    )
    if resp.status_code >= 400:
        try:
            detail = resp.json()
        except ValueError:
            detail = resp.text
        raise RuntimeError(f"oauth/token failed ({resp.status_code}): {detail}")
    body = resp.json()
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("oauth/token succeeded but returned no access_token")
    return token, body.get("expires_in", 900)
