"""The security boundary. See MCP_BUILD_PLAN.md §2.

entityId/programId never reach a tool signature - they live only in Scope,
built from master's own bootstrap responses, and are injected here into every
LMS request. viewType is hard-pinned to "PROGRAM" and filterProgramId/programName
are hard-pinned to null: this is a tenant boundary, not a default.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

_logger = logging.getLogger("lms_mcp")


class SessionError(Exception):
    pass


class ScopeRequired(SessionError):
    """Several scopes exist and the caller named none - the model must ask which."""


@dataclass(frozen=True)
class Scope:
    handle: str
    entity: str
    program: str
    _entity_id: str
    _program_id: Any


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    try:
        _, payload_b64, _ = token.split(".")
    except ValueError as exc:
        raise SessionError("malformed token: expected a JWT with three dot-separated segments") from exc
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except Exception as exc:
        raise SessionError("malformed token: could not decode payload") from exc
    if not isinstance(payload, dict):
        raise SessionError("malformed token: payload is not a JSON object")
    return payload


def _slugify(*parts: str) -> str:
    return "-".join(p.strip().lower().replace(" ", "-") for p in parts if p)


def _error_code(resp: httpx.Response) -> str | None:
    try:
        return resp.json().get("errorCode")
    except ValueError:
        return None


class Session:
    def __init__(
        self,
        token: str,
        master_base_url: str = "",
        lms_base_url: str = "",
        client: httpx.Client | None = None,
        on_signed_out: Callable[[], None] | None = None,
    ) -> None:
        self.master_base_url = master_base_url.rstrip("/")
        self.lms_base_url = lms_base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=30.0)
        # One refresh in flight at a time, plus a flag+hook for "can never be revived".
        self._refresh_lock = threading.Lock()
        self._on_signed_out = on_signed_out
        self.is_signed_out = False
        self._set_token(token)
        self._check_exp()
        self.scopes: list[Scope] = self._bootstrap()
        if not self.scopes:
            raise SessionError("token resolves to zero entity/program scopes - refusing to start")

    def _set_token(self, token: str) -> None:
        self.token = token
        self._payload = _decode_jwt_payload(token)

    def _refresh(self) -> bool:
        """Hidden refresh cookie rides along via the client's cookie jar."""
        resp = self._client.post(f"{self.master_base_url}/v1/auth/refresh")
        if resp.status_code >= 400:
            return False
        try:
            body = resp.json()
        except ValueError:
            return False
        token = body.get("accessToken") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            return False
        self._set_token(token)
        return True

    # Refresh this far ahead of expiry - a request landing in the final second, or any
    # clock skew between us and master, shouldn't have to hit a 401 first.
    _REFRESH_SKEW_SECONDS = 60

    def _near_exp(self) -> bool:
        exp = self._payload.get("exp")
        return exp is not None and time.time() >= exp - self._REFRESH_SKEW_SECONDS

    def _check_exp(self) -> None:
        if not self._near_exp():
            return
        with self._refresh_lock:
            # Another thread may have already refreshed while we waited for the lock -
            # only one refresh should actually hit the network per expiry.
            if not self._near_exp():
                return
            if self._refresh():
                return
            self.is_signed_out = True
            if self._on_signed_out:
                self._on_signed_out()
            expired_at = datetime.fromtimestamp(self._payload.get("exp", 0), tz=timezone.utc).isoformat()
            raise SessionError(f"token expired at {expired_at} and could not be refreshed - reconnect the connector")

    def _headers(self, scope: Scope | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.token}"}
        if scope is not None:
            headers["Program-Id"] = str(scope._program_id)
        return headers

    def _bootstrap(self) -> list[Scope]:
        resp = self._client.get(f"{self.master_base_url}/v1/users/entities", headers=self._headers())
        entities = self._records(resp, "entityId", "entityName")
        scopes: list[Scope] = []
        handle_counts: dict[str, int] = {}
        for entity in entities:
            entity_id = entity["entityId"]
            entity_name = entity["entityName"]
            resp = self._client.get(
                f"{self.master_base_url}/v1/users/programs",
                params={"entityId": entity_id},
                headers=self._headers(),
            )
            # MSA009 means zero programs assigned to this one entity, not the whole account -
            # skip it and keep checking the user's other entities. Any other 400 still aborts.
            if resp.status_code == 400 and _error_code(resp) == "MSA009":
                _logger.info("entity %s (%s) has no programs assigned, skipping", entity_id, entity_name)
                continue
            programs = self._records(resp, "programId", "programName")
            for program in programs:
                handle = _slugify(entity_name, program["programName"])
                handle_counts[handle] = handle_counts.get(handle, 0) + 1
                if handle_counts[handle] > 1:
                    handle = f"{handle}-{handle_counts[handle]}"
                scopes.append(
                    Scope(
                        handle=handle,
                        entity=entity_name,
                        program=program["programName"],
                        _entity_id=entity_id,
                        _program_id=program["programId"],
                    )
                )
        return scopes

    def _records(self, resp: httpx.Response, id_key: str, name_key: str) -> list[dict[str, Any]]:
        rows = self._raise_for_status(resp).json()
        if not isinstance(rows, list) or not all(
            isinstance(r, dict) and r.get(id_key) is not None and isinstance(r.get(name_key), str) for r in rows
        ):
            raise SessionError(f"master returned an unexpected {id_key}/{name_key} list")
        return rows

    def _describe_scopes(self) -> str:
        return "; ".join(f"{s.handle} ({s.entity} / {s.program})" for s in self.scopes)

    def pick(self, handle: str | None) -> list[Scope]:
        if handle is None:
            if len(self.scopes) == 1:
                return list(self.scopes)
            raise ScopeRequired(
                "this account has several entity/program scopes, so the answer depends on "
                "which one you mean. Ask the user which of these to use, then pass it as "
                f"`scope`: {self._describe_scopes()}. Pass scope='all' to combine them."
            )
        if handle.lower() == "all":
            return list(self.scopes)
        for scope in self.scopes:
            if scope.handle == handle:
                return [scope]
        matches = [s for s in self.scopes if s.program.lower() == handle.lower()]
        valid = ", ".join(s.handle for s in self.scopes)
        if len(matches) == 1:
            return matches
        if not matches:
            raise SessionError(f"unknown scope {handle!r}; valid handles: {valid}")
        raise SessionError(f"ambiguous scope {handle!r} matches multiple programs; valid handles: {valid}")

    def fan_out(self, fn: Callable[[Scope], Any], handle: str | None = None) -> dict[str, Any]:
        rows: list[Any] = []
        scopes_ok: list[str] = []
        scopes_failed: list[dict[str, str]] = []
        for scope in self.pick(handle):
            try:
                result = fn(scope)
            except Exception as exc:
                scopes_failed.append({"scope": scope.handle, "error": str(exc)})
                continue
            scopes_ok.append(scope.handle)
            rows.extend(result) if isinstance(result, list) else rows.append(result)
        return {"rows": rows, "scopes_ok": scopes_ok, "scopes_failed": scopes_failed}

    def get(self, path: str, scope: Scope, **params: Any) -> httpx.Response:
        self._check_exp()
        query = {k: v for k, v in params.items() if v is not None}
        query["entityId"] = scope._entity_id
        query["programId"] = scope._program_id
        query["viewType"] = "PROGRAM"
        query.pop("filterProgramId", None)
        query.pop("programName", None)
        resp = self._client.get(
            f"{self.lms_base_url}{path}",
            params=query,
            headers=self._headers(scope),
        )
        return self._raise_for_status(resp)

    def post(self, path: str, scope: Scope, body: dict[str, Any] | None = None, **params: Any) -> httpx.Response:
        self._check_exp()
        payload = dict(body or {})
        payload["entityId"] = scope._entity_id
        payload["programId"] = scope._program_id
        payload["viewType"] = "PROGRAM"
        payload["filterProgramId"] = None
        payload["programName"] = None
        query = {k: v for k, v in params.items() if v is not None}
        resp = self._client.post(
            f"{self.lms_base_url}{path}",
            params=query or None,
            json=payload,
            headers=self._headers(scope),
        )
        return self._raise_for_status(resp)

    def _raise_for_status(self, resp: httpx.Response) -> httpx.Response:
        if resp.is_success:
            return resp
        _logger.warning("upstream %s %s returned %s", resp.request.method, resp.request.url, resp.status_code)
        if resp.status_code in (401, 403):
            raise SessionError("token expired or invalid - paste a fresh one and restart")
        if resp.status_code == 400:
            try:
                message = resp.json().get("message", resp.text)
            except ValueError:
                message = resp.text
            raise SessionError(f"upstream rejected this request: {message}")
        if resp.status_code >= 500:
            raise SessionError("LMS unavailable - do not retry automatically")
        # Never httpx's raise_for_status(): its message carries the full URL, incl. entityId/programId.
        raise SessionError(f"LMS request failed (status {resp.status_code})")
