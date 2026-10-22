"""Contract tests: the properties that must hold across modules, not within one."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import pytest

from src.tools.transactions import _summary_body, _txn_body

TENANT_PARAM = re.compile(r"entity|program|tenant|view_?type", re.IGNORECASE)


@pytest.mark.parametrize(
    "to_date",
    [
        "2026-09-21",
        "2026-09-21T23:59:59",
        "2026-09-21T23:59:59.000Z",
        "2026-09-21T00:00:00.000Z",
        "2026-09-21 23:59:59",
    ],
)
def test_transactions_and_summary_send_the_same_upper_bound(to_date: str) -> None:
    """Both endpoints apply plusDays(1) upstream (TransactionService:336,
    TransactionSummaryService:257). If the two tools send different bounds, their
    totals silently disagree - the bug this test exists to catch."""
    txn = _txn_body(None, None, None, "2026-08-01", to_date)
    summary = _summary_body(None, None, "2026-08-01", to_date)
    assert txn["transactionToDate"] == summary["transactionToDate"]
    assert txn["transactionToDate"].endswith("T00:00:00.000Z")
    assert txn["transactionFromDate"] == summary["transactionFromDate"]


def test_no_registered_tool_exposes_a_tenant_identifier() -> None:
    """Non-negotiable #1/#2: the model must not be able to name a tenant. Checked
    against what FastMCP actually publishes, over every tool that takes arguments."""
    from src.server import mcp

    tools = asyncio.run(mcp.list_tools())
    assert len(tools) >= 7

    offenders: list[tuple[str, str]] = []
    for tool in tools:
        params: dict[str, Any] = (tool.parameters or {}).get("properties", {})
        offenders += [(tool.name, p) for p in params if TENANT_PARAM.search(p)]
    assert not offenders, f"tenant identifiers exposed to the model: {offenders}"


def test_every_tool_that_takes_arguments_accepts_scope() -> None:
    from src.server import mcp

    tools = asyncio.run(mcp.list_tools())
    for tool in tools:
        params = (tool.parameters or {}).get("properties", {})
        if params:
            assert "scope" in params, f"{tool.name} takes arguments but no scope"


def _multi_scope_session():
    """Real Session (not a stub) with two entitled scopes, over a mock transport."""
    import base64
    import json as _json
    import time

    import httpx

    from src.session import Session

    header = base64.urlsafe_b64encode(b'{"alg":"HS512"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        _json.dumps({"userId": "u1", "exp": int(time.time()) + 3600}).encode()
    ).decode().rstrip("=")
    token = f"{header}.{body}.aJ62MhlENiY8latX064xOBQqfBgd_qRbEdLANyGSd56"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/v1/users/entities"):
            return httpx.Response(200, json=[
                {"entityId": "E1", "entityName": "TransBnk"},
                {"entityId": "E2", "entityName": "OtherCo"},
            ])
        if path.endswith("/v1/users/programs"):
            return httpx.Response(200, json=[{"programId": 21, "programName": "General"}])
        return httpx.Response(200, json={"content": [], "totalElements": 0, "totalPages": 0, "last": True})

    return Session(
        token=token, master_base_url="https://m.invalid", lms_base_url="https://l.invalid",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_real_session_drives_a_real_tool_and_asks_which_scope():
    """The stub-vs-real seam: a real Session through a real tool, two scopes, no scope given."""
    from src.session import ScopeRequired
    from src.tools.accounts import get_balances

    session = _multi_scope_session()
    assert len(session.scopes) == 2

    with pytest.raises(ScopeRequired) as exc:
        get_balances(session)
    message = str(exc.value)
    assert "transbnk-general" in message and "otherco-general" in message

    combined = get_balances(session, scope="all")
    assert sorted(combined["scopes_ok"]) == ["otherco-general", "transbnk-general"]

    one = get_balances(session, scope="transbnk-general")
    assert one["scopes_ok"] == ["transbnk-general"]
