"""Dashboard aggregate against TrustHub's LMS banking API.

GET /v1/dashboard/stats matches accounts by entityId OR link table (a union) -
list_accounts/accounts.list filters differently, so the two can legitimately disagree.
"""

from __future__ import annotations

from typing import Any

from src.session import Session


def _to_amount(value: Any) -> float:
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return 0.0


def dashboard_stats(session: Session, scope: str | None = None) -> dict[str, Any]:
    """TrustHub LMS dashboard summary (total accounts, total balance) - a quick headline figure.

    This is computed over a DIFFERENT account set than `list_accounts`/`get_balances`
    (entityId-match OR account-link, a union, vs. link-table-first elsewhere) and may
    legitimately disagree with them. Prefer `list_accounts`/`get_balances` for anything
    that must add up exactly; use this only for a rough headline number.

    `scope`: omit it when the account has one entity/program (the common case). If it has
    several, the tool returns an error listing them - ask the user which one, then pass its
    handle. Pass scope='all' only when the user explicitly wants every scope combined.
    """
    scopes = session.pick(scope)
    rows: list[dict[str, Any]] = []
    scopes_ok: list[str] = []
    scopes_failed: list[dict[str, str]] = []
    for s in scopes:
        try:
            data = session.get("/v1/dashboard/stats", s).json()
        except Exception as exc:
            scopes_failed.append({"scope": s.handle, "error": str(exc)})
            continue
        scopes_ok.append(s.handle)
        rows.append({"scope": s.handle, **data})

    total_accounts = sum(r.get("totalAccount") or 0 for r in rows)
    total_balance = round(sum(_to_amount(r.get("totalBalance")) for r in rows), 2)
    coverage = f"aggregated across {len(scopes_ok)} scope(s)"
    if any(not r.get("isLatestBalanceFetched") for r in rows):
        coverage += "; balances are NOT all current - use get_balances for per-account staleness"
    if scopes_failed:
        coverage += f"; {len(scopes_failed)} scope(s) failed and are excluded from the total"

    return {
        "rows": rows,
        "total_accounts": total_accounts,
        "total_balance": total_balance,
        "coverage": coverage,
        "scopes_ok": scopes_ok,
        "scopes_failed": scopes_failed,
    }
