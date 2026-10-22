"""Account identity and balance reads against TrustHub's LMS banking API.

POST /v1/accounts/list backs both tools below - list_accounts for identity/metadata,
get_balances for money questions with staleness and coverage framing on top.
"""

from __future__ import annotations

from typing import Any

from src.paging import build_page_meta, clamp_size, fan_out_pages
from src.session import Session


def _accounts_body(bank: str | None, account_number: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if bank is not None:
        body["bankCode"] = [bank]
    if account_number is not None:
        body["accountNumber"] = [account_number]
    return body


def _to_amount(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(str(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


def list_accounts(
    session: Session,
    bank: str | None = None,
    account_number: str | None = None,
    scope: str | None = None,
    page: int = 0,
    size: int = 50,
) -> dict[str, Any]:
    """List TrustHub LMS bank accounts by identity/metadata - bank, account number, IFSC, product/branch.

    Use this for "which accounts do we have" questions. For "what's our balance"
    questions use `get_balances` instead: it adds the staleness flag and a coverage
    total that this tool does not compute. `account_number` is EXACT MATCH ONLY -
    upstream compares encrypted values, so a partial or prefix number silently matches
    nothing; a 0-result response does not mean the account doesn't exist.

    `scope`: omit it when the account has one entity/program (the common case). If it has
    several, the tool returns an error listing them - ask the user which one, then pass its
    handle. Pass scope='all' only when the user explicitly wants every scope combined.
    """
    size = clamp_size(size)
    body = _accounts_body(bank, account_number)
    rows, page_jsons, scopes_ok, scopes_failed = fan_out_pages(
        session,
        scope,
        lambda s: session.post("/v1/accounts/list", s, body=body, page=page, size=size).json(),
    )
    return {
        "rows": rows,
        "scopes_ok": scopes_ok,
        "scopes_failed": scopes_failed,
        **build_page_meta(page_jsons, page, size),
    }


def get_balances(
    session: Session,
    bank: str | None = None,
    scope: str | None = None,
    page: int = 0,
    size: int = 50,
) -> dict[str, Any]:
    """TrustHub LMS bank balances with staleness and coverage - the tool for "what's our balance".

    Each row carries `fetched_at` (upstream `balanceFetchedAt`) and `is_stale`
    (`isLatestBalanceFetched` inverted). `total_balance` sums ONLY the non-stale rows -
    never a bare total - and `coverage` states how many of the accounts on this page
    that total actually covers, e.g. "total across 1 of 15 accounts; 14 never fetched".
    Use `list_accounts` instead for account identity/metadata questions.

    `scope`: omit it when the account has one entity/program (the common case). If it has
    several, the tool returns an error listing them - ask the user which one, then pass its
    handle. Pass scope='all' only when the user explicitly wants every scope combined.
    """
    size = clamp_size(size)
    body = _accounts_body(bank, None)
    raw_rows, page_jsons, scopes_ok, scopes_failed = fan_out_pages(
        session,
        scope,
        lambda s: session.post("/v1/accounts/list", s, body=body, page=page, size=size).json(),
    )

    rows = []
    for acct in raw_rows:
        fetched = bool(acct.get("isLatestBalanceFetched"))
        rows.append(
            {
                "accountNumber": acct.get("accountNumber"),
                "bankCode": acct.get("bankCode"),
                "balanceAmount": acct.get("balanceAmount"),
                "availableBalance": acct.get("availableBalance"),
                "fetched_at": acct.get("balanceFetchedAt"),
                "is_stale": not fetched,
            }
        )

    counted = [r for r in rows if not r["is_stale"] and _to_amount(r["balanceAmount"]) is not None]
    total_accounts, fetched_count = len(rows), len(counted)
    uncounted = total_accounts - fetched_count
    total_balance = round(sum(_to_amount(r["balanceAmount"]) or 0.0 for r in counted), 2)

    if total_accounts == 0 and scopes_failed:
        first = scopes_failed[0].get("error", "unknown error")
        coverage = f"no data: every requested scope failed - {first}"
    elif total_accounts == 0:
        coverage = "no accounts found for the requested scope(s)"
    elif uncounted == 0:
        coverage = f"total across all {total_accounts} accounts"
    else:
        coverage = (
            f"total across {fetched_count} of {total_accounts} accounts; "
            f"{uncounted} excluded (stale or no balance recorded)"
        )
    if scopes_failed:
        coverage += f"; {len(scopes_failed)} scope(s) failed and are missing from this total"

    return {
        "rows": rows,
        "total_balance": total_balance,
        "coverage": coverage,
        "scopes_ok": scopes_ok,
        "scopes_failed": scopes_failed,
        **build_page_meta(page_jsons, page, size),
    }
