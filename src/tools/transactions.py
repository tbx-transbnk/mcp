"""Transaction reads and summaries against TrustHub's LMS banking API.

Three endpoints, three different date/pagination rules - each function below sends
dates through the exact coercion the corresponding upstream parser expects.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from src.dates import to_lms_date, to_lms_datetime, validate_date_order
from src.paging import build_page_meta, clamp_size, fan_out_pages
from src.session import Session

_VALID_TRANSACTION_TYPES = {"CREDIT", "DEBIT"}


def _validate_transaction_type(transaction_type: str) -> str:
    normalized = transaction_type.strip().upper()
    if normalized not in _VALID_TRANSACTION_TYPES:
        raise ValueError(
            f"transaction_type must be one of {sorted(_VALID_TRANSACTION_TYPES)}, got {transaction_type!r}"
        )
    return normalized


def _txn_body(
    bank: str | None,
    account_number: str | None,
    transaction_type: str | None,
    from_date: Any,
    to_date: Any,
) -> dict[str, Any]:
    if from_date is not None and to_date is not None:
        validate_date_order(from_date, to_date)
    body: dict[str, Any] = {}
    if bank is not None:
        body["bankCode"] = [bank]
    if account_number is not None:
        body["accountNumber"] = [account_number]
    if transaction_type is not None:
        body["transactionType"] = _validate_transaction_type(transaction_type)
    if from_date is not None:
        body["transactionFromDate"] = to_lms_datetime(from_date)
    if to_date is not None:
        # Upstream does plusDays(1) on this bound (TransactionService:336), as the summary
        # endpoint does; truncate to midnight so both land on the same instant.
        body["transactionToDate"] = to_lms_datetime(to_lms_date(to_date))
    return body


def list_transactions(
    session: Session,
    from_date: Any = None,
    to_date: Any = None,
    account_number: str | None = None,
    bank: str | None = None,
    transaction_type: str | None = None,
    scope: str | None = None,
    page: int = 0,
    size: int = 50,
) -> dict[str, Any]:
    """List individual TrustHub LMS bank transactions (the full, unaggregated feed).

    `transaction_type` must be exactly "CREDIT" or "DEBIT" if given. `account_number`
    is EXACT MATCH ONLY - upstream compares encrypted values, so a partial/prefix
    number silently matches nothing. `bank` filters by bank code. Dates accept any
    sensible format and are coerced internally - never pass a wire-format string.

    `scope`: omit it when the account has one entity/program (the common case). If it has
    several, the tool returns an error listing them - ask the user which one, then pass its
    handle. Pass scope='all' only when the user explicitly wants every scope combined.
    """
    size = clamp_size(size)
    body = _txn_body(bank, account_number, transaction_type, from_date, to_date)
    rows, page_jsons, scopes_ok, scopes_failed = fan_out_pages(
        session,
        scope,
        lambda s: session.post("/v1/transactions/list", s, body=body, page=page, size=size).json(),
    )
    return {
        "rows": rows,
        "scopes_ok": scopes_ok,
        "scopes_failed": scopes_failed,
        **build_page_meta(page_jsons, page, size),
    }


def _summary_body(
    bank: str | None,
    account_number: str | None,
    from_date: Any,
    to_date: Any,
) -> dict[str, Any]:
    if from_date is not None and to_date is not None:
        validate_date_order(from_date, to_date)
    body: dict[str, Any] = {}
    if bank is not None:
        body["bankName"] = [bank]
    if account_number is not None:
        body["accountNumber"] = [account_number]
    if from_date is not None:
        body["transactionFromDate"] = to_lms_datetime(from_date)
    if to_date is not None:
        # Upstream does plusDays(1) on this bound (TransactionSummaryService:257); truncate
        # to midnight so it matches the transactions list, which does the same.
        body["transactionToDate"] = to_lms_datetime(to_lms_date(to_date))
    return body


def transaction_summary(
    session: Session,
    from_date: Any = None,
    to_date: Any = None,
    account_number: str | None = None,
    bank: str | None = None,
    scope: str | None = None,
    page: int = 0,
    size: int = 50,
) -> dict[str, Any]:
    """Per-account TrustHub LMS transaction totals (credit/debit counts and amounts), not the feed.

    The nested `transactions[]` array upstream returns per row is STRIPPED here - use
    `list_transactions` for the individual transactions. `bank` filters by bank name
    (not bank code, unlike the other transaction tools - same MCP-level parameter,
    different upstream field). `account_number` is EXACT MATCH ONLY. Over the same
    `from_date`/`to_date` range this tool and `list_transactions` cover the same
    calendar days.

    `scope`: omit it when the account has one entity/program (the common case). If it has
    several, the tool returns an error listing them - ask the user which one, then pass its
    handle. Pass scope='all' only when the user explicitly wants every scope combined.
    """
    size = clamp_size(size)
    body = _summary_body(bank, account_number, from_date, to_date)
    rows, page_jsons, scopes_ok, scopes_failed = fan_out_pages(
        session,
        scope,
        lambda s: session.post("/v1/transaction-summary/list", s, body=body, page=page, size=size).json(),
    )
    stripped = [{k: v for k, v in row.items() if k != "transactions"} for row in rows]
    return {
        "rows": stripped,
        "scopes_ok": scopes_ok,
        "scopes_failed": scopes_failed,
        **build_page_meta(page_jsons, page, size),
    }


def _end_date_exclusive(end_date: Any) -> str:
    normalized = to_lms_date(end_date)
    next_day = datetime.strptime(normalized, "%Y-%m-%d").date() + timedelta(days=1)
    return next_day.strftime("%Y-%m-%d")


def _is_empty_row(row: dict[str, Any]) -> bool:
    # The empty-range sentinel has a null date, and @JsonInclude(NON_NULL) drops the key
    # entirely. Real rows are grouped from existing transactions, so always carry a date.
    return not row.get("date")


def credit_debit_summary(
    session: Session,
    start_date: Any = None,
    end_date: Any = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Daily TrustHub LMS credit/debit totals. Range is INCLUSIVE of both `start_date` and `end_date`
    (whole days; any time component is ignored). Pass both dates or neither - upstream
    discards a one-sided range and silently returns the last 7 days, so that is rejected
    here. Not paginated. Two upstream quirks are handled transparently: a scope with no
    accounts throws instead of returning empty, and an empty date range returns a single
    all-zero placeholder row; both are collapsed to no rows and reported via `note`.

    `scope`: omit it when the account has one entity/program (the common case). If it has
    several, the tool returns an error listing them - ask the user which one, then pass its
    handle. Pass scope='all' only when the user explicitly wants every scope combined.
    """
    if (start_date is None) != (end_date is None):
        raise ValueError(
            "pass both start_date and end_date or neither; "
            "upstream ignores a one-sided range and returns the last 7 days"
        )
    if start_date is not None:
        validate_date_order(start_date, end_date, from_name="start_date", to_name="end_date")
    params: dict[str, str] = {}
    if start_date is not None:
        params["startDate"] = to_lms_date(start_date)
    if end_date is not None:
        params["endDate"] = _end_date_exclusive(end_date)

    no_accounts_scopes: list[str] = []

    def fetch(s: Any) -> list[Any]:
        try:
            data = session.get("/v1/transactions/credit-debit", s, **params).json()
        except Exception as exc:
            if "no accounts found" in str(exc).lower():
                no_accounts_scopes.append(s.handle)
                return []
            raise
        if len(data) == 1 and _is_empty_row(data[0]):
            return []
        return data

    scopes = session.pick(scope)
    if len(scopes) == 1:
        s = scopes[0]
        result: dict[str, Any] = {"rows": fetch(s), "scopes_ok": [s.handle], "scopes_failed": []}
    else:
        result = session.fan_out(fetch, scope)

    notes = []
    if not result["rows"]:
        notes.append("no transactions in this range")
    if no_accounts_scopes:
        notes.append(f"no accounts found for scope(s): {', '.join(no_accounts_scopes)}")
    if notes:
        result["note"] = "; ".join(notes)
    return result
