"""Date coercion for the LMS API's inconsistent wire formats.

See MCP_BUILD_PLAN.md §1 "Date handling". `to_lms_datetime` output must end in
exactly one character that occurs nowhere else in the string: LMS parses it by
globally replacing the last character before calling `LocalDateTime.parse`, so
any repeated trailing character corrupts the whole string server-side.
"""

from __future__ import annotations

from datetime import date, datetime

DateLike = str | date | datetime

_LMS_DATETIME_FMT = "%Y-%m-%dT%H:%M:%S.000Z"
_LMS_DATE_FMT = "%Y-%m-%d"
_LMS_RESPONSE_FMT = "%d-%m-%Y %H:%M:%S"

_INPUT_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y",
)


def _coerce(value: DateLike) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1]
        for fmt in _INPUT_FORMATS:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
        raise ValueError(f"unrecognized date/datetime value: {value!r}")
    raise TypeError(f"expected str, date or datetime, got {type(value)!r}")


def validate_date_order(
    from_date: DateLike, to_date: DateLike, from_name: str = "from_date", to_name: str = "to_date"
) -> None:
    # Compare whole days: every caller treats to_date as inclusive of its full day.
    if _coerce(from_date).date() > _coerce(to_date).date():
        raise ValueError(f"{from_name} ({from_date}) must not be after {to_name} ({to_date})")


def to_lms_datetime(value: DateLike) -> str:
    """Format for /v1/transactions/list and /v1/transaction-summary/list."""
    return _coerce(value).strftime(_LMS_DATETIME_FMT)


def to_lms_date(value: DateLike) -> str:
    """Format for /v1/transactions/credit-debit only. Not interchangeable with to_lms_datetime."""
    return _coerce(value).strftime(_LMS_DATE_FMT)


def from_lms(value: str) -> datetime:
    """Parse an LMS response timestamp, e.g. "18-09-2026 19:41:21"."""
    return datetime.strptime(value.strip(), _LMS_RESPONSE_FMT)
