from __future__ import annotations

import pytest

from src.tools.accounts import get_balances, list_accounts
from src.tools.dashboard import dashboard_stats
from src.tools.transactions import credit_debit_summary, list_transactions, transaction_summary


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class FakeScope:
    def __init__(self, handle, entity="TransBnk", program="General"):
        self.handle = handle
        self.entity = entity
        self.program = program


class FakeSession:
    """Stands in for src.session.Session; no network, no import of the real thing."""

    def __init__(self, scopes, get_handler=None, post_handler=None):
        self.scopes = scopes
        self._get_handler = get_handler
        self._post_handler = post_handler
        self.get_calls = []
        self.post_calls = []

    def pick(self, handle):
        if handle is None:
            if len(self.scopes) == 1:
                return list(self.scopes)
            raise ValueError("several scopes; ask which one")
        if handle.lower() == "all":
            return list(self.scopes)
        matches = [s for s in self.scopes if s.handle == handle]
        if len(matches) == 1:
            return matches
        matches = [s for s in self.scopes if s.program.lower() == handle.lower()]
        valid = ", ".join(s.handle for s in self.scopes)
        if len(matches) == 1:
            return matches
        if not matches:
            raise ValueError(f"unknown scope {handle!r}; valid handles: {valid}")
        raise ValueError(f"ambiguous scope {handle!r}; valid handles: {valid}")

    def fan_out(self, fn, handle=None):
        rows, scopes_ok, scopes_failed = [], [], []
        for s in self.scopes:
            try:
                result = fn(s)
            except Exception as exc:
                scopes_failed.append({"scope": s.handle, "error": str(exc)})
                continue
            scopes_ok.append(s.handle)
            if isinstance(result, list):
                rows.extend(result)
            else:
                rows.append(result)
        return {"rows": rows, "scopes_ok": scopes_ok, "scopes_failed": scopes_failed}

    def get(self, path, scope, **params):
        self.get_calls.append((path, scope, params))
        return self._get_handler(path, scope, **params)

    def post(self, path, scope, body=None, **params):
        self.post_calls.append((path, scope, body, params))
        return self._post_handler(path, scope, body=body, **params)


ACCOUNTS_PAGE = {
    "content": [
        {
            "accountNumber": "111",
            "bankCode": "HDFC",
            "balanceAmount": "1000.50",
            "availableBalance": "1000.50",
            "balanceFetchedAt": "18-09-2026 10:00:00",
            "isLatestBalanceFetched": True,
        },
        {
            "accountNumber": "222",
            "bankCode": "ICICI",
            "balanceAmount": "500.00",
            "availableBalance": "500.00",
            "balanceFetchedAt": "01-01-2020 00:00:00",
            "isLatestBalanceFetched": False,
        },
        {
            "accountNumber": "333",
            "bankCode": "SBI",
            "balanceAmount": "9999.00",
            "availableBalance": "9999.00",
            "balanceFetchedAt": "01-01-2020 00:00:00",
            "isLatestBalanceFetched": False,
        },
    ],
    "totalElements": 3,
    "totalPages": 1,
    "last": True,
}


def _single_scope_session():
    return FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(ACCOUNTS_PAGE),
    )


def test_get_balances_and_list_accounts_agree_on_count_and_numbers():
    session_a = _single_scope_session()
    session_b = _single_scope_session()
    accounts = list_accounts(session_a)
    balances = get_balances(session_b)
    assert len(accounts["rows"]) == len(balances["rows"]) == 3
    assert {r["accountNumber"] for r in accounts["rows"]} == {r["accountNumber"] for r in balances["rows"]}


def test_get_balances_coverage_sums_only_fetched_accounts():
    session = _single_scope_session()
    result = get_balances(session)
    assert result["total_balance"] == 1000.50
    stale = [r for r in result["rows"] if r["is_stale"]]
    assert len(stale) == 2
    assert result["coverage"] == "total across 1 of 3 accounts; 2 excluded (stale or no balance recorded)"


def test_get_balances_full_coverage_message():
    all_fetched = {**ACCOUNTS_PAGE, "content": [{**row, "isLatestBalanceFetched": True} for row in ACCOUNTS_PAGE["content"]]}
    session = FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(all_fetched),
    )
    result = get_balances(session)
    assert result["coverage"] == "total across all 3 accounts"


def test_list_accounts_bank_maps_to_bank_code():
    session = _single_scope_session()
    list_accounts(session, bank="HDFC")
    _, _, body, _ = session.post_calls[0]
    assert body["bankCode"] == ["HDFC"]
    assert "bankName" not in body


def test_list_transactions_bank_maps_to_bank_code():
    session = FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(
            {"content": [], "totalElements": 0, "totalPages": 0, "last": True}
        ),
    )
    list_transactions(session, bank="HDFC")
    _, _, body, _ = session.post_calls[0]
    assert body["bankCode"] == ["HDFC"]


def test_transaction_summary_bank_maps_to_bank_name():
    session = FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(
            {"content": [], "totalElements": 0, "totalPages": 0, "last": True}
        ),
    )
    transaction_summary(session, bank="HDFC")
    _, _, body, _ = session.post_calls[0]
    assert body["bankName"] == ["HDFC"]
    assert "bankCode" not in body


def test_transaction_summary_strips_nested_transactions():
    summary_row = {
        "bankCode": "HDFC",
        "accountNumber": "111",
        "noOfDebits": 2,
        "noOfCredits": 1,
        "transactions": [{"transactionId": "t1"}, {"transactionId": "t2"}],
    }
    session = FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(
            {"content": [summary_row], "totalElements": 1, "totalPages": 1, "last": True}
        ),
    )
    result = transaction_summary(session)
    assert "transactions" not in result["rows"][0]
    assert result["rows"][0]["noOfDebits"] == 2


def test_transaction_summary_to_date_truncated_to_midnight():
    session = FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(
            {"content": [], "totalElements": 0, "totalPages": 0, "last": True}
        ),
    )
    transaction_summary(session, to_date="2026-09-21T18:30:00")
    _, _, body, _ = session.post_calls[0]
    assert body["transactionToDate"] == "2026-09-21T00:00:00.000Z"


def test_credit_debit_summary_end_date_plus_one_day_in_yyyy_mm_dd():
    session = FakeSession(
        [FakeScope("transbnk-general")],
        get_handler=lambda path, scope, **params: FakeResponse(
            [{"date": "2026-09-01", "totalCredit": 100, "totalDebit": 50}]
        ),
    )
    credit_debit_summary(session, start_date="2026-09-01", end_date="2026-09-21")
    path, scope, params = session.get_calls[0]
    assert params["startDate"] == "2026-09-01"
    assert params["endDate"] == "2026-09-22"


def test_credit_debit_summary_no_accounts_exception_becomes_empty_result():
    def get_handler(path, scope, **params):
        raise RuntimeError("upstream rejected this request: No accounts found for the given entityId and programId.")

    session = FakeSession([FakeScope("transbnk-general")], get_handler=get_handler)
    result = credit_debit_summary(session)
    assert result["rows"] == []
    assert result["scopes_ok"] == ["transbnk-general"]
    assert result["scopes_failed"] == []
    assert "no accounts found" in result["note"].lower()


def test_credit_debit_summary_all_zero_null_date_row_becomes_empty_list():
    session = FakeSession(
        [FakeScope("transbnk-general")],
        get_handler=lambda path, scope, **params: FakeResponse(
            [{"date": None, "totalCredit": 0, "totalDebit": 0}]
        ),
    )
    result = credit_debit_summary(session)
    assert result["rows"] == []
    assert "no transactions in this range" in result["note"]


def test_credit_debit_summary_real_upstream_failure_is_not_swallowed():
    def get_handler(path, scope, **params):
        raise RuntimeError("upstream rejected this request: something else broke")

    session = FakeSession([FakeScope("transbnk-general")], get_handler=get_handler)
    # A single scope has nothing to partially aggregate, so the failure propagates rather
    # than being reported as an empty result the model would read as "no data".
    with pytest.raises(RuntimeError, match="something else broke"):
        credit_debit_summary(session)


def test_fan_out_partial_failure_surfaces_in_dashboard_stats():
    def get_handler(path, scope, **params):
        if scope.handle == "b":
            raise RuntimeError("token expired")
        return FakeResponse({"totalAccount": 15, "totalBalance": "23,94,523.74"})

    session = FakeSession([FakeScope("a"), FakeScope("b")], get_handler=get_handler)
    result = dashboard_stats(session, scope="all")
    assert result["scopes_ok"] == ["a"]
    assert result["scopes_failed"] == [{"scope": "b", "error": "token expired"}]
    assert result["total_accounts"] == 15
    assert "1 scope(s) failed" in result["coverage"]


def test_transaction_type_must_be_valid_enum():
    session = FakeSession(
        [FakeScope("transbnk-general")],
        post_handler=lambda path, scope, body=None, **params: FakeResponse(
            {"content": [], "totalElements": 0, "totalPages": 0, "last": True}
        ),
    )
    with pytest.raises(ValueError):
        list_transactions(session, transaction_type="credits")


@pytest.mark.parametrize("call", [
    lambda s: list_transactions(s, from_date="2026-09-22", to_date="2026-09-21"),
    lambda s: transaction_summary(s, from_date="2026-09-22", to_date="2026-09-21"),
    lambda s: credit_debit_summary(s, start_date="2026-09-22", end_date="2026-09-21"),
])
def test_inverted_date_range_rejected_before_upstream_call(call):
    session = FakeSession([FakeScope("transbnk-general")])
    with pytest.raises(ValueError, match="must not be after"):
        call(session)
    assert session.post_calls == [] and session.get_calls == []
