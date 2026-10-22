import base64
import inspect
import json
import time
from datetime import datetime, timezone

import httpx
import pytest

from src.server import list_scopes
from src.session import ScopeRequired, Session, SessionError


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_token(exp: float) -> str:
    header = _b64({"alg": "HS512", "typ": "JWT"})
    payload = _b64({"sub": "user1", "exp": exp})
    return f"{header}.{payload}.signature"


ENTITIES = [
    {"entityId": "E1", "entityName": "TransBnk"},
    {"entityId": "E2", "entityName": "OtherBank"},
]
PROGRAMS = {
    "E1": [{"programId": 21, "programName": "General"}],
    "E2": [{"programId": 99, "programName": "General"}],
}


def two_scope_master_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/v1/users/entities"):
        return httpx.Response(200, json=ENTITIES)
    if request.url.path.endswith("/v1/users/programs"):
        entity_id = request.url.params["entityId"]
        return httpx.Response(200, json=PROGRAMS.get(entity_id, []))
    return httpx.Response(404, json={"message": "not found"})


def single_scope_master_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/v1/users/entities"):
        return httpx.Response(200, json=[{"entityId": "1b206ac1-xxxx", "entityName": "TransBnk"}])
    if request.url.path.endswith("/v1/users/programs"):
        return httpx.Response(200, json=[{"programId": 21, "programName": "General"}])
    return httpx.Response(404, json={"message": "not found"})


def zero_scope_master_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=[])


def make_session(exp: float | None = None, handler=two_scope_master_handler) -> Session:
    exp = exp if exp is not None else time.time() + 3600
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Session(token=make_token(exp), master_base_url="https://master.test", lms_base_url="https://lms.test", client=client)


def test_scope_table_built_from_master():
    session = make_session()
    handles = {s.handle for s in session.scopes}
    assert handles == {"transbnk-general", "otherbank-general"}
    scope = next(s for s in session.scopes if s.handle == "transbnk-general")
    assert (scope.entity, scope.program, scope._entity_id, scope._program_id) == ("TransBnk", "General", "E1", 21)


def test_single_scope_matches_plan_gate():
    session = make_session(handler=single_scope_master_handler)
    assert len(session.scopes) == 1
    assert (session.scopes[0].handle, session.scopes[0].entity, session.scopes[0].program) == (
        "transbnk-general",
        "TransBnk",
        "General",
    )


def test_zero_scopes_refuses_to_start():
    with pytest.raises(SessionError, match="zero entity/program scopes"):
        make_session(handler=zero_scope_master_handler)


def one_entity_unprovisioned_handler(request: httpx.Request) -> httpx.Response:
    """One of several linked entities has no programs assigned (master's real MSA009 shape)."""
    if request.url.path.endswith("/v1/users/entities"):
        return httpx.Response(200, json=ENTITIES)
    if request.url.path.endswith("/v1/users/programs"):
        entity_id = request.url.params["entityId"]
        if entity_id == "E2":
            return httpx.Response(400, json={"errorMessage": "No programs assigned to user", "errorCode": "MSA009"})
        return httpx.Response(200, json=PROGRAMS[entity_id])
    return httpx.Response(404, json={"message": "not found"})


def test_unprovisioned_entity_is_skipped_not_fatal():
    session = make_session(handler=one_entity_unprovisioned_handler)
    assert {s.handle for s in session.scopes} == {"transbnk-general"}


def one_entity_other_400_handler(request: httpx.Request) -> httpx.Response:
    """A 400 that is NOT MSA009 is a real failure and must still abort, not be skipped."""
    if request.url.path.endswith("/v1/users/entities"):
        return httpx.Response(200, json=ENTITIES)
    if request.url.path.endswith("/v1/users/programs"):
        entity_id = request.url.params["entityId"]
        if entity_id == "E2":
            return httpx.Response(400, json={"errorMessage": "entity is suspended", "errorCode": "MSA077"})
        return httpx.Response(200, json=PROGRAMS[entity_id])
    return httpx.Response(404, json={"message": "not found"})


def test_non_msa009_400_still_aborts_login():
    with pytest.raises(SessionError, match="entity is suspended"):
        make_session(handler=one_entity_other_400_handler)


def test_expired_token_refused_at_construction_names_expiry():
    past = time.time() - 10
    with pytest.raises(SessionError) as exc_info:
        make_session(exp=past)
    expected_iso = datetime.fromtimestamp(past, tz=timezone.utc).isoformat()
    assert expected_iso in str(exc_info.value)
    assert "expired" in str(exc_info.value)


def test_exp_checked_before_every_request(monkeypatch):
    # Beyond Session's proactive-refresh skew window, so construction itself doesn't
    # already see this as "near expiry" and try to refresh.
    exp = time.time() + 120
    session = make_session(exp=exp)
    monkeypatch.setattr(time, "time", lambda: exp + 100)
    with pytest.raises(SessionError, match="expired"):
        session.get("/v1/dashboard/stats", session.scopes[0])


def test_refresh_swaps_in_new_token(monkeypatch):
    exp = time.time() + 120
    new_exp = time.time() + 3600
    new_token = make_token(new_exp)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v1/auth/refresh"):
            calls.append(request)
            return httpx.Response(200, json={"accessToken": new_token, "expiresIn": 900})
        if request.url.path.endswith("/v1/dashboard/stats"):
            return httpx.Response(200, json={})
        return two_scope_master_handler(request)

    session = make_session(exp=exp, handler=handler)
    monkeypatch.setattr(time, "time", lambda: exp + 100)
    session.get("/v1/dashboard/stats", session.scopes[0])
    assert len(calls) == 1
    assert session.token == new_token


def test_refresh_failure_raises_expired(monkeypatch):
    exp = time.time() + 120
    session = make_session(exp=exp)
    monkeypatch.setattr(time, "time", lambda: exp + 100)
    with pytest.raises(SessionError, match="expired"):
        session.get("/v1/dashboard/stats", session.scopes[0])


def test_unrefreshable_session_sets_signed_out_flag_and_fires_hook(monkeypatch):
    exp = time.time() + 120
    client = httpx.Client(transport=httpx.MockTransport(two_scope_master_handler))
    calls = []
    session = Session(
        token=make_token(exp), master_base_url="https://master.test", lms_base_url="https://lms.test",
        client=client, on_signed_out=lambda: calls.append(1),
    )
    assert session.is_signed_out is False
    monkeypatch.setattr(time, "time", lambda: exp + 100)
    with pytest.raises(SessionError):
        session.get("/v1/dashboard/stats", session.scopes[0])
    assert session.is_signed_out is True
    assert calls == [1]


def test_concurrent_requests_only_refresh_once(monkeypatch):
    import threading
    import time as time_module

    exp = time.time() + 120
    new_token = make_token(time.time() + 3600)
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v1/auth/refresh"):
            calls.append(request)
            # Widen the window: without the lock, a second concurrent call would
            # overlap with this and also reach here before either sees the new token.
            time_module.sleep(0.05)
            return httpx.Response(200, json={"accessToken": new_token, "expiresIn": 900})
        if request.url.path.endswith("/v1/dashboard/stats"):
            return httpx.Response(200, json={})
        return two_scope_master_handler(request)

    session = make_session(exp=exp, handler=handler)
    monkeypatch.setattr(time, "time", lambda: exp + 100)

    results = []

    def call():
        try:
            session.get("/v1/dashboard/stats", session.scopes[0])
            results.append("ok")
        except Exception as exc:  # noqa: BLE001 - just recording for the assertion below
            results.append(exc)

    t1 = threading.Thread(target=call)
    t2 = threading.Thread(target=call)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert results == ["ok", "ok"]
    assert len(calls) == 1


def test_pick_none_with_several_scopes_asks_which_one():
    session = make_session()
    assert len(session.scopes) > 1
    with pytest.raises(ScopeRequired) as exc:
        session.pick(None)
    for scope in session.scopes:
        assert scope.handle in str(exc.value)
    assert "scope='all'" in str(exc.value)


def test_pick_all_returns_every_scope():
    session = make_session()
    assert session.pick("all") == session.scopes
    assert session.pick("ALL") == session.scopes


def test_pick_exact_handle():
    session = make_session()
    result = session.pick("transbnk-general")
    assert [s.handle for s in result] == ["transbnk-general"]


def test_pick_case_insensitive_program_name_when_unambiguous():
    session = make_session(handler=single_scope_master_handler)
    result = session.pick("gEnErAl")
    assert result[0].handle == "transbnk-general"


def test_pick_unknown_handle_raises_and_lists_valid_handles():
    session = make_session()
    with pytest.raises(SessionError) as exc_info:
        session.pick("does-not-exist")
    assert "transbnk-general" in str(exc_info.value)
    assert "otherbank-general" in str(exc_info.value)


def test_pick_unknown_does_not_fall_through_to_all_scopes():
    session = make_session()
    try:
        session.pick("does-not-exist")
        pytest.fail("expected SessionError")
    except SessionError:
        pass


def test_pick_ambiguous_program_name_raises():
    session = make_session()
    with pytest.raises(SessionError, match="ambiguous"):
        session.pick("General")


def test_fan_out_partial_failure_reports_failed_and_keeps_ok_rows():
    session = make_session()

    def fn(scope):
        if scope.handle == "transbnk-general":
            raise RuntimeError("boom")
        return [{"x": 1}]

    result = session.fan_out(fn, "all")
    assert result["scopes_ok"] == ["otherbank-general"]
    assert result["scopes_failed"] == [{"scope": "transbnk-general", "error": "boom"}]
    assert result["rows"] == [{"x": 1}]


def test_post_pins_program_id_header_and_view_type():
    session = make_session()
    captured = {}

    def lms_handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={"content": []})

    session._client = httpx.Client(transport=httpx.MockTransport(lms_handler))
    scope = session.scopes[0]
    session.post("/v1/accounts/list", scope, body={"bankCode": ["HDFC"]})

    req = captured["request"]
    assert req.headers["Program-Id"] == str(scope._program_id)
    body = json.loads(req.content)
    assert body["viewType"] == "PROGRAM"
    assert body["entityId"] == scope._entity_id
    assert body["programId"] == scope._program_id
    assert body["filterProgramId"] is None
    assert body["programName"] is None


def test_get_pins_program_id_header_and_view_type():
    session = make_session()
    captured = {}

    def lms_handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return httpx.Response(200, json={})

    session._client = httpx.Client(transport=httpx.MockTransport(lms_handler))
    scope = session.scopes[0]
    session.get("/v1/dashboard/stats", scope)

    req = captured["request"]
    assert req.headers["Program-Id"] == str(scope._program_id)
    assert req.url.params["viewType"] == "PROGRAM"
    assert req.url.params["entityId"] == scope._entity_id


@pytest.mark.parametrize(
    "status,body,match",
    [
        (401, {}, "token expired"),
        (403, {}, "token expired"),
        (400, {"message": "bad date range"}, "bad date range"),
        (503, {}, "LMS unavailable"),
    ],
)
def test_error_mapping(status, body, match):
    session = make_session()

    def lms_handler(request: httpx.Request) -> httpx.Response:
        if body:
            return httpx.Response(status, json=body)
        return httpx.Response(status, text="")

    session._client = httpx.Client(transport=httpx.MockTransport(lms_handler))
    with pytest.raises(SessionError, match=match):
        session.get("/v1/dashboard/stats", session.scopes[0])


def test_list_scopes_tool_signature_has_no_tenant_ids():
    params = inspect.signature(list_scopes).parameters
    assert "entityId" not in params
    assert "programId" not in params
