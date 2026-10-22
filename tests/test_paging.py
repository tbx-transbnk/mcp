from __future__ import annotations

from src.paging import build_page_meta, clamp_size, fan_out_pages


def test_clamp_size_upper_bound():
    assert clamp_size(1000) == 100


def test_clamp_size_lower_bound():
    assert clamp_size(0) == 1


def test_clamp_size_default():
    assert clamp_size(None) == 50


def test_clamp_size_passthrough():
    assert clamp_size(30) == 30


def test_build_page_meta_no_more_results():
    page_json = {"content": [1, 2], "totalElements": 2, "totalPages": 1, "last": True}
    meta = build_page_meta([page_json], page=0, size=50)
    assert meta["total_elements"] == 2
    assert meta["total_pages"] == 1
    assert meta["has_more"] is False
    assert "note" not in meta


def test_build_page_meta_has_more_via_last_flag():
    page_json = {"content": [1], "totalElements": 5, "totalPages": 5, "last": False}
    meta = build_page_meta([page_json], page=0, size=1)
    assert meta["has_more"] is True
    assert "more results available" in meta["note"]


def test_build_page_meta_has_more_without_last_flag():
    page_json = {"content": [1], "totalElements": 5, "totalPages": 5}
    meta = build_page_meta([page_json], page=0, size=1)
    assert meta["has_more"] is True


def test_build_page_meta_merges_across_scopes():
    a = {"content": [1], "totalElements": 1, "totalPages": 1, "last": True}
    b = {"content": [2, 3], "totalElements": 2, "totalPages": 1, "last": True}
    meta = build_page_meta([a, b], page=0, size=50)
    assert meta["total_elements"] == 3
    assert meta["has_more"] is False


def test_build_page_meta_empty():
    meta = build_page_meta([], page=0, size=50)
    assert meta["total_elements"] == 0
    assert meta["has_more"] is False


class _Scope:
    def __init__(self, handle):
        self.handle = handle
        self.program = handle


class _FakeSession:
    def __init__(self, scopes):
        self.scopes = scopes

    def pick(self, handle):
        if handle is None:
            if len(self.scopes) == 1:
                return list(self.scopes)
            raise ValueError("several scopes; ask which one")
        if handle.lower() == "all":
            return list(self.scopes)
        matches = [s for s in self.scopes if s.handle == handle]
        if not matches:
            raise ValueError(f"unknown scope {handle!r}")
        return matches

    def fan_out(self, fn, handle=None):
        rows, scopes_ok, scopes_failed = [], [], []
        for s in self.scopes:
            try:
                result = fn(s)
            except Exception as exc:
                scopes_failed.append({"scope": s.handle, "error": str(exc)})
                continue
            scopes_ok.append(s.handle)
            rows.extend(result)
        return {"rows": rows, "scopes_ok": scopes_ok, "scopes_failed": scopes_failed}


def test_fan_out_pages_single_named_scope():
    session = _FakeSession([_Scope("a"), _Scope("b")])
    rows, page_jsons, scopes_ok, scopes_failed = fan_out_pages(
        session, "a", lambda s: {"content": [f"{s.handle}-row"], "totalElements": 1, "totalPages": 1, "last": True}
    )
    assert rows == ["a-row"]
    assert scopes_ok == ["a"]
    assert scopes_failed == []
    assert len(page_jsons) == 1


def test_fan_out_pages_all_scopes_partial_failure():
    session = _FakeSession([_Scope("a"), _Scope("b")])

    def fetch(s):
        if s.handle == "b":
            raise RuntimeError("boom")
        return {"content": ["a-row"], "totalElements": 1, "totalPages": 1, "last": True}

    rows, page_jsons, scopes_ok, scopes_failed = fan_out_pages(session, "all", fetch)
    assert rows == ["a-row"]
    assert scopes_ok == ["a"]
    assert scopes_failed == [{"scope": "b", "error": "boom"}]
    assert len(page_jsons) == 1
