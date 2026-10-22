"""Page-size clamping, page metadata, and scoped-page fan-out. See MCP_BUILD_PLAN.md §1/§2.

Shared by every paged tool so clamping and the "more results available" note are
applied exactly once, and so multi-scope aggregates and single-scope reads go through
the same fan-out shape (rows, scopes_ok, scopes_failed).
"""

from __future__ import annotations

from typing import Any, Callable

MIN_SIZE = 1
MAX_SIZE = 100
DEFAULT_SIZE = 50


def clamp_size(size: int | None) -> int:
    if size is None:
        return DEFAULT_SIZE
    return max(MIN_SIZE, min(MAX_SIZE, size))


def build_page_meta(page_jsons: list[dict[str, Any]], page: int, size: int) -> dict[str, Any]:
    """Aggregate Spring Page<> metadata across one or more scope responses."""
    if not page_jsons:
        return {"page": page, "size": size, "total_elements": 0, "total_pages": 0, "has_more": False}
    total_elements = sum(pj.get("totalElements", len(pj.get("content", []))) for pj in page_jsons)
    total_pages = max(pj.get("totalPages", 1) for pj in page_jsons)
    has_more = any(
        (not pj["last"]) if "last" in pj else (page + 1 < pj.get("totalPages", 1)) for pj in page_jsons
    )
    meta: dict[str, Any] = {
        "page": page,
        "size": size,
        "total_elements": total_elements,
        "total_pages": total_pages,
        "has_more": has_more,
    }
    if has_more:
        meta["note"] = "more results available - request the next page"
    return meta


def fan_out_pages(
    session: Any,
    scope: str | None,
    fetch_page: Callable[[Any], dict[str, Any]],
) -> tuple[list[Any], list[dict[str, Any]], list[str], list[dict[str, str]]]:
    """Run fetch_page(scope) -> Page<> json for a named scope or every entitled scope.

    A named scope resolves to exactly one call (errors propagate - there is nothing to
    partially aggregate). scope=None fans out across every scope via session.fan_out,
    so a single failing scope never silently drops out of an aggregate total.
    """
    scopes = session.pick(scope)
    page_jsons: list[dict[str, Any]] = []
    if len(scopes) == 1:
        s = scopes[0]
        pj = fetch_page(s)
        page_jsons.append(pj)
        return list(pj.get("content", [])), page_jsons, [s.handle], []

    def _fn(s: Any) -> list[Any]:
        pj = fetch_page(s)
        page_jsons.append(pj)
        return list(pj.get("content", []))

    result = session.fan_out(_fn, scope)
    return result["rows"], page_jsons, result["scopes_ok"], result["scopes_failed"]
