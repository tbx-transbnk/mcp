"""Shared Redis connection, built from discrete env vars rather than a URL string -
REDIS_PASSWORD can contain '@', easy to get subtly wrong when percent-encoded into a
URL. REDIS_HOST unset means "no Redis configured"; callers fall back on their own."""

from __future__ import annotations

import os


def _config() -> dict | None:
    host = os.environ.get("REDIS_HOST")
    if not host:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("REDIS_PORT", "6379")),
        "password": os.environ.get("REDIS_PASSWORD") or None,
        "db": int(os.environ.get("REDIS_DB", "0")),
        "decode_responses": True,
    }


def async_redis_client():
    config = _config()
    if config is None:
        return None
    import redis.asyncio as redis

    return redis.Redis(**config)
