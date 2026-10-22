# lms-mcp — TransBnk LMS MCP server (FastMCP, HTTP transport).
#
# No deployment infra is baked into this image. LMS_MCP_OAUTH_BASE_URL (which
# domain this instance answers as - used to build the OAuth redirect_uri and
# /login, /callback, /static routes) must be supplied at `docker run`/deploy
# time via --env-file or -e; there is no default, and the server refuses to
# start without it. LMS_MCP_ALLOWED_REDIRECT_URIS (optional, comma-separated)
# overrides which OAuth client redirect URIs may register - default is Claude's
# own connector callbacks; loopback http redirects are always accepted.
#
# OAuth/per-user login state is stored in Redis so it survives a pod restart and
# works across more than one replica - without it, that state lives in-process
# only (see oauth.py). REDIS_HOST/PORT/DB/PASSWORD are NOT baked
# into this image at all - they're deploy-time config, not build-time config, and
# REDIS_PASSWORD in particular is a secret that must never end up in an image
# layer or git history. Supply them via a .env file (gitignored - see .env.example)
# mounted or written at deploy time, which server.py loads automatically via
# python-dotenv, or via `docker run -e REDIS_HOST=... -e REDIS_PASSWORD=...`.
#
# Build:
#   docker build -t lms-mcp .
#
# Run:
#   docker run --rm -p 8080:8080 --env-file .env lms-mcp
#
# Health: curl http://localhost:8080/mcp. A bare GET correctly returns 400
# (streamable-http MCP requires an existing session) - the healthcheck below
# checks for a reachable, responding server, not a 2xx status.

FROM python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LMS_MCP_HOST=0.0.0.0 \
    PORT=8080

# build-essential for native wheels; curl for HEALTHCHECK. Pins break when trixie-security supersedes them - bump then.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential=12.12 curl=8.14.1-2+deb13u7 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./
# Dependencies come from uv.lock (hash-checked), never re-resolved from pyproject ranges.
RUN pip install --no-cache-dir uv==0.11.31 \
 && uv export --locked --no-dev --no-emit-project -o requirements.txt \
 && pip install --no-cache-dir -r requirements.txt

COPY src ./src
RUN pip install --no-cache-dir --no-deps .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -s -o /dev/null http://localhost:${PORT}/mcp || exit 1

CMD ["lms-mcp"]
