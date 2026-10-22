# lms-mcp

FastMCP server for TransBnk LMS, run as a hosted, OAuth-protected MCP connector.
Each MCP client signs in through TrustHub's own login page (OAuth 2.1 + PKCE);
lms-mcp never sees a password and stores no local credentials.

## Run

```bash
docker build -t lms-mcp .
docker run --rm -p 8080:8080 --env-file .env lms-mcp
```

Configuration lives in `.env` (see `.env.example`). The server refuses to start
without `LMS_MCP_OAUTH_BASE_URL`.

| Var | Default | Meaning |
|---|---|---|
| `LMS_MCP_OAUTH_BASE_URL` | — (required) | Public base URL this instance answers as |
| `MASTER_BASE_URL` / `LMS_BASE_URL` | — (required) | TransBnk master/LMS API hosts |
| `TRUSTHUB_OAUTH_CLIENT_ID` / `_SECRET`, `TRUSTHUB_LOGIN_URL` | — | TrustHub OAuth client config |
| `REDIS_HOST` / `_PORT` / `_DB` / `_PASSWORD` | — | OAuth state store (in-process if unset); `_PASSWORD` required when `_HOST` is set |
| `LMS_MCP_HOST` | `0.0.0.0` | Bind address |
| `PORT` / `LMS_MCP_PORT` | `8080` | Listen port |
| `LMS_MCP_ALLOWED_REDIRECT_URIS` | Claude's callbacks | Comma-separated OAuth client redirect URIs accepted at registration (loopback is always allowed) |

## Connect

Add `https://<LMS_MCP_OAUTH_BASE_URL>/mcp` as a custom connector in your MCP
client (see SETUP.md). The client opens TrustHub sign-in on first use.

## Install (for development)

```bash
uv venv
uv pip install -e .
```

## Tests

```bash
uv run --extra dev pytest
```
