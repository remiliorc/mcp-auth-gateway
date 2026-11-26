# mcp-auth-gateway

An OAuth 2.1 **resource-server gateway** that sits in front of any streamable-HTTP
MCP server. It lets you expose internal MCP tools to external AI clients without
adding auth code to every server.

```
MCP client ──Bearer JWT──▶ mcp-auth-gateway ──(verified identity, no token)──▶ MCP server
                               │
                               ├─ RFC 9728 metadata  →  points to your IdP
                               ├─ per-tool scopes     →  403 + WWW-Authenticate scope=
                               ├─ rate limit / subject
                               └─ JSONL audit log (no arguments, no tokens)
```

It follows the role split in the MCP authorization spec: the gateway is the
**protected resource**, and tokens come from your existing authorization server
(Keycloak, Auth0, Entra ID, Okta...). The gateway does not issue tokens.

## What it enforces

| Control | Behaviour |
|---|---|
| Discovery | RFC 9728 metadata at `/.well-known/oauth-protected-resource/<resource-path>` (path insertion), plus the root form, listing the authorization server and supported scopes |
| Authentication | JWT signature via JWKS (RS256/ES256), plus `iss`, `aud`, `exp`, `iat` and `sub` are required, with clock leeway. `alg: none`, algorithm confusion and non-access-token `typ` values are rejected. JWKS outages return `503`, not `401`. Key fetching runs off the event loop |
| Challenge | `401` with `WWW-Authenticate: Bearer resource_metadata="…"`, so clients can start the OAuth flow. No error code when no token was sent (RFC 6750 §3.1); `invalid_token` when one was sent and failed |
| Authorization | Reads the JSON-RPC body, including batches. Each `tools/call` needs the scope mapped to that tool. Tools with no mapping are blocked unless `tool_scope_fallback` names a scope (default: `null`, deny). Malformed messages get `400` |
| No token passthrough | The client's `Authorization` and `Cookie` headers are never forwarded. The upstream receives `X-Authenticated-Subject` and `X-Authenticated-Client`. Any `X-Authenticated-*` header sent by the client is stripped, so identity cannot be spoofed |
| Rate limiting | Token bucket per subject. Excess requests get `429` |
| Audit | One JSONL line per request: subject, JSON-RPC methods and tools, decision, status, latency. Tool arguments and tokens are never written |
| Streaming | Responses, including SSE and compressed bodies, are relayed as raw bytes without buffering. `Mcp-Session-Id` is preserved |
| Hardening | The body is read only after authentication, with a 1 MB cap (`Content-Length` is checked first), and only for `POST`: `GET` and `DELETE` bodies are never forwarded. Client-controlled text never reaches `WWW-Authenticate` unescaped |

## Run

```bash
pip install -e ".[dev]"
pytest -q
python -m mcp_auth_gateway --config examples/gateway.yaml --port 8080
```

Secrets never go in the YAML file. HS256 is for local demos only: set
`GATEWAY_HS256_SECRET` (at least 32 characters) in the environment. In
production, configure `jwks_url`.

## Tested end-to-end

Besides the 39 unit tests (using an in-process fake upstream), `examples/e2e_client.py`
(install with `pip install -e ".[e2e]"`) runs the official MCP Python SDK client through the gateway against a real
streamable-HTTP MCP server, for example
[instrument-index-mcp](https://github.com/remiliorc/instrument-index-mcp),
with `examples/e2e.yaml`:

```
tools listed: 8
index_summary: ok
calibration_due: refused (MCPError)
```

A token with the `mcp:read` scope can initialize, list tools and call
`index_summary`. `calibration_due`, which requires `mcp:maint`, is refused with
403. The audit log records the `GET` (SSE), `POST` and `DELETE` requests of the
session, each with its decision.

## Limitations (by design, or not yet done)

- `tools/list` is not filtered per user: clients see tools they may not be allowed to call.
- No token introspection (RFC 7662) for opaque tokens. Only JWT access tokens are supported.
- The rate limiter keeps its state in memory and runs per subject after authentication. With several replicas, use a shared store. Put a per-IP limit at the edge proxy as well.
- MCP sessions are not bound to the authenticated subject: the gateway forwards `Mcp-Session-Id` as is, so the upstream should tie sessions to `X-Authenticated-Subject` if that matters.
- Tokens with an unknown `kid` make the JWKS client refetch the key set. Use it behind an edge proxy with rate limiting.

## License

MIT
