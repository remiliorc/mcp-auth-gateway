"""OAuth 2.1 resource-server gateway in front of a streamable-HTTP MCP server.

The gateway follows the MCP authorization model: the MCP server acts as a
protected resource, and tokens come from an external authorization server.

- Publishes Protected Resource Metadata (RFC 9728) so clients can discover the
  authorization server.
- Answers 401 with a ``WWW-Authenticate`` header that points to that metadata.
- Validates JWT access tokens: signature, issuer, audience, exp.
- Enforces per-tool scopes by reading the JSON-RPC body (single or batch).
- Applies a rate limit per subject.
- Writes a JSONL audit log with who called which method or tool and the
  decision. Arguments are never logged.
- Never forwards the client's token upstream (no token passthrough). The
  upstream receives the verified identity in ``X-Authenticated-*`` headers.
"""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from .auth import AuthError, RateLimiter, TokenValidator, authorize
from .config import Config

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailers", "transfer-encoding", "upgrade", "host",
              "content-length", "authorization", "cookie"}
MAX_BODY = 1_000_000


def _rpc_calls(body: bytes) -> list[tuple[str | None, str | None]]:
    if not body:
        return [(None, None)]
    try:
        msg = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise AuthError(400, "invalid_request", "body is not valid JSON")
    items = msg if isinstance(msg, list) else [msg]
    calls = []
    for m in items:
        if not isinstance(m, dict):
            raise AuthError(400, "invalid_request", "invalid JSON-RPC message")
        method = m.get("method")
        if method is not None and not isinstance(method, str):
            raise AuthError(400, "invalid_request", "method must be a string")
        tool = None
        if method == "tools/call":
            params = m.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                raise AuthError(400, "invalid_request", "tools/call needs params.name (string)")
            tool = params["name"]
        calls.append((method, tool))
    return calls or [(None, None)]


def _header_safe(text: str) -> str:
    """Make a value safe inside a quoted WWW-Authenticate parameter."""
    return "".join(c if 0x20 <= ord(c) < 0x7F and c not in '"\\' else "?" for c in text)[:200]


async def _read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                raise AuthError(413, "invalid_request", "request body too large")
        except ValueError:
            raise AuthError(400, "invalid_request", "invalid content-length")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise AuthError(413, "invalid_request", "request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(cfg: Config, validator: TokenValidator | None = None,
               transport: httpx.AsyncBaseTransport | None = None,
               limiter: RateLimiter | None = None) -> Starlette:
    validator = validator or TokenValidator(cfg)
    limiter = limiter or RateLimiter(cfg.rate_per_minute)
    client = httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(60, read=None))
    # RFC 9728 section 3.1: insert the well-known segment before the resource path
    parts = httpx.URL(cfg.resource_url)
    resource_path = parts.path.rstrip("/")
    metadata_path = "/.well-known/oauth-protected-resource" + resource_path
    metadata_url = str(parts.copy_with(path=metadata_path, query=None, fragment=None))

    def audit(**event) -> None:
        if cfg.audit_log:
            event["ts"] = round(time.time(), 3)
            with Path(cfg.audit_log).open("a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

    def deny(e: AuthError) -> Response:
        params = ([f'error="{e.error}"',
                   f'error_description="{_header_safe(e.description)}"']
                  if e.error else [])
        if e.status == 401:
            params.insert(0, f'resource_metadata="{metadata_url}"')
        if e.scope:
            params.append(f'scope="{_header_safe(e.scope)}"')
        headers = {"WWW-Authenticate": "Bearer " + ", ".join(params)} \
            if e.status in (401, 403) else {}
        if e.status == 429:
            headers["Retry-After"] = str(max(1, round(60 / cfg.rate_per_minute)))
        return JSONResponse({"error": e.error or "unauthorized",
                             "error_description": e.description},
                            status_code=e.status, headers=headers)

    async def protected_resource(_: Request) -> Response:
        scopes = sorted({cfg.default_scope, *cfg.tool_scopes.values(),
                         *([cfg.tool_scope_fallback] if cfg.tool_scope_fallback else [])})
        return JSONResponse({
            "resource": cfg.resource_url,
            "authorization_servers": [cfg.issuer],
            "scopes_supported": scopes,
            "bearer_methods_supported": ["header"],
        })

    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def proxy(request: Request) -> Response:
        t0 = time.perf_counter()
        sub = None
        calls: list = []
        try:
            # authenticate from headers first: unauthenticated bodies are never read
            principal = await run_in_threadpool(
                validator.validate, request.headers.get("authorization"))
            sub = principal.subject
            if not limiter.allow(sub):
                raise AuthError(429, "rate_limited", "too many requests")
            # only POST carries JSON-RPC; GET (SSE) and DELETE bodies are never forwarded
            body = await _read_capped(request, MAX_BODY) if request.method == "POST" else b""
            calls = _rpc_calls(body) if request.method == "POST" else [(None, None)]
            authorize(cfg, principal, calls)
        except AuthError as e:
            audit(sub=sub, method=request.method, calls=calls, decision="deny",
                  status=e.status, reason=e.error)
            return deny(e)

        # drop hop-by-hop headers and any identity header the client tried to set
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP
                   and not k.lower().replace("_", "-").startswith("x-authenticated-")}
        headers["X-Authenticated-Subject"] = principal.subject
        if principal.client_id:
            headers["X-Authenticated-Client"] = principal.client_id
        upstream = client.build_request(request.method, cfg.upstream_url,
                                        params=request.query_params, headers=headers,
                                        content=body or None)
        try:
            resp = await client.send(upstream, stream=True)
        except httpx.HTTPError as e:
            audit(sub=sub, method=request.method, calls=calls, decision="allow",
                  status=502, reason=type(e).__name__)
            return JSONResponse({"error": "upstream_unavailable"}, status_code=502)
        audit(sub=sub, method=request.method, calls=calls, decision="allow",
              status=resp.status_code, latency_s=round(time.perf_counter() - t0, 4))
        # raw bytes are relayed untouched, so content-encoding must be kept
        out_headers = {k: v for k, v in resp.headers.items()
                       if k.lower() not in HOP_BY_HOP}
        return StreamingResponse(resp.aiter_raw(), status_code=resp.status_code,
                                 headers=out_headers, background=BackgroundTask(resp.aclose))

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await client.aclose()

    return Starlette(routes=[
        Route(metadata_path, protected_resource),
        Route("/.well-known/oauth-protected-resource", protected_resource),
        Route("/healthz", health),
        Route(resource_path or "/mcp", proxy, methods=["GET", "POST", "DELETE"]),
    ], lifespan=lifespan)
