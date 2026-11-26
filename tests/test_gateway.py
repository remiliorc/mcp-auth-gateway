import gzip
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_auth_gateway import Config, RateLimiter, TokenValidator, create_app

SECRET = "x" * 40
ISS, AUD = "https://idp.example.test/", "https://gw.example.test/mcp"
seen_headers: list[dict] = []


async def upstream(request: Request):
    seen_headers.append(dict(request.headers))
    if request.method == "GET":
        async def events():
            for i in range(3):
                yield f"event: message\ndata: {{\"n\": {i}}}\n\n".encode()
        return StreamingResponse(events(), media_type="text/event-stream")
    if request.method == "DELETE":
        return Response(status_code=200)
    body = await request.json()
    payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                          "result": {"ok": True}}).encode()
    if "gzip" in request.headers.get("accept-encoding", ""):
        return Response(gzip.compress(payload), media_type="application/json",
                        headers={"content-encoding": "gzip", "mcp-session-id": "abc"})
    return Response(payload, media_type="application/json",
                    headers={"mcp-session-id": "abc"})

UPSTREAM = Starlette(routes=[Route("/mcp", upstream, methods=["GET", "POST", "DELETE"])])


def cfg(tmp_path, **kw):
    base = dict(upstream_url="http://upstream/mcp", resource_url=AUD, issuer=ISS,
                audience=AUD, hs256_secret=SECRET,
                tool_scopes={"get_instrument": "mcp:read", "calibration_due": "mcp:maint"},
                tool_scope_fallback=None, audit_log=str(tmp_path / "audit.jsonl"))
    base.update(kw)
    return Config(**base)


def token(scope="mcp:read", sub="alice", aud=AUD, exp=300, key=SECRET, alg="HS256", **extra):
    now = int(time.time())
    claims = {"iss": ISS, "aud": aud, "sub": sub, "iat": now, "exp": now + exp,
              "scope": scope, **extra}
    return jwt.encode(claims, key, algorithm=alg)


def client(c, **kw):
    app = create_app(c, transport=httpx.ASGITransport(app=UPSTREAM), **kw)
    return TestClient(app)


def call(tool, id=1):
    return {"jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": {"tag": "TT-1"}}}


def test_metadata_document(tmp_path):
    r = client(cfg(tmp_path)).get("/.well-known/oauth-protected-resource/mcp")
    d = r.json()
    assert d["resource"] == AUD and d["authorization_servers"] == [ISS]
    assert {"mcp:read", "mcp:maint"} <= set(d["scopes_supported"])


def test_missing_token_gives_401_with_resource_metadata(tmp_path):
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"))
    assert r.status_code == 401
    assert ('resource_metadata="https://gw.example.test/.well-known/'
            'oauth-protected-resource/mcp"') in r.headers["www-authenticate"]


@pytest.mark.parametrize("tok,reason", [
    (lambda: token(exp=-120), "expired"),
    (lambda: token(aud="https://other/mcp"), "not issued"),
    (lambda: token(key="y" * 40), "invalid"),
    (lambda: "not.a.jwt", "malformed"),
])
def test_bad_tokens_rejected(tmp_path, tok, reason):
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                   headers={"Authorization": f"Bearer {tok()}"})
    assert r.status_code == 401 and reason in r.json()["error_description"]


def test_alg_none_rejected(tmp_path):
    t = jwt.encode({"iss": ISS, "aud": AUD, "sub": "a", "iat": 1, "exp": 2**31},
                   None, algorithm="none")
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                   headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 401


def test_allowed_call_is_proxied_without_token_passthrough(tmp_path):
    seen_headers.clear()
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                   headers={"Authorization": f"Bearer {token()}"})
    assert r.status_code == 200 and r.json()["result"]["ok"]
    assert r.headers["mcp-session-id"] == "abc"
    h = seen_headers[-1]
    assert "authorization" not in h and h["x-authenticated-subject"] == "alice"


def test_scope_enforced_per_tool_and_in_batches(tmp_path):
    c = client(cfg(tmp_path))
    auth = {"Authorization": f"Bearer {token('mcp:read')}"}
    r = c.post("/mcp", json=call("calibration_due"), headers=auth)
    assert r.status_code == 403 and 'scope="mcp:maint"' in r.headers["www-authenticate"]
    r = c.post("/mcp", json=[call("get_instrument", 1), call("calibration_due", 2)],
               headers=auth)
    assert r.status_code == 403
    ok = {"Authorization": f"Bearer {token('mcp:read mcp:maint')}"}
    assert c.post("/mcp", json=call("calibration_due"), headers=ok).status_code == 200


def test_unlisted_tool_blocked_when_no_fallback(tmp_path):
    r = client(cfg(tmp_path)).post("/mcp", json=call("delete_everything"),
                                   headers={"Authorization": f"Bearer {token('mcp:read mcp:maint')}"})
    assert r.status_code == 403 and "not exposed" in r.json()["error_description"]


def test_non_tool_methods_need_default_scope(tmp_path):
    c = client(cfg(tmp_path))
    init = {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}
    assert c.post("/mcp", json=init, headers={
        "Authorization": f"Bearer {token('other')}"}).status_code == 403
    assert c.post("/mcp", json=init, headers={
        "Authorization": f"Bearer {token('mcp:read')}"}).status_code == 200


def test_rate_limit_per_subject(tmp_path):
    t = [0.0]
    lim = RateLimiter(2, clock=lambda: t[0])
    c = client(cfg(tmp_path), limiter=lim)
    a = {"Authorization": f"Bearer {token(sub='a')}"}
    b = {"Authorization": f"Bearer {token(sub='b')}"}
    codes = [c.post("/mcp", json=call("get_instrument"), headers=a).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert c.post("/mcp", json=call("get_instrument"), headers=b).status_code == 200
    t[0] += 30  # refill one token
    assert c.post("/mcp", json=call("get_instrument"), headers=a).status_code == 200


def test_audit_log_has_decisions_but_no_arguments(tmp_path):
    c = client(cfg(tmp_path))
    c.post("/mcp", json=call("get_instrument"), headers={"Authorization": f"Bearer {token()}"})
    c.post("/mcp", json=call("calibration_due"), headers={"Authorization": f"Bearer {token()}"})
    lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [l["decision"] for l in lines] == ["allow", "deny"]
    assert lines[0]["sub"] == "alice" and lines[1]["status"] == 403
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "TT-1" not in raw and "eyJ" not in raw


def test_rs256_with_key_resolver(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c = cfg(tmp_path, hs256_secret=None, jwks_url="https://idp.example.test/jwks")
    v = TokenValidator(c, key_resolver=lambda tok: key.public_key())
    cl = client(c, validator=v)
    good = token(key=key, alg="RS256")
    assert cl.post("/mcp", json=call("get_instrument"),
                   headers={"Authorization": f"Bearer {good}"}).status_code == 200
    hs = token()  # HS256 token must not be accepted by an RS256 gateway
    assert cl.post("/mcp", json=call("get_instrument"),
                   headers={"Authorization": f"Bearer {hs}"}).status_code == 401


def test_config_guards(tmp_path):
    with pytest.raises(ValueError):
        cfg(tmp_path, hs256_secret="short")
    with pytest.raises(ValueError):
        cfg(tmp_path, jwks_url="https://x")  # both configured
    with pytest.raises(ValueError):
        cfg(tmp_path, hs256_secret=None, jwks_url="https://x", algorithms=["none"])


def test_upstream_down_gives_502(tmp_path):
    class Down(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise httpx.ConnectError("refused")
    app = create_app(cfg(tmp_path), transport=Down())
    r = TestClient(app).post("/mcp", json=call("get_instrument"),
                             headers={"Authorization": f"Bearer {token()}"})
    assert r.status_code == 502


def auth(scope="mcp:read", **kw):
    return {"Authorization": f"Bearer {token(scope, **kw)}"}


def test_client_cannot_spoof_identity_headers(tmp_path):
    seen_headers.clear()
    h = {**auth(), "x-authenticated-subject": "root", "X-Authenticated-Client": "admin"}
    client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"), headers=h)
    got = {k.lower(): v for k, v in seen_headers[-1].items()}
    assert got["x-authenticated-subject"] == "alice"
    assert "x-authenticated-client" not in got


def test_gzip_upstream_response_is_relayed_intact(tmp_path):
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                   headers={**auth(), "accept-encoding": "gzip"})
    assert r.status_code == 200 and r.json()["result"]["ok"]


@pytest.mark.parametrize("payload", [
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": 5}},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["x"]},
    {"jsonrpc": "2.0", "id": 1, "method": 7},
    [1, 2],
])
def test_malformed_rpc_gives_400(tmp_path, payload):
    r = client(cfg(tmp_path)).post("/mcp", json=payload, headers=auth())
    assert r.status_code == 400


def test_unicode_and_quotes_never_break_the_header(tmp_path):
    c = client(cfg(tmp_path))
    for name in ['x" , scope="admin', "café✓"]:
        r = c.post("/mcp", json=call(name), headers=auth())
        assert r.status_code == 403
        assert 'scope="admin' not in r.headers["www-authenticate"]


def test_body_limit_checked_after_auth(tmp_path):
    c = client(cfg(tmp_path))
    big = b'{"jsonrpc":"2.0","id":1,"method":"ping","pad":"' + b"a" * 1_100_000 + b'"}'
    assert c.post("/mcp", content=big).status_code == 401          # no token: body unread
    assert c.post("/mcp", content=big, headers=auth()).status_code == 413


def test_sse_get_is_streamed_and_delete_proxied(tmp_path):
    c = client(cfg(tmp_path))
    with c.stream("GET", "/mcp", headers=auth()) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        body = b"".join(r.iter_bytes())
    assert body.count(b"event: message") == 3
    assert c.delete("/mcp", headers=auth()).status_code == 200
    assert c.get("/mcp").status_code == 401


def test_wrong_token_type_rejected(tmp_path):
    t = jwt.encode({"iss": ISS, "aud": AUD, "sub": "a", "iat": int(time.time()),
                    "exp": int(time.time()) + 60, "scope": "mcp:read"},
                   SECRET, algorithm="HS256", headers={"typ": "id+jwt"})
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                   headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 401


def test_jwks_outage_gives_503(tmp_path):
    c = cfg(tmp_path, hs256_secret=None, jwks_url="https://idp.example.test/jwks")
    def down(tok):
        raise jwt.PyJWKClientConnectionError("Fail to fetch data from the url")
    cl = client(c, validator=TokenValidator(c, key_resolver=down))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = cl.post("/mcp", json=call("get_instrument"),
                headers={"Authorization": f"Bearer {token(key=key, alg='RS256')}"})
    assert r.status_code == 503


@pytest.mark.parametrize("exc", [jwt.PyJWKClientError("The JWKS endpoint did not contain any signing keys"),
                                 ValueError("html instead of json")])
def test_bad_jwks_document_gives_503(tmp_path, exc):
    c = cfg(tmp_path, hs256_secret=None, jwks_url="https://idp.example.test/jwks")
    def bad(tok):
        raise exc
    cl = client(c, validator=TokenValidator(c, key_resolver=bad))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    r = cl.post("/mcp", json=call("get_instrument"),
                headers={"Authorization": f"Bearer {token(key=key, alg='RS256')}"})
    assert r.status_code == 503


def test_deeply_nested_body_gives_400(tmp_path):
    body = b"[" * 100_000 + b"]" * 100_000
    r = client(cfg(tmp_path)).post("/mcp", content=body, headers=auth())
    assert r.status_code in (400, 413)


def test_underscore_identity_header_is_stripped(tmp_path):
    seen_headers.clear()
    client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                               headers={**auth(), "x_authenticated_subject": "root"})
    assert all("root" not in v for v in seen_headers[-1].values())


@pytest.mark.parametrize("claims", [{"client_id": {"a": 1}}, {"client_id": 5},
                                    {"sub": "alice\r\nX-Evil: 1"}, {"sub": ""}])
def test_malformed_identity_claims_rejected(tmp_path, claims):
    now = int(time.time())
    base = {"iss": ISS, "aud": AUD, "sub": "alice", "iat": now, "exp": now + 60,
            "scope": "mcp:read"}
    base.update(claims)
    t = jwt.encode(base, SECRET, algorithm="HS256")
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                   headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 401


def test_rate_limited_response_has_retry_after(tmp_path):
    lim = RateLimiter(1, clock=lambda: 0.0)
    c = client(cfg(tmp_path, rate_per_minute=1), limiter=lim)
    c.post("/mcp", json=call("get_instrument"), headers=auth())
    r = c.post("/mcp", json=call("get_instrument"), headers=auth())
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


def test_missing_token_challenge_has_no_error_code(tmp_path):
    r = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"))
    challenge = r.headers["www-authenticate"]
    assert r.status_code == 401 and "error=" not in challenge
    bad = client(cfg(tmp_path)).post("/mcp", json=call("get_instrument"),
                                      headers={"Authorization": "Bearer not-a-jwt"})
    assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]


def test_unlisted_tools_are_blocked_by_default():
    c = Config(upstream_url="http://u/mcp", resource_url=AUD, issuer=ISS,
               audience=AUD, hs256_secret=SECRET)
    assert c.tool_scope_fallback is None


def test_delete_body_is_not_forwarded(tmp_path):
    seen_bodies: list[bytes] = []

    async def up(request: Request):
        seen_bodies.append(await request.body())
        return Response(status_code=200)
    app = create_app(cfg(tmp_path), transport=httpx.ASGITransport(
        app=Starlette(routes=[Route("/mcp", up, methods=["GET", "POST", "DELETE"])])))
    r = TestClient(app).request("DELETE", "/mcp", content=b"smuggled",
                                headers={"Authorization": f"Bearer {token()}"})
    assert r.status_code == 200 and seen_bodies == [b""]
