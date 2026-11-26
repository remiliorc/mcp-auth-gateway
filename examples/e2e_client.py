"""End-to-end check with the official MCP Python SDK client, through the gateway.

Setup (three terminals, local demo only):
  1. any streamable-HTTP MCP server on 127.0.0.1:8000/mcp, for example:
       python -m instrument_index_mcp.server --http --port 8000
  2. the gateway in HS256 demo mode, with examples/e2e.yaml:
       GATEWAY_HS256_SECRET=<32+ chars> python -m mcp_auth_gateway --config examples/e2e.yaml --port 8080
  3. this script, with the same secret:
       GATEWAY_HS256_SECRET=<same> python examples/e2e_client.py --allowed index_summary --denied calibration_due

It mints a short-lived demo token with scope ``mcp:read``, lists the tools,
calls one allowed tool and one tool that needs a scope the token lacks.
Exit code 0 means: allowed call succeeded and the denied call was refused.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

import jwt
from mcp.client.session import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client


def mint(secret: str, issuer: str, audience: str, scope: str) -> str:
    now = int(time.time())
    return jwt.encode({"iss": issuer, "aud": audience, "sub": "demo-user",
                       "iat": now, "exp": now + 300, "scope": scope},
                      secret, algorithm="HS256")


def failed(result) -> bool:
    # field name differs between MCP SDK 2.x (is_error) and 1.x (isError)
    return bool(getattr(result, "is_error", getattr(result, "isError", False)))


async def main(a: argparse.Namespace) -> int:
    token = mint(os.environ["GATEWAY_HS256_SECRET"], a.issuer, a.url, a.scope)
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    async with streamable_http_client(a.url, http_client=http) as streams:
        async with ClientSession(streams[0], streams[1]) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            print(f"tools listed: {len(tools)}")
            ok = await s.call_tool(a.allowed, {})
            print(f"{a.allowed}: {'error' if failed(ok) else 'ok'}")
            try:
                denied = await s.call_tool(a.denied, {})
                refused = failed(denied)
                print(f"{a.denied}: {'refused' if refused else 'ALLOWED'}")
            except Exception as e:  # the gateway answers 403
                refused = True
                print(f"{a.denied}: refused ({type(e).__name__})")
            return 0 if (not failed(ok) and refused) else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8080/mcp")
    p.add_argument("--issuer", default="https://idp.example.test/")
    p.add_argument("--scope", default="mcp:read")
    p.add_argument("--allowed", required=True)
    p.add_argument("--denied", required=True)
    sys.exit(asyncio.run(main(p.parse_args())))
