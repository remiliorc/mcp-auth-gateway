"""Run:  python -m mcp_auth_gateway --config gateway.yaml --port 8080"""

import argparse

import uvicorn

from .app import create_app
from .config import Config


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    uvicorn.run(create_app(Config.from_file(a.config)), host=a.host, port=a.port)


if __name__ == "__main__":
    main()
