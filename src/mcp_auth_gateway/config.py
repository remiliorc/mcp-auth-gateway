"""Gateway configuration (YAML file or environment)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    upstream_url: str                       # e.g. http://127.0.0.1:8000/mcp
    resource_url: str                       # public URL of this gateway's /mcp
    issuer: str                             # OAuth authorization server (IdP)
    audience: str                           # expected `aud` claim
    jwks_url: str | None = None             # production: asymmetric keys
    hs256_secret: str | None = None         # demo/tests only
    algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    default_scope: str = "mcp:read"         # needed for any MCP request
    tool_scopes: dict[str, str] = field(default_factory=dict)  # tool -> scope
    tool_scope_fallback: str | None = None  # scope for unlisted tools; None = blocked
    rate_per_minute: int = 120
    audit_log: str | None = "audit.jsonl"
    leeway_s: int = 30

    def __post_init__(self) -> None:
        if bool(self.jwks_url) == bool(self.hs256_secret):
            raise ValueError("configure exactly one of jwks_url or hs256_secret")
        if self.hs256_secret:
            if len(self.hs256_secret) < 32:
                raise ValueError("hs256_secret must be at least 32 characters")
            self.algorithms = ["HS256"]
        if "none" in [a.lower() for a in self.algorithms]:
            raise ValueError("alg 'none' is never allowed")

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        data = yaml.safe_load(Path(path).read_text()) or {}
        # secrets come from the environment, never from the file
        if data.pop("hs256_secret", None):
            raise ValueError("put the HS256 secret in GATEWAY_HS256_SECRET, not in the file")
        secret = os.environ.get("GATEWAY_HS256_SECRET")
        if secret:
            data["hs256_secret"] = secret
        return cls(**data)
