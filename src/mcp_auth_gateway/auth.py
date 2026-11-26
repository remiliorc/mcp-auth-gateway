"""Bearer token validation and scope policy."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

import jwt

from .config import Config


def _clean_identifier(value: object) -> bool:
    # identity claims are forwarded as HTTP headers: printable ASCII only
    return (isinstance(value, str) and 0 < len(value) <= 256
            and all(0x20 < ord(c) < 0x7F for c in value))


class AuthError(Exception):
    def __init__(self, status: int, error: str, description: str,
                 scope: str | None = None):
        super().__init__(description)
        self.status, self.error, self.description, self.scope = status, error, description, scope


@dataclass
class Principal:
    subject: str
    client_id: str | None
    scopes: frozenset[str]
    claims: dict


class TokenValidator:
    def __init__(self, cfg: Config,
                 key_resolver: Callable[[str], Any] | None = None):
        self.cfg = cfg
        if key_resolver is not None:
            self._key = key_resolver
        elif cfg.hs256_secret:
            self._key = self._from_config
        else:
            client = jwt.PyJWKClient(cfg.jwks_url, cache_keys=True, lifespan=300)
            self._key = lambda token: client.get_signing_key_from_jwt(token).key

    def _from_config(self, _jwt: str) -> str:
        return self.cfg.hs256_secret

    def validate(self, authorization: str | None) -> Principal:
        if not authorization or not authorization.lower().startswith("bearer "):
            # RFC 6750 section 3.1: no error code when no credentials were sent
            raise AuthError(401, "", "missing bearer token")
        token = authorization[7:].strip()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AuthError(401, "invalid_token", "malformed token")
        if header.get("alg") not in self.cfg.algorithms:
            raise AuthError(401, "invalid_token", "signing algorithm not allowed")
        if header.get("typ") not in (None, "JWT", "at+jwt", "application/at+jwt"):
            raise AuthError(401, "invalid_token", "not an access token")
        try:
            key = self._key(token)
        except jwt.PyJWKClientError as e:
            if "Unable to find a signing key" in str(e):
                raise AuthError(401, "invalid_token", "unknown signing key")
            raise AuthError(503, "temporarily_unavailable", "cannot fetch signing keys")
        except Exception:  # malformed JWKS document, empty key set, HTML error page...
            raise AuthError(503, "temporarily_unavailable", "cannot fetch signing keys")
        try:
            claims = jwt.decode(
                token, key, algorithms=self.cfg.algorithms,
                audience=self.cfg.audience, issuer=self.cfg.issuer,
                leeway=self.cfg.leeway_s,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except jwt.ExpiredSignatureError:
            raise AuthError(401, "invalid_token", "token expired")
        except jwt.InvalidAudienceError:
            raise AuthError(401, "invalid_token", "token not issued for this resource")
        except jwt.PyJWTError as e:
            raise AuthError(401, "invalid_token", f"invalid token: {type(e).__name__}")
        raw = claims.get("scope") or claims.get("scp") or ""
        if isinstance(raw, str):
            scopes = frozenset(raw.split())
        elif isinstance(raw, list) and all(isinstance(x, str) for x in raw):
            scopes = frozenset(raw)
        else:
            raise AuthError(401, "invalid_token", "malformed scope claim")
        sub = claims["sub"]
        client = claims.get("client_id") or claims.get("azp")
        for value in (sub, client):
            if value is not None and not _clean_identifier(value):
                raise AuthError(401, "invalid_token", "malformed identity claim")
        return Principal(sub, client, scopes, claims)


def required_scopes(cfg: Config, method: str | None, tool: str | None) -> set[str]:
    need = {cfg.default_scope}
    if method == "tools/call":
        scope = cfg.tool_scopes.get(tool or "", cfg.tool_scope_fallback)
        if scope is None:
            raise AuthError(403, "insufficient_scope", "tool is not exposed")
        need.add(scope)
    return need


def authorize(cfg: Config, p: Principal, calls: list[tuple[str | None, str | None]]) -> None:
    for method, tool in calls:
        missing = required_scopes(cfg, method, tool) - p.scopes
        if missing:
            raise AuthError(403, "insufficient_scope",
                            f"missing scope: {' '.join(sorted(missing))}",
                            scope=" ".join(sorted(missing)))


class RateLimiter:
    """Token bucket per subject."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic):
        self.rate = per_minute / 60.0
        self.capacity = float(per_minute)
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = self.clock()
        tokens, last = self._buckets.get(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1, now)
        return True
