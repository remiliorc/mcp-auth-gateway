"""mcp-auth-gateway: OAuth resource-server gateway for MCP servers."""

from .app import create_app
from .auth import Principal, RateLimiter, TokenValidator
from .config import Config

__all__ = ["create_app", "Config", "TokenValidator", "RateLimiter", "Principal"]
__version__ = "0.1.0"
