"""Trust server daemon."""

from fastmcp import FastMCP

from ai_contained.trust.server.secret_route import secret_route as secret_route
from ai_contained.trust.server.trust_config import get_trust_config as get_trust_config
from ai_contained.trust.server.trust_register import register as register


async def load_provider(mcp: FastMCP) -> None:
    """Entry point for ai_contained.provider — no-op; trust server setup is explicit."""
    pass


__all__ = ["secret_route", "get_trust_config", "register", "load_provider"]
