"""Trust server provider."""

from fastmcp import FastMCP

from ai_contained.trust.server.secret_route import secret_route as secret_route
from ai_contained.trust.server.trust_config import get_trust_config as get_trust_config
from ai_contained.trust.server.trust_register import register as _register_trust_endpoint


async def register(mcp: FastMCP) -> None:
    """Register trust server endpoints with the MCP server."""
    await _register_trust_endpoint(mcp)


__all__ = ["secret_route", "get_trust_config", "register"]
