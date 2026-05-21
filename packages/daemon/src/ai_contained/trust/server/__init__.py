"""Trust server daemon."""

from fastmcp import FastMCP

from ai_contained.trust.server.trust_config import get_trust_config
from ai_contained.trust.server.trust_register import register as _register_trust_register


def register(mcp: FastMCP) -> None:
    """Register all trust server endpoints with the MCP server."""
    _register_trust_register(mcp)
