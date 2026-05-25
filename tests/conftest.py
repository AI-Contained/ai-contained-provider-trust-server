from collections.abc import AsyncGenerator, Generator

import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.transports import FastMCPTransport

from ai_contained.core.mcp.testing import Elicitor
from ai_contained.provider.template import register


@pytest.fixture
async def mcp() -> FastMCP:
    """Create a FastMCP server with the template provider registered."""
    server = FastMCP("test")
    await register(server)
    return server


@pytest.fixture
def elicitor() -> Generator[Elicitor, None, None]:
    """Provide an Elicitor and assert all queued steps were consumed."""
    e = Elicitor()
    yield e
    assert not e._queue, f"{len(e._queue)} elicitation step(s) were never triggered"


@pytest.fixture
async def client(mcp: FastMCP, elicitor: Elicitor) -> AsyncGenerator[Client[FastMCPTransport], None]:
    """Provide a connected MCP client wired to the elicitor."""
    async with Client(transport=mcp, elicitation_handler=elicitor) as c:
        yield c
