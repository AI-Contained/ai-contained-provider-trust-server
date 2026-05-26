from collections.abc import AsyncGenerator

import httpx
import pytest
from fastmcp import FastMCP

from ai_contained.trust import server as trust_server
from ai_contained.trust.server.trust_store import get_trust_store


@pytest.fixture(autouse=True)
def reset_trust_store() -> None:
    get_trust_store().reset()
    trust_server.get_trust_config().reset("127.0.0.1")  # allow test client IP with wildcard roles


@pytest.fixture
async def mcp() -> FastMCP:
    server = FastMCP("test")
    await trust_server.register(server)
    return server


@pytest.fixture
async def http(mcp: FastMCP) -> AsyncGenerator[httpx.AsyncClient, None]:
    # ASGITransport routes directly to the ASGI app — base_url host is ignored.
    # client overrides the remote IP so one-registration-per-IP enforcement works.
    transport = httpx.ASGITransport(app=mcp.http_app(), client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://ignored") as client:
        yield client
