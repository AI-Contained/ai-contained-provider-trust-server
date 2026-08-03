from collections.abc import AsyncGenerator

import httpx
import pytest

from ai_contained.core.mcp.harness import Harness
from ai_contained.trust import server as trust_server
from ai_contained.trust.server import TrustServer


@pytest.fixture
async def harness() -> AsyncGenerator[Harness, None]:
    # 127.0.0.1 is the peer address raw_client() forges — allow it with wildcard roles.
    async with Harness(env={"TRUST_CLIENTS": "127.0.0.1"}) as h:
        yield h


@pytest.fixture
async def trust(harness: Harness) -> TrustServer:
    state = await harness.install(trust_server.provide)
    assert isinstance(state, TrustServer)
    return state


@pytest.fixture
async def http(harness: Harness, trust: TrustServer) -> AsyncGenerator[httpx.AsyncClient, None]:
    # Test files that mount secret routes override this fixture so the routes
    # exist before http_app() is built (later custom_routes are dropped).
    async with harness.raw_client() as client:
        yield client
