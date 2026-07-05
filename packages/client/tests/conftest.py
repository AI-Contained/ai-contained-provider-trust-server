from collections.abc import AsyncGenerator

import httpx
import pytest

from ai_contained.core.mcp.stack import Stack
from ai_contained.trust import server as trust_server
from ai_contained.trust.server import TrustServer
from ai_contained.trust.testing import loopback_http


@pytest.fixture
async def stack() -> AsyncGenerator[Stack, None]:
    # 127.0.0.1 is the peer address loopback_http() forges — allow it with wildcard roles.
    async with Stack(env={"TRUST_CLIENTS": "127.0.0.1"}) as s:
        yield s


@pytest.fixture
async def trust(stack: Stack) -> TrustServer:
    state = await stack.install(trust_server.provide)
    assert isinstance(state, TrustServer)
    return state


@pytest.fixture
async def http(stack: Stack, trust: TrustServer) -> AsyncGenerator[httpx.AsyncClient, None]:
    # Test files that mount secret routes override this fixture so the routes
    # exist before http_app() is built (later custom_routes are dropped).
    async with loopback_http(stack) as client:
        yield client
