import pytest

from ai_contained.trust.client import TrustClient
from ai_contained.trust.server import TrustServer


@pytest.fixture
def server() -> TrustServer:
    return TrustServer()


@pytest.fixture
def trust_client(server: TrustServer) -> TrustClient:
    return TrustClient(server=server)
