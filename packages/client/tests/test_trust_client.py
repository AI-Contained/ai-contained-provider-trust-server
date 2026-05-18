import pytest
from assertpy import assert_that
from starlette.testclient import TestClient

from ai_contained.trust.client import TrustClient


def describe_TrustClient() -> None:
    @pytest.fixture
    def trust_client(http: TestClient) -> TrustClient:
        return TrustClient(http)  # TestClient is a subclass of httpx.Client

    def describe_register() -> None:
        def it_returns_true_on_success(trust_client: TrustClient) -> None:
            assert_that(trust_client.register()).is_true()

        def it_returns_false_when_already_registered(trust_client: TrustClient) -> None:
            assert_that(trust_client.register()).is_true()
            assert_that(trust_client.register()).is_false()
