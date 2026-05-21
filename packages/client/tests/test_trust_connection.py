import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.testclient import TestClient

from ai_contained.trust import server as trust_server
from ai_contained.trust.client.trust_connection import TrustConnection


async def secret_handler(request: Request) -> Response:
    raise NotImplementedError


@pytest.fixture
def mcp() -> FastMCP:
    server = FastMCP("test")
    trust_server.register(server)

    @trust_server.secret_route(server, role="test")
    async def secret_endpoint(request: Request) -> Response:
        return await secret_handler(request)

    return server


def describe_TrustConnection() -> None:
    @pytest.fixture
    def connection(http: TestClient) -> TrustConnection:
        return TrustConnection(http)

    def describe_register() -> None:
        def it_returns_true_on_success(connection: TrustConnection) -> None:
            assert_that(connection.register()).is_true()

        def it_fails_when_already_registered(connection: TrustConnection) -> None:
            assert_that(connection.register()).is_true()
            assert_that(connection.register()).is_false()

    def describe_authorize_header() -> None:
        # we need to be able to make raw http connections (to fake our malformed requests)
        @pytest.fixture
        def registered_http(http: TestClient) -> TestClient:
            TrustConnection(http).register()
            return http

        def it_returns_401_when_authorization_header_is_missing(registered_http: TestClient) -> None:
            response = registered_http.post("/test/secret", json={})
            assert_that(response.status_code).is_equal_to(401)
            assert_that(response.json()).is_equal_to({"code": "INVALID_AUTHORIZATION"})

        def it_returns_401_when_signature_is_invalid(registered_http: TestClient) -> None:
            response = registered_http.post(
                "/test/secret",
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "authorization": f'Signature keyId="Ed25519",signature="{"ab" * 32}"',
                },
            )
            assert_that(response.status_code).is_equal_to(401)
            assert_that(response.json()).is_equal_to({"code": "INVALID_SIGNATURE"})

        def it_returns_401_when_signature_hex_is_odd_length(registered_http: TestClient) -> None:
            response = registered_http.post(
                "/test/secret",
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "authorization": 'Signature keyId="Ed25519",signature="abc"',
                },
            )
            assert_that(response.status_code).is_equal_to(401)
            assert_that(response.json()).is_equal_to({"code": "INVALID_AUTHORIZATION"})
