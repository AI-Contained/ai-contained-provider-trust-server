import time

import httpx
import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import Response

import ai_contained.trust.client.trust_connection as trust_connection
from ai_contained.trust import server as trust_server
from ai_contained.trust.client.trust_connection import TrustConnection


async def _raise_not_implemented(request: Request) -> Response:
    raise NotImplementedError


class SecretEndpointHandler:
    handle = _raise_not_implemented


@pytest.fixture
async def mcp() -> FastMCP:
    server = FastMCP("test")
    await trust_server.register(server)

    @trust_server.secret_route(server, role="test")
    async def secret_endpoint(request: Request) -> Response:
        return await SecretEndpointHandler.handle(request)

    return server


def describe_TrustConnection() -> None:
    @pytest.fixture
    def connection(http: httpx.AsyncClient) -> TrustConnection:
        return TrustConnection(http)

    def describe_register() -> None:
        async def it_returns_true_on_success(connection: TrustConnection) -> None:
            assert_that(await connection.register()).is_true()

        async def it_fails_when_already_registered(connection: TrustConnection) -> None:
            assert_that(await connection.register()).is_true()
            assert_that(await connection.register()).is_false()

    def describe_post_raw() -> None:
        @pytest.fixture
        async def connection(http: httpx.AsyncClient) -> TrustConnection:
            conn = TrustConnection(http)
            await conn.register()
            return conn

        async def it_decrypts_response(connection: TrustConnection, monkeypatch: pytest.MonkeyPatch) -> None:
            expected = b"hello"

            async def _handler(request: Request) -> Response:
                return Response(content=expected)

            monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
            assert_that(await connection.post_raw("/test/secret", {})).is_equal_to(expected)

    def describe_authorize_header() -> None:
        @pytest.fixture
        async def registered_http(http: httpx.AsyncClient) -> httpx.AsyncClient:
            await TrustConnection(http).register()
            return http

        async def it_returns_401_when_authorization_header_is_missing(registered_http: httpx.AsyncClient) -> None:
            response = await registered_http.post("/test/secret", json={})
            assert_that(response.status_code).is_equal_to(401)
            assert_that(response.json()).is_equal_to({"code": "INVALID_AUTHORIZATION"})

        async def it_returns_401_when_signature_is_invalid(registered_http: httpx.AsyncClient) -> None:
            created_ts = int(time.time())
            response = await registered_http.post(
                "/test/secret",
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "authorization": f'Signature keyId="Ed25519",created_ts="{created_ts}",signature="{"ab" * 32}"',
                },
            )
            assert_that(response.status_code).is_equal_to(401)
            assert_that(response.json()).is_equal_to({"code": "INVALID_SIGNATURE"})

        async def it_returns_401_when_signature_hex_is_odd_length(registered_http: httpx.AsyncClient) -> None:
            response = await registered_http.post(
                "/test/secret",
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "authorization": 'Signature keyId="Ed25519",signature="abc"',
                },
            )
            assert_that(response.status_code).is_equal_to(401)
            assert_that(response.json()).is_equal_to({"code": "INVALID_AUTHORIZATION"})

    def describe_replay_protection() -> None:
        @pytest.fixture
        async def connection(http: httpx.AsyncClient) -> TrustConnection:
            conn = TrustConnection(http)
            await conn.register()
            return conn

        async def it_rejects_an_expired_timestamp(connection: TrustConnection, monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setattr(trust_connection, "_now", lambda: time.time() - 60)
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await connection.post_raw("/test/secret", {})
            assert_that(exc_info.value.response.status_code).is_equal_to(401)
            assert_that(exc_info.value.response.json()).is_equal_to({"code": "REQUEST_EXPIRED"})

        async def it_rejects_a_future_timestamp(connection: TrustConnection, monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setattr(trust_connection, "_now", lambda: time.time() + 60)
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await connection.post_raw("/test/secret", {})
            assert_that(exc_info.value.response.status_code).is_equal_to(401)
            assert_that(exc_info.value.response.json()).is_equal_to({"code": "REQUEST_EXPIRED"})
