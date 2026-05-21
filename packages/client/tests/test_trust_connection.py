import json

import httpx
import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.testclient import TestClient

import test_trust_client as _self
from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustConnection


# Delegate for secret_endpoint - monkeypatched per test to control the response.
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
    def trust_client(http: TestClient) -> TrustConnection:
        return TrustConnection(http)  # TestClient is a subclass of httpx.Client

    def describe_register() -> None:
        def it_returns_true_on_success(trust_client: TrustConnection) -> None:
            assert_that(trust_client.register()).is_true()

        def it_fails_when_already_registered(trust_client: TrustConnection) -> None:
            assert_that(trust_client.register()).is_true()
            assert_that(trust_client.register()).is_false()

    def describe_post_raw() -> None:
        expected = {"value": "supersecret"}

        @pytest.fixture
        def trust_client(http: TestClient, monkeypatch: pytest.MonkeyPatch) -> TrustConnection:
            async def _handler(request: Request) -> Response:
                return JSONResponse(expected)

            monkeypatch.setattr(_self, "secret_handler", _handler)
            client = TrustConnection(http)
            client.register()
            return client

        def it_raises_on_unregistered_client(http: TestClient) -> None:
            client = TrustConnection(http)  # not registered
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                client.post_raw("/test/secret", {})
            assert_that(exc_info.value.response.status_code).is_equal_to(401)

        @pytest.mark.parametrize("status_code", [401])
        @pytest.mark.parametrize("x_trust_secret", ["encrypt", "plaintext"])
        def it_raises_on_non_200(
            trust_client: TrustConnection,
            monkeypatch: pytest.MonkeyPatch,
            status_code: int,
            x_trust_secret: str,
        ) -> None:
            async def _handler(request: Request) -> Response:
                return JSONResponse(expected, status_code=status_code, headers={"X-Trust-Secret": x_trust_secret})

            monkeypatch.setattr(_self, "secret_handler", _handler)
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                trust_client.post_raw("/test/secret", {})
            assert_that(exc_info.value.response.status_code).is_equal_to(status_code)
            assert_that(exc_info.value.response.json()).is_equal_to(expected)

        def describe_post() -> None:
            @pytest.mark.parametrize("x_trust_secret", ["encrypt", "plaintext"])
            def it_decrypts_json(
                trust_client: TrustConnection, monkeypatch: pytest.MonkeyPatch, x_trust_secret: str
            ) -> None:
                async def _handler(request: Request) -> Response:
                    return JSONResponse(expected, headers={"X-Trust-Secret": x_trust_secret})

                monkeypatch.setattr(_self, "secret_handler", _handler)
                result = trust_client.post("/test/secret", {})
                assert_that(result).is_equal_to(expected)

            def it_raises_on_non_json_response(
                trust_client: TrustConnection, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                async def _handler(request: Request) -> Response:
                    return Response(content=b"not json", headers={"X-Trust-Secret": "plaintext"})

                monkeypatch.setattr(_self, "secret_handler", _handler)
                with pytest.raises(json.JSONDecodeError):
                    trust_client.post("/test/secret", {})

            def it_sets_authorization_header(
                trust_client: TrustConnection, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                captured: dict = {}

                async def _handler(request: Request) -> Response:
                    captured["headers"] = dict(request.headers)
                    return JSONResponse(expected)

                monkeypatch.setattr(_self, "secret_handler", _handler)
                result = trust_client.post("/test/secret", {})
                assert_that(result).is_equal_to(expected)
                assert_that(captured["headers"].get("authorization")).starts_with('Signature keyId="Ed25519",signature="')

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

    def describe_role_enforcement() -> None:
        def it_can_register_at_custom_path(mcp: FastMCP) -> None:
            expected = {"ok": True}
            trust_server.get_trust_config().reset("shell=127.0.0.1")

            @trust_server.secret_route(mcp, role="shell", path="/custom/path")
            async def shell_endpoint(request: Request) -> Response:
                return JSONResponse(expected)

            # TestClient created after route registration so the route is visible
            http = TestClient(mcp.http_app(), client=("127.0.0.1", 50000))
            client = TrustConnection(http)
            client.register()

            # "shell" role cannot access the "test" route
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                client.post("/test/secret", {})
            assert_that(exc_info.value.response.status_code).is_equal_to(403)

            # custom path with matching role succeeds
            assert_that(client.post("/custom/path", {})).is_equal_to(expected)

        def it_allows_request_when_role_is_permitted(
            http: TestClient, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            expected = {"ok": True}
            trust_server.get_trust_config().reset("test=127.0.0.1")  # explicit test role
            async def _handler(request: Request) -> Response:
                return JSONResponse(expected)
            monkeypatch.setattr(_self, "secret_handler", _handler)
            client = TrustConnection(http)
            client.register()
            assert_that(client.post("/test/secret", {})).is_equal_to(expected)

        def it_returns_403_when_role_is_not_permitted(http: TestClient) -> None:
            trust_server.get_trust_config().reset("aws=127.0.0.1")  # only aws role — test not permitted
            client = TrustConnection(http)
            client.register()
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                client.post("/test/secret", {})
            assert_that(exc_info.value.response.status_code).is_equal_to(403)
            assert_that(exc_info.value.response.json()).is_equal_to({"code": "FORBIDDEN"})
