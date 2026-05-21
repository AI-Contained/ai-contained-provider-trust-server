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
from ai_contained.trust.client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection


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


def describe_TrustClient() -> None:
    @pytest.fixture
    def trust_client(http: TestClient, monkeypatch: pytest.MonkeyPatch) -> TrustClient:
        expected = {"value": "supersecret"}

        async def _handler(request: Request) -> Response:
            return JSONResponse(expected)

        monkeypatch.setattr(_self, "secret_handler", _handler)
        conn = TrustConnection(http)
        conn.register()
        return TrustClient(_connection=conn, _path="/test/secret")

    def describe_post_raw() -> None:
        expected = {"value": "supersecret"}

        def it_raises_on_unregistered_client(http: TestClient) -> None:
            conn = TrustConnection(http)  # not registered
            client = TrustClient(_connection=conn, _path="/test/secret")
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                client.post_raw({})
            assert_that(exc_info.value.response.status_code).is_equal_to(401)

        @pytest.mark.parametrize("status_code", [401])
        @pytest.mark.parametrize("x_trust_secret", ["encrypt", "plaintext"])
        def it_raises_on_non_200(
            trust_client: TrustClient,
            monkeypatch: pytest.MonkeyPatch,
            status_code: int,
            x_trust_secret: str,
        ) -> None:
            async def _handler(request: Request) -> Response:
                return JSONResponse(expected, status_code=status_code, headers={"X-Trust-Secret": x_trust_secret})

            monkeypatch.setattr(_self, "secret_handler", _handler)
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                trust_client.post_raw({})
            assert_that(exc_info.value.response.status_code).is_equal_to(status_code)
            assert_that(exc_info.value.response.json()).is_equal_to(expected)

        def describe_post() -> None:
            @pytest.mark.parametrize("x_trust_secret", ["encrypt", "plaintext"])
            def it_decrypts_json(
                trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch, x_trust_secret: str
            ) -> None:
                expected = {"value": "supersecret"}

                async def _handler(request: Request) -> Response:
                    return JSONResponse(expected, headers={"X-Trust-Secret": x_trust_secret})

                monkeypatch.setattr(_self, "secret_handler", _handler)
                assert_that(trust_client.post({})).is_equal_to(expected)

            def it_raises_on_non_json_response(
                trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                async def _handler(request: Request) -> Response:
                    return Response(content=b"not json", headers={"X-Trust-Secret": "plaintext"})

                monkeypatch.setattr(_self, "secret_handler", _handler)
                with pytest.raises(json.JSONDecodeError):
                    trust_client.post({})

            def it_sets_authorization_header(
                trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                expected = {"value": "supersecret"}
                captured: dict = {}

                async def _handler(request: Request) -> Response:
                    captured["headers"] = dict(request.headers)
                    return JSONResponse(expected)

                monkeypatch.setattr(_self, "secret_handler", _handler)
                assert_that(trust_client.post({})).is_equal_to(expected)
                assert_that(captured["headers"].get("authorization")).starts_with('Signature keyId="Ed25519",signature="')

    def describe_role_enforcement() -> None:
        def it_can_register_at_custom_path(mcp: FastMCP) -> None:
            expected = {"ok": True}
            trust_server.get_trust_config().reset("shell=127.0.0.1")

            @trust_server.secret_route(mcp, role="shell", path="/custom/path")
            async def shell_endpoint(request: Request) -> Response:
                return JSONResponse(expected)

            http = TestClient(mcp.http_app(), client=("127.0.0.1", 50000))
            conn = TrustConnection(http)
            conn.register()
            client = TrustClient(_connection=conn, _path="/custom/path")

            # "shell" role cannot access the "test" route
            test_client = TrustClient(_connection=conn, _path="/test/secret")
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                test_client.post({})
            assert_that(exc_info.value.response.status_code).is_equal_to(403)

            # custom path with matching role succeeds
            assert_that(client.post({})).is_equal_to(expected)

        def it_allows_request_when_role_is_permitted(
            http: TestClient, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            expected = {"ok": True}
            trust_server.get_trust_config().reset("test=127.0.0.1")

            async def _handler(request: Request) -> Response:
                return JSONResponse(expected)

            monkeypatch.setattr(_self, "secret_handler", _handler)
            conn = TrustConnection(http)
            conn.register()
            client = TrustClient(_connection=conn, _path="/test/secret")
            assert_that(client.post({})).is_equal_to(expected)

        def it_returns_403_when_role_is_not_permitted(http: TestClient) -> None:
            trust_server.get_trust_config().reset("aws=127.0.0.1")  # only aws role — test not permitted
            conn = TrustConnection(http)
            conn.register()
            client = TrustClient(_connection=conn, _path="/test/secret")
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                client.post({})
            assert_that(exc_info.value.response.status_code).is_equal_to(403)
            assert_that(exc_info.value.response.json()).is_equal_to({"code": "FORBIDDEN"})

        def it_shares_connection_instance_across_roles(http: TestClient) -> None:
            conn = TrustConnection(http)
            aws = TrustClient(_connection=conn, _path="/aws/secret")
            github = TrustClient(_connection=conn, _path="/github/secret")
            assert_that(aws._connection).is_same_as(github._connection)
