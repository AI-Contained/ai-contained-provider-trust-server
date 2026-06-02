import json

import httpx
import pytest
from assertpy import assert_that
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ai_contained.trust import server as trust_server
from ai_contained.trust.client import TrustClient
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


def describe_TrustClient() -> None:
    @pytest.fixture
    async def trust_client(http: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> TrustClient:
        expected = {"value": "supersecret"}

        async def _handler(request: Request) -> Response:
            return JSONResponse(expected)

        monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
        conn = TrustConnection(http)
        await conn.register()
        return TrustClient(_connection=conn, _path="/test/secret")

    def describe_post_raw() -> None:
        expected = {"value": "supersecret"}

        async def it_raises_on_unregistered_client(http: httpx.AsyncClient) -> None:
            conn = TrustConnection(http)  # not registered
            client = TrustClient(_connection=conn, _path="/test/secret")
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.post_raw(b"{}")
            assert_that(exc_info.value.response.status_code).is_equal_to(401)

        @pytest.mark.parametrize("status_code", [401])
        @pytest.mark.parametrize("x_trust_secret", ["encrypt", "plaintext"])
        async def it_raises_on_non_200(
            trust_client: TrustClient,
            monkeypatch: pytest.MonkeyPatch,
            status_code: int,
            x_trust_secret: str,
        ) -> None:
            async def _handler(request: Request) -> Response:
                return JSONResponse(expected, status_code=status_code, headers={"X-Trust-Secret": x_trust_secret})

            monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await trust_client.post_raw(b"{}")
            assert_that(exc_info.value.response.status_code).is_equal_to(status_code)
            assert_that(exc_info.value.response.json()).is_equal_to(expected)

        async def it_forwards_raw_bytes_as_body(
            trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            expected = b"not-json"
            captured: dict = {}

            async def _handler(request: Request) -> Response:
                captured["body"] = await request.body()
                return Response(content=b'{"ok": true}', headers={"X-Trust-Secret": "plaintext"})

            monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
            await trust_client.post_raw(expected)
            assert_that(captured.get("body")).is_equal_to(expected)

        def describe_post() -> None:
            @pytest.mark.parametrize("x_trust_secret", ["encrypt", "plaintext"])
            async def it_decrypts_json(
                trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch, x_trust_secret: str
            ) -> None:
                expected = {"value": "supersecret"}

                async def _handler(request: Request) -> Response:
                    return JSONResponse(expected, headers={"X-Trust-Secret": x_trust_secret})

                monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
                assert_that(await trust_client.post({})).is_equal_to(expected)

            async def it_raises_on_non_json_response(
                trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch
            ) -> None:
                async def _handler(request: Request) -> Response:
                    return Response(content=b"not json", headers={"X-Trust-Secret": "plaintext"})

                monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
                with pytest.raises(json.JSONDecodeError):
                    await trust_client.post({})

            async def it_sets_authorization_header(trust_client: TrustClient, monkeypatch: pytest.MonkeyPatch) -> None:
                expected = {"value": "supersecret"}
                captured: dict = {}

                async def _handler(request: Request) -> Response:
                    captured["headers"] = dict(request.headers)
                    return JSONResponse(expected)

                monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
                assert_that(await trust_client.post({})).is_equal_to(expected)
                result = captured["headers"].get("authorization")
                assert_that(result).matches(r'^Signature keyId="Ed25519",created_ts="\d+",signature="[0-9a-f]+"$')

    def describe_role_enforcement() -> None:
        async def it_can_register_at_custom_path(mcp: FastMCP) -> None:
            expected = {"ok": True}
            trust_server.get_trust_config().reset("shell=127.0.0.1")

            @trust_server.secret_route(mcp, role="shell", path="/custom/path")
            async def shell_endpoint(request: Request) -> Response:
                return JSONResponse(expected)

            transport = httpx.ASGITransport(app=mcp.http_app(), client=("127.0.0.1", 50000))
            async with httpx.AsyncClient(transport=transport, base_url="http://ignored") as http:
                conn = TrustConnection(http)
                await conn.register()
                client = TrustClient(_connection=conn, _path="/custom/path")

                # "shell" role cannot access the "test" route
                test_client = TrustClient(_connection=conn, _path="/test/secret")
                with pytest.raises(httpx.HTTPStatusError) as exc_info:
                    await test_client.post({})
                assert_that(exc_info.value.response.status_code).is_equal_to(403)

                # custom path with matching role succeeds
                assert_that(await client.post({})).is_equal_to(expected)

        async def it_allows_request_when_role_is_permitted(
            http: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
        ) -> None:
            expected = {"ok": True}
            trust_server.get_trust_config().reset("test=127.0.0.1")

            async def _handler(request: Request) -> Response:
                return JSONResponse(expected)

            monkeypatch.setattr(SecretEndpointHandler, "handle", _handler)
            conn = TrustConnection(http)
            await conn.register()
            client = TrustClient(_connection=conn, _path="/test/secret")
            assert_that(await client.post({})).is_equal_to(expected)

        async def it_returns_403_when_role_is_not_permitted(http: httpx.AsyncClient) -> None:
            trust_server.get_trust_config().reset("aws=127.0.0.1")  # only aws role — test not permitted
            conn = TrustConnection(http)
            await conn.register()
            client = TrustClient(_connection=conn, _path="/test/secret")
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await client.post({})
            assert_that(exc_info.value.response.status_code).is_equal_to(403)
            assert_that(exc_info.value.response.json()).is_equal_to({"code": "FORBIDDEN"})

        def it_shares_connection_instance_across_roles(http: httpx.AsyncClient) -> None:
            conn = TrustConnection(http)
            aws = TrustClient(_connection=conn, _path="/aws/secret")
            github = TrustClient(_connection=conn, _path="/github/secret")
            assert_that(aws._connection).is_same_as(github._connection)
