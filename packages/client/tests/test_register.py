import httpx
from assertpy import assert_that

from ai_contained.trust.client import TrustClient
from ai_contained.trust.server import TrustServer


def describe_POST_register() -> None:
    async def it_returns_server_encryption_public_key(trust_client: TrustClient) -> None:
        server_public_key = await trust_client.register()
        assert_that(server_public_key).is_not_none()
        assert_that(server_public_key).is_length(64)  # 32-byte Curve25519 key as hex

    async def it_allows_re_registration_with_same_key(trust_client: TrustClient) -> None:
        await trust_client.register()
        await trust_client.register()  # same keypair — should update record, not raise

    async def it_rejects_missing_signing_key(server: TrustServer) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.app), base_url="http://test"
        ) as client:
            response = await client.post("/register", json={"encryption_public_key": "ab" * 32})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")

    async def it_rejects_missing_encryption_key(server: TrustServer) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.app), base_url="http://test"
        ) as client:
            response = await client.post("/register", json={"signing_public_key": "ab" * 32})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")

    async def it_rejects_malformed_key_format(server: TrustServer) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/register",
                json={"signing_public_key": "not-hex", "encryption_public_key": "not-hex"},
            )
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")
