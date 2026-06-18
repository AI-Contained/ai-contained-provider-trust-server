from ipaddress import ip_address

import httpx
import pytest
from assertpy import assert_that

import ai_contained.trust.server.trust_config as trust_config
from ai_contained.trust import server as trust_server
from ai_contained.trust.server.trust_store import get_trust_store


def describe_POST_trust_register() -> None:
    async def it_is_accessible(http: httpx.AsyncClient) -> None:
        response = await http.post("/trust/register", json={})
        assert_that(response.status_code).is_not_equal_to(404)
        assert_that(response.status_code).is_less_than(500)

    async def it_returns_empty_body_on_success(http: httpx.AsyncClient) -> None:
        payload = {"signing_public_key": "ab" * 32, "encryption_public_key": "cd" * 32}
        response = await http.post("/trust/register", json=payload)
        assert_that(response.status_code).is_equal_to(200)
        assert_that(response.content).is_empty()

    async def it_rejects_missing_signing_key(http: httpx.AsyncClient) -> None:
        response = await http.post("/trust/register", json={"encryption_public_key": "ab" * 32})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()).is_equal_to(
            {"code": "INVALID_KEY", "detail": "signing_public_key: missing or not a string"}
        )

    async def it_rejects_missing_encryption_key(http: httpx.AsyncClient) -> None:
        response = await http.post("/trust/register", json={"signing_public_key": "ab" * 32})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()).is_equal_to(
            {"code": "INVALID_KEY", "detail": "encryption_public_key: missing or not a string"}
        )

    async def it_rejects_malformed_key_format(http: httpx.AsyncClient) -> None:
        response = await http.post(
            "/trust/register",
            json={"signing_public_key": "not-hex", "encryption_public_key": "not-hex"},
        )
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")
        assert_that(response.json()["detail"]).starts_with("signing_public_key: non-hexadecimal number found")

    async def it_rejects_invalid_json_payload(http: httpx.AsyncClient) -> None:
        response = await http.post("/trust/register", content=b"not json", headers={"content-type": "application/json"})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_JSON")
        assert_that(response.json()["detail"]).starts_with("Expecting value")

    async def it_rejects_non_json_content_type(http: httpx.AsyncClient) -> None:
        response = await http.post(
            "/trust/register",
            content=b'{"signing_public_key": "ab", "encryption_public_key": "cd"}',
            headers={"content-type": "text/plain"},
        )
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()).is_equal_to({"code": "INVALID_CONTENT_TYPE"})

    async def it_rejects_duplicate_registration_from_same_ip(http: httpx.AsyncClient) -> None:
        payload = {"signing_public_key": "ab" * 32, "encryption_public_key": "cd" * 32}
        first = await http.post("/trust/register", json=payload)
        assert_that(first.status_code).is_equal_to(200)
        second = await http.post("/trust/register", json=payload)
        assert_that(second.status_code).is_equal_to(401)
        assert_that(second.json()).is_equal_to({"code": "ALREADY_REGISTERED"})

    async def it_rejects_client_not_in_trust_config(http: httpx.AsyncClient) -> None:
        trust_server.get_trust_config().reset("172.172.172.172")  # override autouse — 127.0.0.1 not permitted
        payload = {"signing_public_key": "ab" * 32, "encryption_public_key": "cd" * 32}
        response = await http.post("/trust/register", json=payload)
        assert_that(response.status_code).is_equal_to(401)
        assert_that(response.json()).is_equal_to({"code": "FORBIDDEN"})

    async def it_merges_role_sets_when_multiple_hostnames_resolve_to_same_ip(
        http: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Operator deliberately aliased two TRUST_CLIENTS entries to one container —
        # both should be applied, not rejected as ambiguous.
        async def _fake_forward_dns(hostname: str) -> list[str]:
            return ["127.0.0.1"] if hostname in ("alias-a", "alias-b") else []

        monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
        trust_server.get_trust_config().reset("aws=alias-a,shell=alias-b")
        payload = {"signing_public_key": "ab" * 32, "encryption_public_key": "cd" * 32}
        response = await http.post("/trust/register", json=payload)
        assert_that(response.status_code).is_equal_to(200)

        registered = get_trust_store()._clients[ip_address("127.0.0.1")]
        assert_that(registered.roles.allowed).is_equal_to({"aws", "shell"})
