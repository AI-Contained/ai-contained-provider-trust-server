from assertpy import assert_that
from starlette.testclient import TestClient


def describe_POST_trust_register() -> None:
    def it_is_accessible(http: TestClient) -> None:
        response = http.post("/trust/register", json={})
        assert_that(response.status_code).is_not_equal_to(404)
        assert_that(response.status_code).is_less_than(500)

    def it_rejects_missing_signing_key(http: TestClient) -> None:
        response = http.post("/trust/register", json={"encryption_public_key": "ab" * 32})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")

    def it_rejects_missing_encryption_key(http: TestClient) -> None:
        response = http.post("/trust/register", json={"signing_public_key": "ab" * 32})
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")

    def it_rejects_malformed_key_format(http: TestClient) -> None:
        response = http.post(
            "/trust/register",
            json={"signing_public_key": "not-hex", "encryption_public_key": "not-hex"},
        )
        assert_that(response.status_code).is_equal_to(400)
        assert_that(response.json()["code"]).is_equal_to("INVALID_KEY")

    def it_rejects_invalid_json_payload(http: TestClient) -> None:
        response = http.post("/trust/register", content=b"not json", headers={"content-type": "application/json"})
        assert_that(response.status_code).is_equal_to(400)

    def it_rejects_non_json_content_type(http: TestClient) -> None:
        response = http.post(
            "/trust/register",
            content=b'{"signing_public_key": "ab" * 32, "encryption_public_key": "cd" * 32}',
            headers={"content-type": "text/plain"},
        )
        assert_that(response.status_code).is_equal_to(400)

    def it_rejects_duplicate_registration_from_same_ip(http: TestClient) -> None:
        payload = {"signing_public_key": "ab" * 32, "encryption_public_key": "cd" * 32}
        first = http.post("/trust/register", json=payload)
        assert_that(first.status_code).is_equal_to(200)
        second = http.post("/trust/register", json=payload)
        assert_that(second.status_code).is_equal_to(401)
