import httpx
import pytest
from assertpy import assert_that

from ai_contained.trust import client as trust_client
from ai_contained.trust.client.trust_config import reset_trust_config
from ai_contained.trust.client.trust_connection import TrustConnection


@pytest.fixture(autouse=True)
def _reset_trust_config() -> None:
    reset_trust_config()


def describe_TrustConfig() -> None:
    def describe_parse() -> None:
        def it_returns_empty_for_empty_string() -> None:
            assert_that(trust_client.TrustConfig._parse("")).is_empty()

        def it_maps_bare_url_to_wildcard() -> None:
            assert_that(trust_client.TrustConfig._parse("http://server:8080")).is_equal_to({"*": "http://server:8080"})

        def it_maps_role_to_url() -> None:
            assert_that(trust_client.TrustConfig._parse("aws=http://aws:8080")).is_equal_to({"aws": "http://aws:8080"})

        def it_maps_multiple_roles() -> None:
            assert_that(trust_client.TrustConfig._parse("aws=http://aws:8080,github=http://github:8080")).is_equal_to(
                {"aws": "http://aws:8080", "github": "http://github:8080"}
            )

        def it_maps_empty_url_to_none() -> None:
            assert_that(trust_client.TrustConfig._parse("aws=")).is_equal_to({"aws": None})

        def it_combines_wildcard_and_role_override() -> None:
            assert_that(trust_client.TrustConfig._parse("http://server:8080,aws=http://aws:8080")).is_equal_to(
                {"*": "http://server:8080", "aws": "http://aws:8080"}
            )

        def it_combines_wildcard_with_deny() -> None:
            assert_that(trust_client.TrustConfig._parse("http://server:8080,aws=")).is_equal_to(
                {"*": "http://server:8080", "aws": None}
            )

        def it_raises_on_duplicate_role() -> None:
            assert_that(trust_client.TrustConfig._parse).raises(trust_client.DuplicateSourceError).when_called_with(
                "aws=http://foo.com:8080,aws=http://bar.com:8080"
            )

        def it_raises_on_duplicate_wildcard() -> None:
            assert_that(trust_client.TrustConfig._parse).raises(trust_client.DuplicateSourceError).when_called_with(
                "http://foo.com:8080,http://foo.com:8081"
            )

    def describe_get_client() -> None:
        def it_is_uninitialized_by_default() -> None:
            assert_that(trust_client.get_trust_config()).is_none()

        async def it_allows_known_role_and_denies_unknown(http: httpx.AsyncClient) -> None:
            await trust_client.init_trust_config("aws=http://127.0.0.1:8080", lambda url: http)
            assert_that(trust_client.get_trust_config().get_client("github")).is_none()
            assert_that(trust_client.get_trust_config().get_client("aws")).is_instance_of(trust_client.TrustClient)

        async def it_allows_any_role_via_wildcard(http: httpx.AsyncClient) -> None:
            await trust_client.init_trust_config("http://127.0.0.1:8080", lambda url: http)
            assert_that(trust_client.get_trust_config().get_client("github")).is_instance_of(trust_client.TrustClient)
            assert_that(trust_client.get_trust_config().get_client("aws")).is_instance_of(trust_client.TrustClient)

        async def it_denies_role_even_with_wildcard(http: httpx.AsyncClient) -> None:
            await trust_client.init_trust_config("http://127.0.0.1:8080,aws=", lambda url: http)
            assert_that(trust_client.get_trust_config().get_client("github")).is_instance_of(trust_client.TrustClient)
            assert_that(trust_client.get_trust_config().get_client("aws")).is_none()

        async def it_shares_connection_across_roles_on_same_host(http: httpx.AsyncClient) -> None:
            await trust_client.init_trust_config(
                "aws=http://127.0.0.1:8080,shell=http://127.0.0.1:8080", lambda url: http
            )
            config = trust_client.get_trust_config()
            assert_that(config.get_client("aws")._connection).is_same_as(config.get_client("shell")._connection)

        async def it_uses_role_specific_path_when_falling_back_to_wildcard(http: httpx.AsyncClient) -> None:
            # Wildcard config bakes _path="/*/secret" into the client. Falling back to it for
            # role="aws" must produce a client whose path is "/aws/secret", not "/*/secret" —
            # otherwise httpx URL-encodes the "*" and the server receives "/%2A/secret" → 404.
            await trust_client.init_trust_config("http://127.0.0.1:8080", lambda url: http)
            assert_that(trust_client.get_trust_config().get_client("aws")._path).is_equal_to("/aws/secret")


def describe_register_clients() -> None:
    from ai_contained.trust.client.trust_config import _register_clients

    async def it_shares_connection_for_same_host(http: httpx.AsyncClient) -> None:
        parsed = {"aws": "http://127.0.0.1:8080", "shell": "http://127.0.0.1:8080"}
        result = await _register_clients(parsed, lambda url: http)
        assert_that(result["aws"]._connection).is_same_as(result["shell"]._connection)

    async def it_retries_on_network_error(http: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
        ncalls = 0
        original_register = TrustConnection.register

        async def flaky_register(self: TrustConnection) -> bool:
            nonlocal ncalls
            ncalls += 1
            if ncalls <= 2:
                raise httpx.ConnectError("connection refused")
            return await original_register(self)

        async def no_sleep(_: float) -> None:
            pass

        monkeypatch.setattr(TrustConnection, "register", flaky_register)
        monkeypatch.setattr("ai_contained.trust.client.trust_config._sleep", no_sleep)

        parsed = {"aws": "http://127.0.0.1:8080"}
        result = await _register_clients(parsed, lambda url: http, max_retries=3)
        assert_that(result["aws"]).is_instance_of(trust_client.TrustClient)

    @pytest.mark.parametrize("base_url", ["http://127.0.0.1:8080", "http://127.0.0.1:8080/"])
    async def it_derives_path_from_role_when_url_has_no_path(http: httpx.AsyncClient, base_url: str) -> None:
        parsed = {"aws": base_url}
        result = await _register_clients(parsed, lambda url: http)
        assert_that(result["aws"]._path).is_equal_to("/aws/secret")

    async def it_uses_explicit_path_when_url_specifies_one(http: httpx.AsyncClient) -> None:
        expected = "/custom/path"
        parsed = {"aws": f"http://127.0.0.1:8080{expected}"}
        result = await _register_clients(parsed, lambda url: http)
        assert_that(result["aws"]._path).is_equal_to(expected)

    async def it_raises_after_max_retries(http: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch) -> None:
        async def always_fail(self: TrustConnection) -> bool:
            raise httpx.ConnectError("connection refused")

        async def no_sleep(_: float) -> None:
            pass

        monkeypatch.setattr(TrustConnection, "register", always_fail)
        monkeypatch.setattr("ai_contained.trust.client.trust_config._sleep", no_sleep)

        parsed = {"aws": "http://127.0.0.1:8080"}
        with pytest.raises(httpx.ConnectError):
            await _register_clients(parsed, lambda url: http, max_retries=2)
