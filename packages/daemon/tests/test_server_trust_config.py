import pytest
from assertpy import assert_that

import ai_contained.trust.server.trust_config as trust_config
from ai_contained.trust.server.trust_config import RoleSet, TrustConfig


def describe_RoleSet() -> None:
    def describe_permits() -> None:
        def it_allows_only_listed_roles() -> None:
            result = RoleSet({"shell"}, set())
            assert_that(result.permits("shell")).is_true()
            assert_that(result.permits("aws")).is_false()

        def it_denies_a_role_that_is_explicitly_blocked() -> None:
            result = RoleSet({"shell", "aws"}, {"shell"})
            assert_that(result.permits("shell")).is_false()
            assert_that(result.permits("aws")).is_true()

        def it_allows_any_role_when_wildcard_is_set() -> None:
            result = RoleSet({"*"}, {"shell"})
            assert_that(result.permits("shell")).is_false()
            assert_that(result.permits("aws")).is_true()


def describe_TrustConfig() -> None:
    def describe_parser() -> None:
        def it_returns_empty_for_empty_string() -> None:
            assert_that(TrustConfig._parse("")).is_empty()

        def it_grants_wildcard_role_for_plain_hostname() -> None:
            result = TrustConfig._parse("client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"*"}, set())})

        def it_maps_role_to_hostname() -> None:
            result = TrustConfig._parse("shell=client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"shell"}, set())})

        def it_merges_multiple_roles_for_same_hostname() -> None:
            result = TrustConfig._parse("shell=client-hostname,aws=client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"shell", "aws"}, set())})

        def it_denies_a_role_for_hostname_using_bang_prefix() -> None:
            result = TrustConfig._parse("client-hostname,aws=!client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"*"}, {"aws"})})

    def describe_is_hostname_permitted() -> None:
        def it_allows_a_known_hostname() -> None:
            config = TrustConfig("client-hostname")
            assert_that(config.is_hostname_permitted("client-hostname")).is_true()

        def it_denies_an_unknown_hostname() -> None:
            config = TrustConfig("client-hostname")
            assert_that(config.is_hostname_permitted("other-hostname")).is_false()

    def describe_is_role_permitted() -> None:
        def it_allows_an_explicitly_listed_role() -> None:
            config = TrustConfig("shell=client-hostname")
            assert_that(config.is_hostname_permitted("client-hostname")).is_true()
            assert_that(config.is_role_permitted("client-hostname", "shell")).is_true()

        def it_allows_listed_roles_and_denies_unlisted_ones() -> None:
            config = TrustConfig("shell=client-hostname")
            assert_that(config.is_hostname_permitted("client-hostname")).is_true()
            assert_that(config.is_role_permitted("client-hostname", "shell")).is_true()
            assert_that(config.is_role_permitted("client-hostname", "aws")).is_false()

        def it_respects_the_bang_deny_list() -> None:
            config = TrustConfig("client-hostname,aws=!client-hostname")
            assert_that(config.is_hostname_permitted("client-hostname")).is_true()
            assert_that(config.is_role_permitted("client-hostname", "shell")).is_true()
            assert_that(config.is_role_permitted("client-hostname", "aws")).is_false()

    def describe_lookup_hostnames() -> None:
        async def it_returns_the_hostname_whose_forward_dns_matches_the_ip(
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            async def _fake_forward_dns(hostname: str) -> list[str]:
                return {"client-a": ["10.0.0.1"], "client-b": ["10.0.0.2"]}.get(hostname, [])

            monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
            config = TrustConfig("client-a,client-b")
            assert_that(await config.lookup_hostnames("10.0.0.1")).is_equal_to({"client-a"})

        async def it_returns_empty_set_when_no_hostname_resolves_to_the_ip(
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            async def _fake_forward_dns(hostname: str) -> list[str]:
                return ["10.0.0.1"]

            monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
            config = TrustConfig("client-a")
            assert_that(await config.lookup_hostnames("10.0.0.99")).is_empty()

        async def it_returns_all_hostnames_when_multiple_resolve_to_the_same_ip(
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            # Operator deliberately aliases two names to one container — merge, don't error.
            async def _fake_forward_dns(hostname: str) -> list[str]:
                return ["10.0.0.1"]

            monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
            config = TrustConfig("client-a,client-b")
            assert_that(await config.lookup_hostnames("10.0.0.1")).is_equal_to({"client-a", "client-b"})

        async def it_caches_results_to_avoid_repeated_dns_lookups(
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            call_count = 0

            async def _fake_forward_dns(hostname: str) -> list[str]:
                nonlocal call_count
                call_count += 1
                return ["10.0.0.1"]

            monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
            config = TrustConfig("client-a")
            await config.lookup_hostnames("10.0.0.1")
            await config.lookup_hostnames("10.0.0.1")
            assert_that(call_count).is_equal_to(1)

        async def it_refreshes_cache_on_miss_then_returns_match(
            monkeypatch: pytest.MonkeyPatch,
        ) -> None:
            # First call: hostname doesn't resolve yet (client not started).
            # Second call: hostname now resolves — cache must refresh on the miss.
            resolves: dict[str, list[str]] = {"client-a": []}

            async def _fake_forward_dns(hostname: str) -> list[str]:
                return resolves.get(hostname, [])

            monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
            config = TrustConfig("client-a")
            assert_that(await config.lookup_hostnames("10.0.0.1")).is_empty()
            resolves["client-a"] = ["10.0.0.1"]
            assert_that(await config.lookup_hostnames("10.0.0.1")).is_equal_to({"client-a"})

        async def it_clears_cache_on_reset(monkeypatch: pytest.MonkeyPatch) -> None:
            async def _fake_forward_dns(hostname: str) -> list[str]:
                return {"client-a": ["10.0.0.1"], "client-b": ["10.0.0.2"]}.get(hostname, [])

            monkeypatch.setattr(trust_config, "_forward_dns", _fake_forward_dns)
            config = TrustConfig("client-a")
            await config.lookup_hostnames("10.0.0.1")  # populate cache
            config.reset("client-b")
            assert_that(await config.lookup_hostnames("10.0.0.1")).is_empty()
            assert_that(await config.lookup_hostnames("10.0.0.2")).is_equal_to({"client-b"})
