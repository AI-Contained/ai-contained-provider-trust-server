from assertpy import assert_that

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
