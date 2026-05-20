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

        def it_returns_empty_for_none_value() -> None:
            assert_that(TrustConfig._parse("none")).is_empty()

        def it_grants_wildcard_role_for_plain_hostname() -> None:
            result = TrustConfig._parse("client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"*"}, set())})

        def it_maps_role_to_hostname() -> None:
            result = TrustConfig._parse("shell=client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"shell"}, set())})

        def it_merges_multiple_roles_for_same_hostname() -> None:
            result = TrustConfig._parse("shell=client-hostname,aws=client-hostname")
            assert_that(result).is_equal_to({"client-hostname": RoleSet({"shell", "aws"}, set())})
