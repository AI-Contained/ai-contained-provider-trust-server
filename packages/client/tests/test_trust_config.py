from assertpy import assert_that

from ai_contained.trust import client as trust_client


def describe_TrustConfig() -> None:
    def describe_parse() -> None:
        def it_returns_empty_for_empty_string() -> None:
            assert_that(trust_client.TrustConfig._parse("")).is_empty()

        def it_maps_bare_url_to_wildcard() -> None:
            assert_that(trust_client.TrustConfig._parse("http://server:8080")).is_equal_to(
                {"*": "http://server:8080"}
            )

        def it_maps_role_to_url() -> None:
            assert_that(trust_client.TrustConfig._parse("aws=http://aws:8080")).is_equal_to(
                {"aws": "http://aws:8080"}
            )

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
