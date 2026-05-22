"""TrustConfig — builds and holds TrustClient instances parsed from TRUST_SERVERS."""

import logging
import time
from collections.abc import Callable

import httpx
from fastmcp.utilities.logging import get_logger

_sleep = time.sleep  # exposed for monkeypatching in tests
_log: logging.Logger = get_logger("trust.client")

from ai_contained.trust.client.trust_client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection

HttpClientFactory = Callable[[httpx.URL], httpx.Client]


def _default_http_client_factory(url: httpx.URL) -> httpx.Client:
    return httpx.Client(base_url=url)


class DuplicateSourceError(ValueError):
    def __init__(self, role: str) -> None:
        display = "wildcard" if role == "*" else f"role {role!r}"
        super().__init__(f"duplicate {display} in TRUST_SERVERS")


def _register_clients(
    parsed: dict[str, str | None],
    factory: HttpClientFactory,
    max_retries: int = 5,
) -> dict[str, TrustClient | None]:
    by_url: dict[str, TrustConnection] = {}
    clients: dict[str, TrustClient | None] = {}

    for role, url in parsed.items():
        if url is None:
            _log.info("role %r: explicitly denied", role)
            clients[role] = None
            continue

        parsed_url = httpx.URL(url)
        key = f"{parsed_url.host}:{parsed_url.port}"

        if key not in by_url:
            _log.info("connecting to %s", key)
            conn = TrustConnection(factory(parsed_url))
            for attempt in range(1, max_retries + 1):
                try:
                    conn.register()
                    _log.info("registered with %s", key)
                    break
                except httpx.ConnectError as e:
                    if attempt == max_retries:
                        _log.error("failed to connect to %s after %d attempts: %s", key, max_retries, e)
                        raise
                    delay = 2 ** (attempt - 1)
                    _log.warning("attempt %d/%d failed for %s, retrying in %ds", attempt, max_retries, key, delay)
                    _sleep(delay)
            by_url[key] = conn

        path = parsed_url.path or f"/{role}/secret"
        clients[role] = TrustClient(_connection=by_url[key], _path=path)

    return clients


class TrustConfig:
    """Parsed registry from TRUST_SERVERS — maps role to TrustClient.

    Populated at startup; static for the lifetime of the process.
    """

    @staticmethod
    def _parse(raw: str) -> dict[str, str | None]:
        """Parse a comma-separated [role=]url string into {role: url | None}.

        - "" → {}
        - "http://server:8080" (no "=") → {"*": "http://server:8080"}
        - "aws=http://server:8080" → {"aws": "http://server:8080"}
        - "aws=" → {"aws": None}  (explicit deny)
        """
        if not raw:
            return {}
        result: dict[str, str | None] = {}
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            elif "=" in token:
                role, raw_url = token.split("=", 1)
                url: str | None = raw_url if raw_url else None
            else:
                role, url = "*", token

            if role in result:
                raise DuplicateSourceError(role)
            result[role] = url
        return result

    def __init__(self, trust_servers: str, factory: HttpClientFactory) -> None:
        self._clients = _register_clients(self._parse(trust_servers), factory)

    def get_client(self, role: str) -> TrustClient | None:
        """Return the TrustClient for a role — falls back to wildcard '*' if role not explicitly configured."""
        return self._clients.get(role, self._clients.get("*", None))


_instance: TrustConfig | None = None


def get_trust_config() -> TrustConfig | None:
    """Return the process-wide TrustConfig singleton, or None if not yet initialized."""
    return _instance


def init_trust_config(raw: str, factory: HttpClientFactory = _default_http_client_factory) -> TrustConfig:
    """Initialize (or reinitialize) the process-wide TrustConfig singleton."""
    global _instance
    if _instance is not None:
        _instance = None
    _instance = TrustConfig(raw, factory)
    return _instance


def reset_trust_config() -> None:
    """Reset the singleton to None. Not part of the public API — intended for test teardown."""
    global _instance
    _instance = None
