"""TrustConfig — role→TrustClient registry, built from TRUST_SERVERS via TrustConfig.create()."""

import asyncio
import logging
from collections.abc import Callable

import httpx
from fastmcp.utilities.logging import get_logger

from ai_contained.trust.client.trust_client import TrustClient
from ai_contained.trust.client.trust_connection import TrustConnection

_sleep = asyncio.sleep  # exposed for monkeypatching in tests
_log: logging.Logger = get_logger("trust.client")

HttpClientFactory = Callable[[httpx.URL], httpx.AsyncClient]


def _default_http_client_factory(url: httpx.URL) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=url)


class DuplicateSourceError(ValueError):
    """Raised when the same role appears more than once in TRUST_SERVERS."""

    def __init__(self, role: str) -> None:
        """Build an error message naming the duplicate role or wildcard."""
        display = "wildcard" if role == "*" else f"role {role!r}"
        super().__init__(f"duplicate {display} in TRUST_SERVERS")


async def _register_clients(
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
            # TODO:  Create an async request to allow the key-exchange to happen in parallel (nice-to-have)
            #        WARNING:  Watch out for issues where the same host is contacted twice
            #                  (it will be rejected by the server)
            _log.info("connecting to %s", key)
            conn = TrustConnection(factory(parsed_url))
            for attempt in range(1, max_retries + 1):
                try:
                    await conn.register()
                    _log.info("registered with %s", key)
                    break
                except httpx.ConnectError as e:
                    if attempt == max_retries:
                        _log.error("failed to connect to %s after %d attempts: %s", key, max_retries, e)
                        raise
                    delay = 2 ** (attempt - 1)
                    _log.warning("attempt %d/%d failed for %s, retrying in %ds", attempt, max_retries, key, delay)
                    await _sleep(delay)
            by_url[key] = conn

        path = f"/{role}/secret" if parsed_url.path == "/" else parsed_url.path
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

    @classmethod
    async def create(cls, raw: str, factory: HttpClientFactory = _default_http_client_factory) -> "TrustConfig":
        """Parse TRUST_SERVERS, register with every trust server, and return the ready TrustConfig.

        The only supported way to build one — this blocks (with retry/backoff)
        until every configured server has accepted our keys, and raises
        httpx.ConnectError if one never does.
        """
        return cls(await _register_clients(cls._parse(raw), factory))

    def __init__(self, clients: dict[str, TrustClient | None]) -> None:
        """Store a pre-built role→TrustClient mapping — internal, use ``await TrustConfig.create(...)``."""
        self._clients = clients

    def get_client(self, role: str) -> TrustClient | None:
        """Return the TrustClient for a role — falls back to wildcard '*' if role not explicitly configured."""
        if role in self._clients:
            return self._clients[role]
        wildcard = self._clients.get("*")
        if wildcard is None:
            return None
        # Wildcard client has _path="/*/secret"; rewrite to the requested role's path so
        # httpx doesn't URL-encode the "*" → "/%2A/secret" → 404 on the server.
        return TrustClient(_connection=wildcard._connection, _path=f"/{role}/secret")
