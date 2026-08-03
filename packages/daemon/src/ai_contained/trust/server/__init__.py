"""Trust server provider."""

from collections.abc import Callable

from fastmcp import FastMCP

from ai_contained.core.mcp import ProviderContext
from ai_contained.trust.server import secret_route as _secret_route
from ai_contained.trust.server import trust_register as _trust_register
from ai_contained.trust.server.secret_route import Handler
from ai_contained.trust.server.trust_config import TrustConfig
from ai_contained.trust.server.trust_store import TrustStore


class TrustServer:
    """The trust provider's state: the store and client allowlist behind /trust/register.

    Dependent providers mount their secret endpoints through it::

        trust = await ctx.ensure(trust_server.provide)

        @trust.secret_route(role="aws")
        async def aws_secret(request: Request) -> Response: ...
    """

    def __init__(self, mcp: FastMCP, store: TrustStore, config: TrustConfig) -> None:
        """Hold the wired store/config and the server secret routes mount onto."""
        self._mcp = mcp
        self._store = store
        self._config = config

    def secret_route(
        self, role: str, path: str | None = None, clock_skew_seconds: int = 30
    ) -> Callable[[Handler], Handler]:
        """Register a custom MCP route that enforces trust authentication and encrypts responses."""
        return _secret_route.secret_route(self._mcp, self._store, role, path, clock_skew_seconds)


async def provide(ctx: ProviderContext) -> TrustServer:
    """Mount /trust/register (allowlist from TRUST_CLIENTS) and share the TrustServer state."""
    store = TrustStore()
    config = TrustConfig(ctx.environ.get("TRUST_CLIENTS", ""))
    await _trust_register.register(ctx.mcp, store, config)
    return TrustServer(ctx.mcp, store, config)


__all__ = ["TrustServer", "provide"]
