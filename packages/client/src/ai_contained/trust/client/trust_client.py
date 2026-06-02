"""TrustClient — role-aware secret fetcher backed by a TrustConnection."""

import json
from dataclasses import dataclass
from typing import Any

from ai_contained.trust.client.trust_connection import TrustConnection


@dataclass
class TrustClient:
    """Tool-facing client for a single role. Wraps a shared TrustConnection with a baked-in path."""

    _connection: TrustConnection
    _path: str

    async def post_raw(self, body: bytes) -> bytes:
        """Sign and POST body to the baked-in path, return raw response bytes."""
        return await self._connection.post_raw(self._path, body)

    async def post(self, payload: dict[str, Any]) -> Any:
        """Sign and POST payload, decode the response as JSON."""
        return json.loads(await self.post_raw(json.dumps(payload).encode()))
