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

    async def post_raw(self, content: bytes, **kwargs) -> bytes:
        """Sign and POST body to the baked-in path, return raw response bytes."""
        return await self._connection.post_raw(self._path, content, **kwargs)

    async def post(self, payload: dict[str, Any], **kwargs) -> Any:
        """Sign and POST payload, decode the response as JSON."""
        headers = kwargs.pop("headers", {})
        headers.setdefault("content-type", "application/json")  # caller may override
        return json.loads(await self.post_raw(json.dumps(payload).encode(), headers=headers, **kwargs))
