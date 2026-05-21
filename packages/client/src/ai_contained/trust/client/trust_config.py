"""TrustConfig — builds and holds TrustClient instances parsed from TRUST_SERVERS."""

import os

from ai_contained.trust.client.trust_client import TrustClient


class DuplicateSourceError(ValueError):
    def __init__(self, role: str) -> None:
        display = "wildcard" if role == "*" else f"role {role!r}"
        super().__init__(f"duplicate {display} in TRUST_SERVERS")


class TrustConfig:
    """Parsed registry from TRUST_SERVERS — maps role to TrustClient.

    Populated at startup; static for the lifetime of the process.
    Call reset() in tests to reconfigure without reinstantiating.
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

    def __init__(self, trust_servers: str) -> None:
        self._clients: dict[str, TrustClient | None] = {}
        raise NotImplementedError

    def reset(self, trust_servers: str = "") -> None:
        """Reconfigure — intended for use in tests only."""
        raise NotImplementedError

    def get_client(self, role: str) -> TrustClient | None:
        """Return the TrustClient for a role, or None if not configured."""
        raise NotImplementedError


_instance: TrustConfig | None = None


def get_trust_config() -> TrustConfig:
    """Return the process-wide TrustConfig singleton."""
    global _instance
    if _instance is None:
        _instance = TrustConfig(os.environ.get("TRUST_SERVERS", ""))
    return _instance
