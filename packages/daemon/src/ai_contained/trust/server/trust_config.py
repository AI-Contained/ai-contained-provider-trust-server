"""TrustConfig — allowlist of permitted clients parsed from TRUST_CLIENTS."""

import asyncio
import os
import socket
from dataclasses import dataclass


async def _forward_dns(hostname: str) -> list[str]:
    """Forward-resolve a hostname to its IP addresses (empty list on failure).

    Exposed at module level so tests can monkeypatch it.
    """
    loop = asyncio.get_running_loop()
    try:
        _, _, ips = await loop.run_in_executor(None, socket.gethostbyname_ex, hostname)
        return ips
    except socket.gaierror:
        return []


@dataclass
class RoleSet:
    """Mutable set of allowed and denied roles for a client."""

    allowed: set[str]  # explicit roles, or {"*"} for wildcard
    denied: set[str]  # explicitly blocked roles

    def permits(self, role: str) -> bool:
        """Return True if role is allowed and not denied."""
        if role in self.denied:
            return False
        return "*" in self.allowed or role in self.allowed


class TrustConfig:
    """Parsed allowlist from TRUST_CLIENTS — maps hostname to RoleSet.

    Populated at startup; static for the lifetime of the server.
    Call reset() in tests to reconfigure without reinstantiating.
    """

    @staticmethod
    def _parse(raw: str) -> dict[str, RoleSet]:
        """Parse a comma-separated role=hostname string into {hostname: RoleSet}.

        - "" or "none" → {}
        - "client-hostname" (no "=") → {"client-hostname": RoleSet({"*"}, set())}
        - "shell=client-hostname" → {"client-hostname": RoleSet({"shell"}, set())}
        - multiple roles for same hostname are merged into one RoleSet
        """
        if not raw or raw == "none":
            return {}
        result: dict[str, RoleSet] = {}
        for token in raw.split(","):
            token = token.strip()
            if not token:
                continue
            if "=" in token:
                role, hostname = token.split("=", 1)
                denied = hostname.startswith("!")
                hostname = hostname.lstrip("!")
            else:
                role, hostname, denied = "*", token, False
            if hostname not in result:
                result[hostname] = RoleSet(set(), set())
            if denied:
                result[hostname].denied.add(role)
            else:
                result[hostname].allowed.add(role)
        return result

    def __init__(self, trust_clients: str) -> None:
        """Parse TRUST_CLIENTS and build the hostname→RoleSet allowlist."""
        self._permitted: dict[str, RoleSet] = self._parse(trust_clients)
        self._ip_cache: dict[str, set[str]] = {}

    def reset(self, trust_clients: str = "") -> None:
        """Reconfigure the allowlist — intended for use in tests only."""
        self._permitted = self._parse(trust_clients)
        self._ip_cache = {}

    def is_hostname_permitted(self, hostname: str) -> bool:
        """Return True if the hostname appears in the allowlist."""
        return hostname in self._permitted

    def is_role_permitted(self, hostname: str, role: str) -> bool:
        """Return True if the hostname is permitted and its RoleSet allows the role."""
        role_set = self._permitted.get(hostname, None)
        return role_set is not None and role_set.permits(role)

    async def lookup_hostnames(self, ip: str) -> set[str]:
        """Return all TRUST_CLIENTS hostnames that forward-resolve to this IP.

        Uses a lazy ip→hostnames cache. On a miss, refreshes the cache by
        forward-resolving every configured hostname and retries.
        Returns an empty set if no allowlisted hostname maps to this IP.
        """
        if ip in self._ip_cache:
            return self._ip_cache[ip]
        await self._refresh_ip_cache()
        return self._ip_cache.get(ip, set())

    async def _refresh_ip_cache(self) -> None:
        new_cache: dict[str, set[str]] = {}
        for hostname in self._permitted:
            for resolved_ip in await _forward_dns(hostname):
                new_cache.setdefault(resolved_ip, set()).add(hostname)
        self._ip_cache = new_cache


_instance: TrustConfig | None = None


def get_trust_config() -> TrustConfig:
    """Return the process-wide TrustConfig singleton."""
    global _instance
    if _instance is None:
        _instance = TrustConfig(os.environ.get("TRUST_CLIENTS", ""))
    return _instance
