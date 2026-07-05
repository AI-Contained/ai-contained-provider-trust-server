"""TrustStore — registry of trusted clients.

Clients register once via POST /trust/register, providing their Ed25519 signing key
and Curve25519 encryption key. Registration is gated by IP address — one registration
per client IP is permitted. Subsequent requests are authenticated by verifying the
Ed25519 signature against the stored signing key.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from ai_contained.trust.server.trust_config import RoleSet

# Union type for both IPv4 and IPv6 client addresses.
IPAddress = IPv4Address | IPv6Address


@dataclass(frozen=True)
class RegisteredClient:
    """Public keys and roles for a registered client.

    frozen=True: keys are immutable after registration — a client cannot
    re-register from the same IP with different keys.
    """

    roles: RoleSet  # permitted roles for this client
    signing_public_key: str  # Ed25519 verify key — used to authenticate each request
    encryption_public_key: str  # Curve25519 public key — used to encrypt responses


class TrustStore:
    """In-memory registry of clients that have completed key exchange.

    Keyed by client IP address — enforces one registration per IP.
    One instance per TrustServer; tests construct fresh ones.
    """

    def __init__(self) -> None:
        """Initialize an empty client registry."""
        self._clients: dict[IPAddress, RegisteredClient] = {}
