"""TrustConnection — low-level key exchange and signed HTTP with a trust server."""

import json
import time
from typing import Any

import httpx
import nacl.public
import nacl.signing

_now = time.time


class TrustConnection:
    """Generates ephemeral keypairs and registers with a trust server.

    Keypairs are generated once at instantiation and held in memory only —
    never written to disk, never passed to subprocesses.

    - Ed25519 SigningKey: signs outgoing requests (authentication)
    - Curve25519 PrivateKey: decrypts incoming responses (confidentiality)
    """

    def __init__(self, http: httpx.AsyncClient) -> None:
        """Wrap an async HTTP client with fresh ephemeral keypairs."""
        self._http = http
        self._signing_key = nacl.signing.SigningKey.generate()
        self._private_key = nacl.public.PrivateKey.generate()

    async def register(self) -> bool:
        """POST public keys to /trust/register.

        Returns:
            True  — successfully registered (HTTP 200)
            False — already registered from this IP (HTTP 401)

        Raises:
            httpx.HTTPStatusError: unexpected response — indicates misconfiguration.
                                   Includes server URL and response body for debugging.

        """
        response = await self._http.post(
            "/trust/register",
            json={
                "signing_public_key": self._signing_key.verify_key.encode().hex(),
                "encryption_public_key": bytes(self._private_key.public_key).hex(),
            },
        )
        if response.status_code == 200:
            return True
        if response.status_code == 401:
            return False
        response.raise_for_status()
        raise RuntimeError("unreachable")

    async def post_raw(self, path: str, payload: dict[str, Any]) -> bytes:
        """Sign and POST payload, decrypt and return the response body."""
        body = json.dumps(payload).encode()
        created_ts = str(int(_now()))

        # 1. Sign created_ts + "\n" + body — binds the timestamp to the payload
        signature = self._signing_key.sign(f"{created_ts}\n".encode() + body).signature

        # 2. POST payload with Authorization: Signature keyId="Ed25519",created_ts="<unix_s>",signature="<hex>"
        response = await self._http.post(
            path,
            content=body,
            headers={
                "content-type": "application/json",
                "authorization": f'Signature keyId="Ed25519",created_ts="{created_ts}",signature="{signature.hex()}"',
            },
        )

        # 3. Decrypt response body if X-Trust-Secret: encrypt, or http-200 and X-Trust-Secret absent
        x_trust = response.headers.get("x-trust-secret")
        should_decrypt = x_trust == "encrypt" or (x_trust is None and response.status_code == 200)

        content = response.content
        if should_decrypt:
            content = nacl.public.SealedBox(self._private_key).decrypt(content)

        # 4. Raise httpx.HTTPStatusError on non-200
        if response.status_code != 200:
            raise httpx.HTTPStatusError(
                f"{response.status_code}",
                request=response.request,
                response=httpx.Response(
                    status_code=response.status_code,
                    content=content,
                    request=response.request,
                ),
            )

        # 5. Return plaintext bytes
        return content
