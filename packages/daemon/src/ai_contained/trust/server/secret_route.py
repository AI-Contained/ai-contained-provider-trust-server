"""secret_route — decorator that registers a signed, encrypted secret endpoint."""

import inspect
import re
import time
from collections.abc import Awaitable, Callable
from ipaddress import ip_address

import nacl.exceptions
import nacl.public
import nacl.signing
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ai_contained.trust.server.trust_store import get_trust_store

Handler = Callable[[Request], Awaitable[Response]]

_now = time.time

_AUTH_RE = re.compile(r'^Signature keyId="Ed25519",created_ts="(\d+)",signature="([0-9a-f]+)"$')


def secret_route(
    mcp: FastMCP,
    role: str,
    path: str | None = None,
    clock_skew_seconds: int = 30,
) -> Callable[[Handler], Handler]:
    """Register a custom MCP route that enforces trust authentication and encrypts responses."""
    resolved_path = path if path is not None else f"/{role}/secret"

    def decorator(fn: Handler) -> Handler:

        @mcp.custom_route(resolved_path, methods=["POST"])
        async def handler(request: Request) -> Response:
            store = get_trust_store()
            # 1. Look up client by IP — 401 if unregistered
            if request.client is None:
                return JSONResponse({"code": "UNREGISTERED"}, status_code=401)
            client_ip = ip_address(request.client.host)
            client = store._clients.get(client_ip)
            if client is None:
                return JSONResponse({"code": "UNREGISTERED"}, status_code=401)

            # 2. Check role before verifying signature — cheap fast-fail
            if not client.roles.permits(role):
                return JSONResponse({"code": "FORBIDDEN"}, status_code=403)

            # 3. Parse Authorization: Signature keyId="Ed25519",created_ts="<unix_s>",signature="<hex>"
            match = _AUTH_RE.match(request.headers.get("authorization", ""))
            if not match:
                return JSONResponse({"code": "INVALID_AUTHORIZATION"}, status_code=401)
            try:
                created_ts = int(match.group(1))
                signature = bytes.fromhex(match.group(2))
            except ValueError:
                return JSONResponse({"code": "INVALID_AUTHORIZATION"}, status_code=401)

            # 3a. Reject requests outside the allowed time window
            if abs(_now() - created_ts) > clock_skew_seconds:
                return JSONResponse({"code": "REQUEST_EXPIRED"}, status_code=401)

            # 4. Verify Ed25519 signature over created_ts + "\n" + body — 401 if invalid
            try:
                body = await request.body()
                verify_key = nacl.signing.VerifyKey(bytes.fromhex(client.signing_public_key))
                verify_key.verify(f"{created_ts}\n".encode() + body, signature)
            except (nacl.exceptions.BadSignatureError, ValueError):
                return JSONResponse({"code": "INVALID_SIGNATURE"}, status_code=401)

            # Inspect at decoration time — avoids TypeError when handler expects payload arg.
            # Payload decoding + content-type enforcement not yet implemented.
            response = await fn(request, None) if len(inspect.signature(fn).parameters) > 1 else await fn(request)

            x_trust = response.headers.get("x-trust-secret")
            should_encrypt = x_trust == "encrypt" or (response.status_code == 200 and x_trust != "plaintext")

            # Strip content-length so Starlette recomputes it for the new body
            headers = {
                k: v for k, v in response.headers.items() if k.lower() not in ("x-trust-secret", "content-length")
            }

            if should_encrypt:
                content: bytes = nacl.public.SealedBox(
                    nacl.public.PublicKey(bytes.fromhex(client.encryption_public_key))
                ).encrypt(bytes(response.body))
                headers["x-trust-secret"] = "encrypt"
            else:
                content = bytes(response.body)
                headers["x-trust-secret"] = "plaintext"

            return Response(content=content, status_code=response.status_code, headers=headers)

        return handler

    return decorator
