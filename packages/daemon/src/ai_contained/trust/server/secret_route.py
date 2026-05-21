import re
from collections.abc import Callable, Coroutine
from ipaddress import ip_address

import nacl.exceptions
import nacl.public
import nacl.signing
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ai_contained.trust.server.trust_store import get_trust_store

Handler = Callable[[Request], Coroutine[None, None, Response]]

_AUTH_RE = re.compile(r'^Signature keyId="Ed25519",signature="([0-9a-f]+)"$')


def secret_route(
    mcp: FastMCP,
    path: str,
    methods: list[str],
    role: str,
) -> Callable[[Handler], Handler]:
    def decorator(fn: Handler) -> Handler:

        @mcp.custom_route(path, methods=methods)
        async def handler(request: Request) -> Response:
            store = get_trust_store()
            # 1. Look up client by IP — 401 if unregistered
            client_ip = ip_address(request.client.host)
            client = store._clients.get(client_ip)
            if client is None:
                return JSONResponse({"code": "UNREGISTERED"}, status_code=401)

            # 2. Check role before verifying signature — cheap fast-fail
            if not client.roles.permits(role):
                return JSONResponse({"code": "FORBIDDEN"}, status_code=403)

            # 3. Parse Authorization: Signature keyId="Ed25519",signature="<hex>"
            match = _AUTH_RE.match(request.headers.get("authorization", ""))
            if not match:
                return JSONResponse({"code": "INVALID_AUTHORIZATION"}, status_code=401)
            try:
                signature = bytes.fromhex(match.group(1))
            except ValueError:
                return JSONResponse({"code": "INVALID_AUTHORIZATION"}, status_code=401)

            # 4. Verify Ed25519 signature over request body — 401 if invalid
            try:
                body = await request.body()
                nacl.signing.VerifyKey(bytes.fromhex(client.signing_public_key)).verify(body, signature)
            except (nacl.exceptions.BadSignatureError, ValueError):
                return JSONResponse({"code": "INVALID_SIGNATURE"}, status_code=401)

            response = await fn(request)

            x_trust = response.headers.get("x-trust-secret")
            should_encrypt = x_trust == "encrypt" or (response.status_code == 200 and x_trust != "plaintext")

            # Strip content-length so Starlette recomputes it for the new body
            headers = {k: v for k, v in response.headers.items() if k.lower() not in ("x-trust-secret", "content-length")}

            if should_encrypt:
                content = nacl.public.SealedBox(
                    nacl.public.PublicKey(bytes.fromhex(client.encryption_public_key))
                ).encrypt(response.body)
                headers["x-trust-secret"] = "encrypt"
            else:
                content = response.body
                headers["x-trust-secret"] = "plaintext"

            return Response(content=content, status_code=response.status_code, headers=headers)

        return handler

    return decorator
