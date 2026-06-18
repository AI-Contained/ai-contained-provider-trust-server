"""trust_register endpoint — one-time key exchange between client and trust server.

Clients POST their Ed25519 signing key and Curve25519 encryption key.
The server stores them keyed by client IP, enforcing one registration per IP.
A second attempt from the same IP is rejected with HTTP 401.
"""

import json
from ipaddress import ip_address

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ai_contained.trust.server.trust_config import RoleSet, get_trust_config
from ai_contained.trust.server.trust_store import RegisteredClient, get_trust_store


async def register(mcp: FastMCP) -> None:
    """Register the /trust/register endpoint with the MCP server."""
    store = get_trust_store()

    @mcp.custom_route("/trust/register", methods=["POST"])
    async def trust_register(request: Request) -> Response:
        # IP check first — if already registered, don't process a potentially poisoned payload
        if request.client is None:
            return JSONResponse({"code": "FORBIDDEN"}, status_code=401)
        client_ip = ip_address(request.client.host)
        if client_ip in store._clients:
            return JSONResponse({"code": "ALREADY_REGISTERED"}, status_code=401)

        # Forward-DNS lookup — find every TRUST_CLIENTS hostname whose A-record matches client_ip.
        # Multiple matches are merged (operator deliberately aliased names to the same container).
        config = get_trust_config()
        hostnames = await config.lookup_hostnames(str(client_ip))
        if not hostnames:
            return JSONResponse({"code": "FORBIDDEN"}, status_code=401)
        merged_roles = RoleSet(allowed=set(), denied=set())
        for hostname in hostnames:
            role_set = config._permitted[hostname]
            merged_roles.allowed |= role_set.allowed
            merged_roles.denied |= role_set.denied

        if "application/json" not in request.headers.get("content-type", ""):
            return JSONResponse({"code": "INVALID_CONTENT_TYPE"}, status_code=400)

        try:
            body = json.loads(await request.body())
        except json.JSONDecodeError as e:
            return JSONResponse({"code": "INVALID_JSON", "detail": str(e)}, status_code=400)

        keys: dict[str, str] = {}
        for field in ("signing_public_key", "encryption_public_key"):
            value = body.get(field)
            if not isinstance(value, str):
                return JSONResponse(
                    {"code": "INVALID_KEY", "detail": f"{field}: missing or not a string"},
                    status_code=400,
                )
            try:
                bytes.fromhex(value)
            except ValueError as e:
                return JSONResponse({"code": "INVALID_KEY", "detail": f"{field}: {e}"}, status_code=400)
            keys[field] = value

        store._clients[client_ip] = RegisteredClient(
            roles=merged_roles,
            signing_public_key=keys["signing_public_key"],
            encryption_public_key=keys["encryption_public_key"],
        )
        return Response(status_code=200)
