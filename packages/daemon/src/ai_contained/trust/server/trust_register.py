"""trust_register endpoint — one-time key exchange between client and trust server.

Clients POST their Ed25519 signing key and Curve25519 encryption key.
The server stores them keyed by client IP, enforcing one registration per IP.
A second attempt from the same IP is rejected with HTTP 401.
"""

import json
import socket
from ipaddress import ip_address

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ai_contained.trust.server.trust_config import get_trust_config
from ai_contained.trust.server.trust_store import RegisteredClient, get_trust_store


def _reverse_dns(ip: str) -> list[str]:
    """Return all names for an IP: primary hostname, aliases, and the IP itself.
    Always including the IP allows TRUST_CLIENTS to use hostnames or IP addresses interchangeably.
    """
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return [hostname] + aliases + [ip]
    except socket.herror:
        return [ip]


def register(mcp: FastMCP) -> None:
    """Register the /trust/register endpoint with the MCP server."""
    store = get_trust_store()

    @mcp.custom_route("/trust/register", methods=["POST"])
    async def trust_register(request: Request) -> JSONResponse:
        # IP check first — if already registered, don't process a potentially poisoned payload
        client_ip = ip_address(request.client.host)
        if client_ip in store._clients:
            return JSONResponse({"code": "ALREADY_REGISTERED"}, status_code=401)

        # Reverse DNS lookup — check all names (hostname, aliases, IP) against TrustConfig
        config = get_trust_config()
        names = _reverse_dns(str(client_ip))
        matches = [n for n in names if config.is_hostname_permitted(n)]
        if len(matches) == 0:
            return JSONResponse({"code": "FORBIDDEN"}, status_code=401)
        elif len(matches) > 1:
            return JSONResponse({"code": "AMBIGUOUS_CONFIG", "detail": f"{client_ip} matches multiple TRUST_CLIENTS entries: {', '.join(matches)}"}, status_code=500)
        permitted_name = matches[0]

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
                return JSONResponse({"code": "INVALID_KEY", "detail": f"{field}: missing or not a string"}, status_code=400)
            try:
                bytes.fromhex(value)
            except ValueError as e:
                return JSONResponse({"code": "INVALID_KEY", "detail": f"{field}: {e}"}, status_code=400)
            keys[field] = value

        store._clients[client_ip] = RegisteredClient(
            roles=config._permitted[permitted_name],
            signing_public_key=keys["signing_public_key"],
            encryption_public_key=keys["encryption_public_key"],
        )
        return Response(status_code=200)
