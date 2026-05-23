# ai-contained-provider-trust-server

Mutual authentication and encrypted secret delivery between AI-contained services. A **daemon** process brokers secrets; **client** processes prove their identity before receiving them.

---

## How it works

```
Client process                          Daemon process
──────────────────────────────────────────────────────────────
1. init_trust_config(TRUST_SERVERS)
   └─ generates ephemeral Ed25519 + Curve25519 keypairs
   └─ POST /trust/register ──────────────────────────────────►
                                         reverse-DNS lookup
                                         check against TRUST_CLIENTS
                                         store client's public keys, keyed by IP + roles
                              ◄──────────── 200 OK ──────────

2. client.post(payload)
   └─ signs (created_ts + "\n" + body) with Ed25519
   └─ POST /role/secret ────────────────────────────────────►
                                         verify signature
                                         check role
                                         call handler
                                         encrypt response with client pubkey
              ◄──────────── encrypted response ─────────────
   └─ decrypt with Curve25519 private key
```

**Keypairs are ephemeral** — generated at startup, held in memory only, never written to disk. A restarted client gets fresh keys and must re-register.

---

## Packages

| Package | Install name | Use it when |
|---|---|---|
| `packages/daemon` | `ai-contained-provider-trust-server-daemon` | You are building a service that **holds** secrets |
| `packages/client` | `ai-contained-provider-trust-server-client` | You are building a provider that **requests** secrets |

---

## Daemon setup

### 1. Configure `TRUST_CLIENTS`

`TRUST_CLIENTS` is a comma-separated allowlist of which client hostnames may register, and what roles they are permitted to access.

| Value | Meaning |
|---|---|
| `""` | Deny all registrations |
| `provider-hostname` | Allow `provider-hostname` to access any role |
| `shell=provider-hostname` | Allow `provider-hostname` to access the `shell` role only |
| `shell=provider-hostname,aws=provider-hostname` | Allow `provider-hostname` to access `shell` and `aws` |
| `shell=provider-a,aws=provider-b` | Different roles from different hosts |
| `!aws=provider-hostname` | Explicitly deny `provider-hostname` from the `aws` role |

The hostname is matched against the client IP's reverse-DNS result (hostname, aliases, and the raw IP are all checked).

### 2. Register the endpoint and protect a route

```python
from fastmcp import FastMCP
from ai_contained.trust import server as trust_server

mcp = FastMCP("my-service")
trust_server.register(mcp)  # mounts POST /trust/register

@trust_server.secret_route(mcp, role="shell")
async def shell_secret(request: Request) -> Response:
    return JSONResponse({"token": os.environ["SHELL_TOKEN"]})
```

`secret_route` enforces signature verification, role check, and response encryption automatically. Your handler only runs if the client is authenticated and authorised.

**Custom path** (default is `/<role>/secret`):
```python
@trust_server.secret_route(mcp, role="shell", path="/v1/shell/credentials")
async def shell_secret(request: Request) -> Response: ...
```

**Adjusting the clock skew tolerance** (default 30 seconds):
```python
@trust_server.secret_route(mcp, role="shell", clock_skew_seconds=10)
async def shell_secret(request: Request) -> Response: ...
```

---

## Client setup

### 1. Configure `TRUST_SERVERS`

`TRUST_SERVERS` is a comma-separated list of which trust servers to connect to, and which roles they serve.

| Value | Meaning |
|---|---|
| `""` | No trust servers |
| `http://trust-server:8080` | One server handles all roles (wildcard) |
| `shell=http://trust-server:8080` | This server handles the `shell` role |
| `shell=http://trust-server-a:8080,aws=http://trust-server-b:8080` | Different roles via different servers |
| `aws=` | Explicitly deny the `aws` role (no server) |

Multiple roles pointing at the same host share a single connection and registration.

### 2. Initialize and use

```python
from ai_contained.trust.client import init_trust_config, get_trust_config

# At startup — connects and registers with each configured server
await init_trust_config(os.environ["TRUST_SERVERS"])

# Later — get a client for a specific role
config = get_trust_config()
client = config.get_client("shell")  # returns None if role not configured

result = await client.post({"action": "get-credentials"})
```

`client.post()` handles signing, sending, decrypting, and JSON-parsing in one call. Use `client.post_raw()` if you need the raw bytes.

---

## Authorization header format

For reference — you normally never construct this manually:

```
Authorization: Signature keyId="Ed25519",created_ts="<unix_seconds>",signature="<hex>"
```

The signature covers `created_ts + "\n" + request_body`.

---

## Error codes

| Code | Status | Meaning |
|---|---|---|
| `UNREGISTERED` | 401 | Client IP has not registered |
| `ALREADY_REGISTERED` | 401 | A second registration attempt from the same IP |
| `FORBIDDEN` | 401 | IP is not in `TRUST_CLIENTS` |
| `AMBIGUOUS_CONFIG` | 500 | Client IP matches multiple `TRUST_CLIENTS` entries |
| `INVALID_AUTHORIZATION` | 401 | Authorization header missing or malformed |
| `REQUEST_EXPIRED` | 401 | `created_ts` is outside the `±clock_skew_seconds` window |
| `INVALID_SIGNATURE` | 401 | Ed25519 signature does not verify |
| `FORBIDDEN` | 403 | Client is registered but does not have the required role |
| `INVALID_CONTENT_TYPE` | 400 | Content-Type is not `application/json` |
| `INVALID_JSON` | 400 | Request body is not valid JSON |
| `INVALID_KEY` | 400 | A public key is missing, not a hex string, or wrong length |

---

## Known limitations

> **⚠ Read before shipping**
>
> - **Replay within the clock skew window** — a captured request can be replayed up to `clock_skew_seconds` seconds after it was issued. There is no nonce store. For most internal deployments this is acceptable; reduce `clock_skew_seconds` if your threat model requires a tighter window.
>
> - **Role revocation requires a restart** — registered clients hold a live reference to their `RoleSet`. Changing `TRUST_CLIENTS` at runtime does not affect already-registered clients. A daemon restart clears all registrations.
>
> - **One registration per IP** — a client that restarts gets fresh keypairs and cannot re-register until the daemon restarts. This is intentional: it prevents key substitution after compromise.
>
> - **`httpx.AsyncClient` is never explicitly closed** — in production, the client lifecycle ends with the process. This is fine for long-lived services but will produce warnings in short-lived or test contexts.

---

## Development

```bash
# Run all tests
python -m pytest packages/client/tests packages/daemon/tests

# Type check
cd packages/client && python -m mypy src --cache-dir=/tmp/mypy_cache
cd packages/daemon && python -m mypy src --cache-dir=/tmp/mypy_cache

# Lint + format check
RUFF_CACHE_DIR=/tmp/ruff_cache python -m ruff check packages/client/src packages/daemon/src
RUFF_CACHE_DIR=/tmp/ruff_cache python -m ruff format --check packages/client/src packages/daemon/src
```
