# VerifyPulse B2B API Security Setup

## Purpose

The B2B scan endpoint, `POST /api/v1/scan`, now requires a server-managed API key and applies a per-client rate limit. Keys are **not** stored in GitHub or browser code. The deployed service stores only SHA-256 hashes of permitted keys in its environment configuration.

## Required deployment configuration

| Variable | Required | Example value | Purpose |
|---|---:|---|---|
| `VERIFYPULSE_B2B_API_KEY_HASHES` | Legacy mode only | `a1b2...64-hex-characters` | Comma-separated SHA-256 hashes of approved keys. Maintained for compatibility; it provides no tenant identity, expiry, or scope. |
| `VERIFYPULSE_B2B_KEY_REGISTRY` | Recommended for enterprise | JSON registry, documented below | Scoped, tenant-labelled, expiring, revocable SHA-256 key records. When set, it takes precedence and fails closed if invalid. |
| `VERIFYPULSE_VERIFY_RATE_LIMIT_MAX` | No | `20` | Maximum verification requests per client IP per minute. Default: `20`. |
| `VERIFYPULSE_B2B_RATE_LIMIT_MAX` | No | `20` | Maximum B2B scan requests per client IP per minute. Default: `20`. |
| `VERIFYPULSE_B2B_ALLOWED_ORIGINS` | Only for browser integrations | `https://partner.example,https://portal.example` | Comma-separated browser origins permitted to call the B2B API. Server-to-server calls do not need this variable. |

## Create a B2B API key safely

Generate a high-entropy key on a trusted device or in a secure password manager. Do not use a predictable sample such as `VP-DEMO-123`, do not place the raw key in source code, and do not send it in a URL query parameter.

Use the key only in the `X-API-Key` request header. The service also accepts `Authorization: Bearer <key>` for server-to-server clients.

To calculate the SHA-256 value to place in `VERIFYPULSE_B2B_API_KEY_HASHES`, run the following command locally, replacing the placeholder only on a trusted device:

```bash
printf %s 'YOUR_HIGH_ENTROPY_B2B_KEY' | sha256sum
```

Copy only the 64-character hash to the deployment environment. Store the raw key separately in an approved secret manager or password manager and share it only with an authorised customer over an appropriate secure channel.

## API request format

```bash
curl -X POST 'https://www.verify-pulse.com/api/v1/scan' \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: YOUR_B2B_KEY' \
  --data '{"url":"https://example.com"}'
```

The endpoint returns `401` for a missing, expired, revoked, or invalid key, `403` for an authenticated key without the required scope, `429` if the rate limit is exceeded, and `503` when B2B authentication has not yet been configured. It deliberately does not reveal whether a particular key exists.

## Limits and scaling

The initial rate limiter is in-memory. It protects a single running serverless instance, but distributed deployments can have more than one instance. Before high-volume enterprise traffic, replace or augment it with a shared atomic rate-limit store such as managed Redis or a platform-supported KV service.

## Enterprise scoped key registry (recommended)

Configure `VERIFYPULSE_B2B_KEY_REGISTRY` as a JSON array in the deployment secret manager. It must contain **only hashes**, never raw keys:

```json
[
  {
    "keyId": "iitr-pilot-2026",
    "tenantId": "iitr",
    "sha256": "PUT_64_CHARACTER_SHA256_HASH_HERE",
    "scopes": ["b2b:scan"],
    "expiresAt": "2027-03-31T23:59:59.000Z",
    "status": "active"
  }
]
```

Enterprise registry requests must include both headers:

```text
X-API-Key: RAW_KEY_FROM_APPROVED_SECRET_MANAGER
X-VerifyPulse-Key-Id: iitr-pilot-2026
```

The current scan endpoint requires the `b2b:scan` scope. Set `status` to `revoked` (or remove the record and redeploy) to immediately disable a key. Give every tenant a separate key record, bounded expiry, and least-privilege scope.

## Key rotation

For the scoped registry, add a new key record with a distinct key ID and expiry, migrate the tenant, then mark the old record `revoked` and redeploy. For legacy mode, keep the old and new hashes together in `VERIFYPULSE_B2B_API_KEY_HASHES`, separated by commas. Rotate immediately if a raw key may have been exposed.

## Correlation and audit evidence

Every B2B response returns `X-VerifyPulse-Correlation-Id` and `correlation_id`. Privacy-safe structured audit events record only correlation ID, tenant ID, key ID, scope, outcome, status, and error code. They deliberately exclude raw scan content, URLs, API keys, IP addresses, credentials, and personal identifiers.

## Browser integrations

Browser-based B2B clients are permitted only if their exact origin is listed in `VERIFYPULSE_B2B_ALLOWED_ORIGINS`. Avoid exposing long-lived B2B keys in frontend JavaScript. Prefer server-to-server integrations or short-lived credentials issued by a dedicated authentication service.
