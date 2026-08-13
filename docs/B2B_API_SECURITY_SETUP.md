# VerifyPulse B2B API Security Setup

## Purpose

The B2B scan endpoint, `POST /api/v1/scan`, now requires a server-managed API key and applies a per-client rate limit. Keys are **not** stored in GitHub or browser code. The deployed service stores only SHA-256 hashes of permitted keys in its environment configuration.

## Required deployment configuration

| Variable | Required | Example value | Purpose |
|---|---:|---|---|
| `VERIFYPULSE_B2B_API_KEY_HASHES` | Yes | `a1b2...64-hex-characters` | Comma-separated SHA-256 hashes of approved B2B API keys. Without it, B2B API access fails closed with HTTP `503`. |
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

The endpoint returns `401` for a missing or invalid key, `429` if the rate limit is exceeded, and `503` when B2B authentication has not yet been configured. It deliberately does not reveal whether a particular key exists.

## Limits and scaling

The initial rate limiter is in-memory. It protects a single running serverless instance, but distributed deployments can have more than one instance. Before high-volume enterprise traffic, replace or augment it with a shared atomic rate-limit store such as managed Redis or a platform-supported KV service.

## Key rotation

During rotation, keep the old and new key hashes together in `VERIFYPULSE_B2B_API_KEY_HASHES`, separated by commas. After authorised clients have moved to the new key, remove the old hash and redeploy. Rotate immediately if a raw key may have been exposed.

## Browser integrations

Browser-based B2B clients are permitted only if their exact origin is listed in `VERIFYPULSE_B2B_ALLOWED_ORIGINS`. Avoid exposing long-lived B2B keys in frontend JavaScript. Prefer server-to-server integrations or short-lived credentials issued by a dedicated authentication service.
