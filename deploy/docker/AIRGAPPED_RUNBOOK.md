# VerifyPulse Air-Gapped Deployment Runbook

This runbook describes a **deployable architecture**, not proof that a bank environment has already been deployed.

## Offline preparation outside the restricted network

1. Build and scan the pinned VerifyPulse image.
2. Pull and scan the exact Redis image declared in `docker-compose.yml`.
3. Export both images with `docker save` and transfer them through the bank's approved media process.
4. Transfer the repository's historical index pack separately and verify its SHA-256 manifest.
5. Review all environment variables; do not put API keys in the image or compose file.

## Restricted-network validation

```bash
docker load -i verifypulse-engine.tar
docker load -i redis-7-alpine.tar
docker compose -f deploy/docker/docker-compose.yml up -d
curl --fail http://127.0.0.1:3000/api/status
```

## Required production checks

- Redis persistence volume survives a restart.
- The engine returns a bounded `NEEDS_VERIFICATION` result when external providers are unavailable.
- Historical-index freshness and checksum gates pass.
- No outbound network route exists unless the bank explicitly approves one.
- Logs contain metadata only; raw URLs, OTPs, credentials, and message bodies are not persisted.
- The bank completes its own penetration test, disaster-recovery test, and release approval.

Until those checks are completed in the target environment, describe this capability as **air-gapped deployment architecture available for validation**, not as an already-certified deployment.
