# VerifyPulse App-Shield

App-Shield is a client-side posture interceptor for payment or other high-risk flows. It can **block a client action when the host application supplies a trusted signal** that screen sharing, display capture, or an untrusted accessibility service is active.

## Current capabilities

- JavaScript SDK export: `AppShield`
- `interceptPaymentIntent()` returns an explicit allow/drop decision
- Optional strict mode throws on a detected unsafe posture
- Android source includes `FLAG_SECURE`, virtual-display checks, and accessibility-service checks
- No OTP, PIN, card data, or raw transaction content is sent by the SDK

## Important boundary

The SDK is **not a complete device-security guarantee**. It cannot prove that a device is clean, and its signal quality depends on the native bridge or host application. A bank must independently validate the Android/iOS integration, permissions, false positives, and release build before production use.

## JavaScript usage

```js
import { AppShield } from '@verifypulse/app-shield';

const shield = new AppShield({ strictMode: true });
const decision = await shield.interceptPaymentIntent(
  { transactionId: 'opaque-reference-only' },
  { isMediaProjectionActive: false }
);

if (!decision.allowed) {
  // Stop the payment flow and ask the user to close the remote-control session.
}
```

## Validation status

The repository has deterministic JavaScript tests for the interceptor. A production SDK claim still requires a signed Android/iOS build, device matrix testing, host-app integration testing, and an independent security review.
