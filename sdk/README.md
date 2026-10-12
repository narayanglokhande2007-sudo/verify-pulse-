# VerifyPulse App-Shield SDK

Runtime Application Self-Protection (RASP) client-side module designed for Indian FinTechs, NBFCs, and banking applications.

## Key Capabilities
* **Screen-Sharing / RAT Interception:** Detects active `MediaProjection`, presentation displays, and third-party remote screen capture (AnyDesk, TeamViewer QuickSupport).
* **Accessibility Service Guard:** Identifies untrusted Accessibility Service bindings attempting to harvest OTPs and PINs.
* **Pre-Transaction Drop:** Intercepts network intents locally before OTP submission or payment gateway routing.
* **Zero-PII Telemetry:** Transmits zero user identities; operates exclusively on device posture flags.

## Integration Example (Web / Hybrid / React Native)
```javascript
import { AppShield } from '@verifypulse/app-shield';

const shield = new AppShield({
  apiKey: process.env.VERIFYPULSE_B2B_KEY,
  strictMode: true
});

// Wrap critical payment triggers
async function onPayClick(paymentIntent) {
  const result = await shield.interceptPaymentIntent(paymentIntent, {
    isMediaProjectionActive: window.__NATIVE_MEDIA_PROJECTION_ACTIVE__
  });

  if (!result.allowed) {
    alert("Transaction blocked: Remote screen-sharing or unsafe overlay detected.");
    return;
  }

  // Proceed with safe checkout
  proceedToGateway(result.intent);
}
```

## Native Android Integration
Include `com.verifypulse.appshield.AppShieldManager` in your Android project:
```kotlin
val shield = AppShieldManager.getInstance(context)

// Enforce FLAG_SECURE on OTP & PIN entry screens
shield.enforceWindowSecurity(this)

// Check device environment before UPI payment
val verdict = shield.evaluatePreTransactionPosture()
if (!verdict.isSafe) {
    showSecurityWarningDialog("Screen-sharing application detected. Payment halted.")
}
```
