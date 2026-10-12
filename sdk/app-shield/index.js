/**
 * VerifyPulse App-Shield Client SDK
 * Runtime Application Self-Protection (RASP) & Real-Time Threat Interceptor
 */

export class AppShield {
  constructor(config = {}) {
    this.apiKey = config.apiKey || '';
    this.keyId = config.keyId || '';
    this.endpoint = config.endpoint || 'https://api.verify-pulse.com';
    this.strictMode = Boolean(config.strictMode);
    this.listeners = new Map();
  }

  /**
   * Evaluates the current device security posture.
   * On mobile environments (React Native / WebView bridges), queries native OS RASP flags.
   */
  async evaluateDevicePosture(telemetry = {}) {
    const isScreenSharingActive = Boolean(
      telemetry.isMediaProjectionActive ||
      telemetry.isDisplayCaptured ||
      (typeof window !== 'undefined' && window.__VERIFYPULSE_SCREEN_SHARED__)
    );

    const hasSuspiciousAccessibility = Boolean(
      telemetry.untrustedAccessibilityBound ||
      (typeof window !== 'undefined' && window.__VERIFYPULSE_ACCESSIBILITY_INTERCEPT__)
    );

    const isDirty = isScreenSharingActive || hasSuspiciousAccessibility;

    const postureReport = {
      isSafe: !isDirty,
      screenSharingDetected: isScreenSharingActive,
      accessibilityAbuseDetected: hasSuspiciousAccessibility,
      action: isDirty ? 'DROP_PAYLOAD' : 'ALLOW_TRANSACTION',
      timestamp: new Date().toISOString()
    };

    if (isDirty) {
      this._emit('threat_intercepted', postureReport);
      if (this.strictMode) {
        throw new Error(
          'VERIFYPULSE_APP_SHIELD_VIOLATION: Transaction dropped due to active screen-sharing or remote overlay.'
        );
      }
    }

    return postureReport;
  }

  /**
   * Pre-transaction interceptor hook.
   * Wraps around the payment intent before submission to payment gateway.
   */
  async interceptPaymentIntent(paymentIntent, deviceTelemetry = {}) {
    const posture = await this.evaluateDevicePosture(deviceTelemetry);
    if (!posture.isSafe) {
      return {
        allowed: false,
        reason: 'UNSAFE_ENVIRONMENT',
        details: posture
      };
    }

    return {
      allowed: true,
      reason: 'ENVIRONMENT_VERIFIED',
      details: posture,
      intent: paymentIntent
    };
  }

  on(event, callback) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event).push(callback);
  }

  _emit(event, data) {
    const callbacks = this.listeners.get(event) || [];
    callbacks.forEach((cb) => cb(data));
  }
}

export default AppShield;
