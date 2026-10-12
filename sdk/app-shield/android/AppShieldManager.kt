package com.verifypulse.appshield

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.content.Context
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.view.WindowManager
import android.view.accessibility.AccessibilityManager

/**
 * VerifyPulse App-Shield Android RASP (Runtime Application Self-Protection) Module.
 * Detects real-time AnyDesk/TeamViewer screen-sharing and accessibility trojans.
 */
class AppShieldManager private constructor(private val context: Context) {

    companion object {
        @Volatile
        private var instance: AppShieldManager? = null

        fun getInstance(context: Context): AppShieldManager {
            return instance ?: synchronized(this) {
                instance ?: AppShieldManager(context.applicationContext).also { instance = it }
            }
        }
    }

    /**
     * Enforces FLAG_SECURE on sensitive activity windows (e.g. OTP, UPI PIN entry screens)
     * preventing screenshots, screen mirroring, and recording overlays.
     */
    fun enforceWindowSecurity(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    /**
     * Inspects active displays to check if virtual displays (MediaProjection / Casting) are active.
     */
    fun isScreenSharingOrMirroringActive(): Boolean {
        val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager ?: return false
        val displays = displayManager.displays
        for (display in displays) {
            // Check for virtual or presentation displays used by screen-capture trojans
            if (display.flags and DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR != 0 ||
                display.flags and DisplayManager.VIRTUAL_DISPLAY_FLAG_PRESENTATION != 0) {
                return true
            }
        }
        return false
    }

    /**
     * Scans currently enabled Accessibility Services on the device.
     * Flags third-party untrusted services attempting to read window content.
     */
    fun hasUntrustedAccessibilityServices(trustedPackagePrefixes: List<String> = listOf("com.google.android.marvin.talkback")): Boolean {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager ?: return false
        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)

        for (service in enabledServices) {
            val servicePackage = service.resolveInfo.serviceInfo.packageName
            val isTrusted = trustedPackagePrefixes.any { servicePackage.startsWith(it) }
            if (!isTrusted) {
                // Untrusted third-party accessibility service bound (e.g. RATs or overlay malware)
                return true
            }
        }
        return false
    }

    /**
     * Evaluates comprehensive device posture before executing high-risk financial intents.
     */
    fun evaluatePreTransactionPosture(): PostureVerdict {
        val isScreenSharing = isScreenSharingOrMirroringActive()
        val hasUntrustedAccess = hasUntrustedAccessibilityServices()
        val isSafe = !isScreenSharing && !hasUntrustedAccess

        return PostureVerdict(
            isSafe = isSafe,
            isScreenSharingActive = isScreenSharing,
            isAccessibilityCompromised = hasUntrustedAccess,
            recommendation = if (isSafe) "ALLOW_PAYMENT" else "ABORT_PAYMENT_DROPPED_BY_RASP"
        )
    }
}

data class PostureVerdict(
    val isSafe: Boolean,
    val isScreenSharingActive: Boolean,
    val isAccessibilityCompromised: Boolean,
    val recommendation: String
)
