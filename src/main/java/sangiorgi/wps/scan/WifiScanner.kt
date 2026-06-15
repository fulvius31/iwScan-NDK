package sangiorgi.wps.scan

import android.content.Context
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Scans for Wi-Fi networks over root using a bundled native nl80211 scanner (libiwscan.so), so it
 * works even when the Android Wi-Fi framework is OFF — the state WPS attacks require.
 *
 * Self-contained: root is detected via libsu and the scanner binary ships in this library's
 * jniLibs (run from the host app's nativeLibDir). All calls return empty/false gracefully when
 * root or the binary is unavailable, or the device's driver can't scan with Wi-Fi off.
 */
class WifiScanner(context: Context) {

    private val iwPath: String = File(context.applicationInfo.nativeLibraryDir, SCANNER_LIB).absolutePath

    /** Quick check: the native scanner is present and executable. */
    fun isBinaryAvailable(): Boolean = File(iwPath).let { it.exists() && it.canExecute() }

    /** Whether scanning is possible (binary present and root granted). */
    suspend fun isAvailable(): Boolean = withContext(Dispatchers.IO) { isBinaryAvailable() && hasRoot() }

    /**
     * Trigger an active scan and return the networks. Works with Wi-Fi off. Returns an empty list
     * if root/binary is unavailable or the driver refuses to scan on this device.
     */
    suspend fun scan(): List<ScannedNetwork> = withContext(Dispatchers.IO) {
        if (!isAvailable()) return@withContext emptyList()
        val iface = wirelessInterface()
        // Best effort: clear any rfkill soft-block and bring the interface up.
        Shell.cmd(
            "rfkill unblock wifi 2>/dev/null",
            "ip link set $iface up 2>/dev/null",
            "ifconfig $iface up 2>/dev/null",
        ).exec()
        var result = Shell.cmd("$iwPath $iface scan").exec()
        if (!result.isSuccess || result.out.isEmpty()) {
            result = Shell.cmd("$iwPath $iface dump").exec()
        }
        if (!result.isSuccess) emptyList() else ScanOutputParser.parseNetworks(result.out)
    }

    /**
     * Read WPS details from the kernel's cached scan (no trigger), keyed by upper-case BSSID. Use
     * this to enrich a framework (WifiManager) scan with WPS info the framework doesn't expose.
     */
    suspend fun wpsInfo(): Map<String, WpsDetails> = withContext(Dispatchers.IO) {
        if (!isAvailable()) return@withContext emptyMap()
        val result = Shell.cmd("$iwPath ${wirelessInterface()} dump").exec()
        if (!result.isSuccess) emptyMap() else ScanOutputParser.parseWpsByBssid(result.out)
    }

    private fun hasRoot(): Boolean = try {
        Shell.isAppGrantedRoot() ?: Shell.getShell().isRoot
    } catch (_: Exception) {
        false
    }

    private fun wirelessInterface(): String = try {
        Shell.cmd("ls /sys/class/net/ | grep -E '^wlan'").exec()
            .out.firstOrNull()?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_IFACE
    } catch (_: Exception) {
        DEFAULT_IFACE
    }

    private companion object {
        const val SCANNER_LIB = "libiwscan.so"
        const val DEFAULT_IFACE = "wlan0"
    }
}
