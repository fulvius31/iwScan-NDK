package sangiorgi.wps.scan

/** WPS details for a scanned access point, derived from its WPS information element. */
data class WpsDetails(
    val enabled: Boolean,
    val locked: Boolean,
    val pinSupported: Boolean,
    val pushButtonSupported: Boolean,
    val nfcSupported: Boolean = false,
    val deviceName: String? = null,
    val manufacturer: String? = null,
    val modelName: String? = null,
    val modelNumber: String? = null,
)

/**
 * A Wi-Fi network found by [WifiScanner]. [capabilities] is a WifiManager-style flags string (e.g.
 * "[WPA2-PSK-CCMP][WPS][ESS]") so callers can reuse existing security parsing.
 */
data class ScannedNetwork(
    val bssid: String,
    val ssid: String,
    val signalDbm: Int,
    val frequencyMhz: Int,
    val capabilities: String,
    val wps: WpsDetails?,
)
