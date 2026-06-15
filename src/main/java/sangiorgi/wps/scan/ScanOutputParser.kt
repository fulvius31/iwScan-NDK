package sangiorgi.wps.scan

/**
 * Pure parser for the `iw`-style text emitted by the bundled native scanner (libiwscan). Kept
 * Android-free so it can be unit-tested on the JVM.
 *
 * WPS Config Methods bit flags: 0x0004 Label, 0x0008 Display, 0x0080 Push Button, 0x0100 Keypad,
 * 0x0280 Virtual PBC, 0x0480 Physical PBC, 0x2008 Virtual Display PIN, NFC = 0x0010|0x0020|0x0040.
 */
internal object ScanOutputParser {

    private const val PUSH_BUTTON_MASK = 0x0080 or 0x0280 or 0x0480
    private const val PIN_MASK = 0x0004 or 0x0008 or 0x0100 or 0x2008
    private const val NFC_MASK = 0x0010 or 0x0020 or 0x0040

    /** WPS details for every BSS, keyed by upper-case BSSID (used to enrich framework scans). */
    fun parseWpsByBssid(lines: List<String>): Map<String, WpsDetails> {
        val result = mutableMapOf<String, WpsDetails>()
        var bssid: String? = null
        var st = WpsState()

        fun flush() {
            val id = bssid ?: return
            buildWps(st)?.let { result[id.uppercase()] = it }
        }

        for (line in lines) {
            val t = line.trim()
            if (t.startsWith("BSS ")) {
                flush(); bssid = extractBssid(t); st = WpsState(); continue
            }
            st.consume(t)
        }
        flush()
        return result
    }

    /** Full network list from `iw scan` output. */
    fun parseNetworks(lines: List<String>): List<ScannedNetwork> {
        val result = mutableListOf<ScannedNetwork>()
        var bssid: String? = null
        var ssid = ""
        var signal = -100
        var freq = 0
        var hasRsn = false
        var hasWpa = false
        var hasSae = false
        var hasOwe = false
        var hasPrivacy = false
        var st = WpsState()

        fun flush() {
            val id = bssid ?: return
            val wps = buildWps(st)
            result += ScannedNetwork(
                bssid = id.uppercase(),
                ssid = ssid,
                signalDbm = signal,
                frequencyMhz = freq,
                capabilities = buildCapabilities(hasRsn, hasWpa, hasSae, hasOwe, hasPrivacy, wps != null),
                wps = wps,
            )
        }

        for (line in lines) {
            val t = line.trim()
            if (t.startsWith("BSS ")) {
                flush()
                bssid = extractBssid(t)
                ssid = ""; signal = -100; freq = 0
                hasRsn = false; hasWpa = false; hasSae = false; hasOwe = false; hasPrivacy = false
                st = WpsState()
                continue
            }
            when {
                t.startsWith("SSID:") -> ssid = extractValue(t) ?: ""
                t.startsWith("signal:") -> signal = extractSignal(t)
                t.startsWith("freq:") -> freq = extractNumber(t) ?: 0
                t.startsWith("RSN:") -> hasRsn = true
                t.startsWith("WPA:") -> hasWpa = true
                t.startsWith("* Authentication suites:") -> {
                    if (t.contains("SAE")) hasSae = true
                    if (t.contains("OWE")) hasOwe = true
                }
                t.startsWith("capability:") -> if (t.contains("Privacy")) hasPrivacy = true
                else -> st.consume(t)
            }
        }
        flush()
        return result
    }

    /** Mutable accumulator for the WPS lines of one BSS. */
    private class WpsState {
        var state: Int? = null
        var config: Int? = null
        var locked = false
        var deviceName: String? = null
        var manufacturer: String? = null
        var modelName: String? = null
        var modelNumber: String? = null

        fun consume(t: String) {
            when {
                t.startsWith("* Wi-Fi Protected Setup State:") -> state = extractNumber(t)
                t.startsWith("* Config methods:") -> config = extractHex(t)
                t.startsWith("* AP setup locked:") -> locked = locked || extractHex(t) != 0
                t.startsWith("* Device name:") -> deviceName = extractValue(t)
                t.startsWith("* Manufacturer:") -> manufacturer = extractValue(t)
                t.startsWith("* Model:") -> modelName = extractValue(t)
                t.startsWith("* Model Number:") -> modelNumber = extractValue(t)
            }
        }
    }

    private fun buildWps(st: WpsState): WpsDetails? {
        val state = st.state ?: return null
        @Suppress("UNUSED_VARIABLE") val configured = state
        val config = st.config ?: 0
        return WpsDetails(
            enabled = true,
            locked = st.locked,
            pinSupported = (config and PIN_MASK) != 0,
            pushButtonSupported = (config and PUSH_BUTTON_MASK) != 0,
            nfcSupported = (config and NFC_MASK) != 0,
            deviceName = st.deviceName,
            manufacturer = st.manufacturer,
            modelName = st.modelName,
            modelNumber = st.modelNumber,
        )
    }

    private fun buildCapabilities(
        rsn: Boolean,
        wpa: Boolean,
        sae: Boolean,
        owe: Boolean,
        privacy: Boolean,
        wps: Boolean,
    ): String {
        val sb = StringBuilder()
        when {
            sae -> sb.append("WPA3 ")
            rsn && wpa -> sb.append("WPA2 WPA ")
            rsn -> sb.append("WPA2 ")
            wpa -> sb.append("WPA ")
            owe -> sb.append("OWE ")
            privacy -> sb.append("WEP ")
        }
        if (wps) sb.append("WPS ")
        sb.append("ESS")
        return "[${sb.toString().trim().replace(" ", "][")}]"
    }

    private fun extractBssid(line: String): String? =
        Regex("BSS ([0-9a-fA-F:]{17})").find(line)?.groupValues?.get(1)

    private fun extractNumber(line: String): Int? =
        Regex("(\\d+)").find(line.substringAfter(":"))?.groupValues?.get(1)?.toIntOrNull()

    private fun extractSignal(line: String): Int =
        Regex("(-?\\d+)").find(line.substringAfter("signal:"))?.groupValues?.get(1)?.toIntOrNull() ?: -100

    private fun extractValue(line: String): String? =
        line.split(":", limit = 2).getOrNull(1)?.trim()

    private fun extractHex(line: String): Int =
        Regex("0x([0-9a-fA-F]+)").find(line)?.groupValues?.get(1)?.toIntOrNull(16) ?: 0
}
