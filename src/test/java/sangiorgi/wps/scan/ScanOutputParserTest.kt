package sangiorgi.wps.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanOutputParserTest {

    private fun lines(text: String): List<String> = text.trimIndent().lines()

    @Test
    fun parsesBssidAndWpsFlags() {
        // 0x0188 = Keypad (0x0100) | Push Button (0x0080) | Display (0x0008) -> both PBC and PIN.
        val out = lines(
            """
            BSS aa:bb:cc:dd:ee:ff
            	WPS:
            		 * Wi-Fi Protected Setup State: 2
            		 * Manufacturer: Cisco
            		 * Model: RV340
            		 * Model Number: ABC123
            		 * Device name: HomeRouter
            		 * Config methods: 0x0188
            """,
        )
        val info = ScanOutputParser.parseWpsByBssid(out)["AA:BB:CC:DD:EE:FF"]
        requireNotNull(info)
        assertTrue(info.enabled)
        assertFalse(info.locked)
        assertTrue(info.pushButtonSupported)
        assertTrue(info.pinSupported)
        assertFalse(info.nfcSupported)
        assertEquals("HomeRouter", info.deviceName)
        assertEquals("Cisco", info.manufacturer)
    }

    @Test
    fun pushButtonOnlyHasNoPin() {
        val out = lines(
            """
            BSS 11:22:33:44:55:66
            		 * Wi-Fi Protected Setup State: 1
            		 * Config methods: 0x0080
            """,
        )
        val info = ScanOutputParser.parseWpsByBssid(out)["11:22:33:44:55:66"]
        requireNotNull(info)
        assertTrue(info.pushButtonSupported)
        assertFalse(info.pinSupported)
    }

    @Test
    fun nfcMethodsAreDetected() {
        val out = lines(
            """
            BSS 01:02:03:04:05:06
            		 * Wi-Fi Protected Setup State: 2
            		 * Config methods: 0x0040
            """,
        )
        val info = ScanOutputParser.parseWpsByBssid(out)["01:02:03:04:05:06"]
        requireNotNull(info)
        assertTrue(info.nfcSupported)
        assertFalse(info.pushButtonSupported)
        assertFalse(info.pinSupported)
    }

    @Test
    fun bssWithoutWpsStateIsExcluded() {
        val out = lines(
            """
            BSS de:ad:be:ef:00:01
            	freq: 5180
            	signal: -42.00 dBm
            """,
        )
        assertTrue(ScanOutputParser.parseWpsByBssid(out).isEmpty())
    }

    @Test
    fun apSetupLockedIsDetected() {
        val out = lines(
            """
            BSS de:ad:be:ef:00:09
            		 * Wi-Fi Protected Setup State: 2
            		 * Config methods: 0x0080
            		 * AP setup locked: 0x01
            """,
        )
        val info = ScanOutputParser.parseWpsByBssid(out)["DE:AD:BE:EF:00:09"]
        requireNotNull(info)
        assertTrue(info.locked)
    }

    @Test
    fun apSetupLockedZeroIsNotLocked() {
        val out = lines(
            """
            BSS de:ad:be:ef:00:0a
            		 * Wi-Fi Protected Setup State: 2
            		 * AP setup locked: 0x00
            """,
        )
        val info = ScanOutputParser.parseWpsByBssid(out)["DE:AD:BE:EF:00:0A"]
        requireNotNull(info)
        assertFalse(info.locked)
    }

    @Test
    fun emptyOutputYieldsEmptyMap() {
        assertTrue(ScanOutputParser.parseWpsByBssid(emptyList()).isEmpty())
    }

    @Test
    fun parseNetworks_extractsFullNetworkWithWpa2AndWps() {
        val out = lines(
            """
            BSS aa:bb:cc:dd:ee:ff
            	freq: 2412
            	signal: -45.00 dBm
            	SSID: HomeNet
            	RSN:
            		 * Authentication suites: PSK
            	WPS:
            		 * Wi-Fi Protected Setup State: 2
            		 * Config methods: 0x0188
            """,
        )
        val net = ScanOutputParser.parseNetworks(out).single()
        assertEquals("AA:BB:CC:DD:EE:FF", net.bssid)
        assertEquals("HomeNet", net.ssid)
        assertEquals(-45, net.signalDbm)
        assertEquals(2412, net.frequencyMhz)
        assertTrue(net.capabilities.contains("WPS"))
        assertTrue(net.capabilities.contains("WPA2"))
        requireNotNull(net.wps)
        assertTrue(net.wps!!.pinSupported)
    }

    @Test
    fun parseNetworks_carriesWpsLocked() {
        val out = lines(
            """
            BSS aa:bb:cc:dd:ee:01
            	freq: 2412
            	signal: -55.00 dBm
            	SSID: LockedNet
            	WPS:
            		 * Wi-Fi Protected Setup State: 2
            		 * AP setup locked: 0x01
            """,
        )
        val net = ScanOutputParser.parseNetworks(out).single()
        requireNotNull(net.wps)
        assertTrue(net.wps!!.locked)
    }

    @Test
    fun parseNetworks_detectsWpa3FromSae() {
        val out = lines(
            """
            BSS 11:22:33:44:55:66
            	freq: 5180
            	signal: -60.00 dBm
            	SSID: SecureNet
            	RSN:
            		 * Authentication suites: SAE
            """,
        )
        val net = ScanOutputParser.parseNetworks(out).single()
        assertTrue(net.capabilities.contains("WPA3"))
        assertNull(net.wps)
    }

    @Test
    fun parseNetworks_handlesOpenAndHidden() {
        val out = lines(
            """
            BSS aa:aa:aa:aa:aa:aa
            	freq: 2462
            	signal: -70.00 dBm
            	SSID: OpenCafe
            BSS bb:bb:bb:bb:bb:bb
            	freq: 2412
            	signal: -50.00 dBm
            	SSID:
            	WPA:
            """,
        )
        val nets = ScanOutputParser.parseNetworks(out)
        assertEquals(2, nets.size)
        val open = nets.first { it.bssid == "AA:AA:AA:AA:AA:AA" }
        assertFalse(open.capabilities.contains("WPA"))
        val hidden = nets.first { it.bssid == "BB:BB:BB:BB:BB:BB" }
        assertEquals("", hidden.ssid)
        assertTrue(hidden.capabilities.contains("WPA"))
    }
}
