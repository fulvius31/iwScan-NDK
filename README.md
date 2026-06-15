# iwScan-NDK

[![](https://jitpack.io/v/fulvius31/iwScan-NDK.svg)](https://jitpack.io/#fulvius31/iwScan-NDK)

A tiny **root Wi‑Fi scanner for Android** built on a self‑contained **NDK nl80211 (netlink)** binary.
It can scan for nearby access points **even when the Android Wi‑Fi framework is turned OFF**, and it
parses each network's **WPS information element** — including the **"AP Setup Locked"** flag.

It is the scanning companion to
[WpsConnectionLibrary](https://github.com/fulvius31/WpsConnectionLibrary) (the WPS attack engine):
WpsConnectionLibrary *attacks* (and needs Wi‑Fi off to bind `wlan0`), while iwScan‑NDK *scans* in
that same Wi‑Fi‑off state — so a host app no longer has to toggle Wi‑Fi on to scan and off to attack.

---

## Why it exists

Android's `WifiManager.startScan()` only works with **Wi‑Fi enabled**, and its `ScanResult`
capabilities string frequently **omits WPS** entirely. Tools that test WPS, however, need Wi‑Fi
**off** (so a bundled `wpa_supplicant` can own `wlan0`). That leaves a gap: *how do you list networks
while Wi‑Fi is off?*

iwScan‑NDK fills it with a small native scanner that talks **nl80211 over generic netlink** directly
to the kernel (no `libnl`, no external `iw` binary), run as **root** from the app's native library
directory.

## Features

- 📶 **Scan with Wi‑Fi off** (root) — active scan via `nl80211`, with graceful fallback to the
  kernel's cached results.
- 🔒 **WPS details from the IE** — enabled, **locked** (AP Setup Locked `0x1057`), PIN / Push‑Button /
  NFC config methods, device/manufacturer/model.
- 🧩 **Self‑contained** — the scanner is compiled from source (`iwscan.c`) by the NDK/CMake during
  the normal Gradle build; no prebuilt binaries, no `libnl`.
- 🧭 **Clean API** — `ScannedNetwork` / `WpsDetails` data classes; capabilities exposed as a
  `WifiManager`‑style flags string so existing security parsers keep working.
- 🛟 **Safe by default** — every call returns empty/false when root or the binary is unavailable, or
  the device's driver can't scan with Wi‑Fi off.

## Requirements

- **Root** access on the device (the scanner runs via a root shell using
  [libsu](https://github.com/topjohnwu/libsu)).
- **minSdk 24** (Android 7.0+).
- A device whose driver allows bringing `wlan0` up while the framework Wi‑Fi is off (most do; see
  *Limitations*).

## Installation

The library is published two ways. Either coordinate is `com.github.fulvius31:iwScan-NDK:1.0.1`.

> Whichever you use, the host app must keep
> `android { packaging { jniLibs { useLegacyPackaging = true } } }` so the bundled `libiwscan.so`
> is extracted to `nativeLibDir` (the only place it can be executed on Android 10+).

### Option A — GitHub Packages (published by CI, recommended)

CI (`.github/workflows/publish.yml`) builds and publishes to GitHub Packages on every `X.Y.Z` tag.
GitHub Packages requires authentication even for reads, so add a token.

`settings.gradle`:

```groovy
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://maven.pkg.github.com/fulvius31/iwScan-NDK")
            credentials {
                username = providers.gradleProperty("gpr.user").orElse(providers.environmentVariable("GITHUB_ACTOR")).orNull
                password = providers.gradleProperty("gpr.token").orElse(providers.environmentVariable("GITHUB_TOKEN")).orNull
            }
        }
    }
}
```

In `~/.gradle/gradle.properties` (never commit a token):

```properties
gpr.user=your-github-username
gpr.token=ghp_xxx   # a Personal Access Token with read:packages
```

### Option B — JitPack

`settings.gradle`:

```groovy
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
}
```

### Dependency

```groovy
dependencies {
    implementation 'com.github.fulvius31:iwScan-NDK:1.0.1'
}
```

## A note on the libsu dependency

This library depends on [libsu](https://github.com/topjohnwu/libsu) for its root shell. libsu is
published **only on JitPack**, and JitPack returns **HTTP 403** to shared GitHub Actions runner IPs
(it works fine from dev machines). To keep CI hermetic, the libsu `core:6.0.0` AAR is **vendored**
under [`vendor/`](vendor/) and resolved from a checked-in local Maven repository declared first in
[`settings.gradle`](settings.gradle). No JitPack access — and no token/secret — is needed to build.

To bump libsu, drop the new `core-X.Y.Z.aar` + a matching POM under
`vendor/com/github/topjohnwu/libsu/core/X.Y.Z/` and update the version in `build.gradle`.

## Releasing

Tag a version and push it — CI publishes it to GitHub Packages:

```bash
git tag 1.0.1 && git push origin 1.0.1
```

## Usage

```kotlin
import sangiorgi.wps.scan.WifiScanner

val scanner = WifiScanner(context)   // any Context

// Is scanning possible right now? (binary present + root granted)
if (scanner.isAvailable()) {

    // Active scan — works even with Wi-Fi OFF. Suspends; call off the main thread.
    val networks = scanner.scan()
    for (n in networks) {
        println("${n.ssid} (${n.bssid}) ${n.signalDbm} dBm  ${n.capabilities}")
        n.wps?.let { wps ->
            if (wps.locked) println("  WPS is LOCKED")
            if (wps.pinSupported) println("  WPS PIN supported")
        }
    }
}

// Or, when Wi-Fi is ON and you already have WifiManager results, enrich them with WPS info
// (keyed by upper-case BSSID) the framework doesn't expose:
val wpsByBssid = scanner.wpsInfo()
```

All three calls (`isAvailable`, `scan`, `wpsInfo`) are `suspend` functions that run on `Dispatchers.IO`.

## API

### `class WifiScanner(context: Context)`
| Member | Description |
| --- | --- |
| `fun isBinaryAvailable(): Boolean` | The native scanner is present and executable. |
| `suspend fun isAvailable(): Boolean` | Binary present **and** root granted. |
| `suspend fun scan(): List<ScannedNetwork>` | Trigger an active scan (Wi‑Fi off OK) and return networks. Empty on failure. |
| `suspend fun wpsInfo(): Map<String, WpsDetails>` | WPS details from the cached scan, keyed by upper‑case BSSID (no trigger). |

### `data class ScannedNetwork`
`bssid`, `ssid`, `signalDbm`, `frequencyMhz`, `capabilities` (e.g. `"[WPA2-PSK-CCMP][WPS][ESS]"`),
`wps: WpsDetails?`.

### `data class WpsDetails`
`enabled`, `locked`, `pinSupported`, `pushButtonSupported`, `nfcSupported`, `deviceName`,
`manufacturer`, `modelName`, `modelNumber`.

## How it works

1. **`libiwscan.so`** — `src/main/cpp/iwscan.c` is compiled by CMake/NDK into an *executable* named
   `libiwscan.so` so the Android Gradle Plugin packages it into the APK's native lib dir, the only
   location an app may execute from on Android 10+.
2. **Scanning** — it opens a generic‑netlink socket, resolves the `nl80211` family, optionally
   triggers an active scan (`NL80211_CMD_TRIGGER_SCAN`), then dumps results
   (`NL80211_CMD_GET_SCAN`) and parses each BSS (BSSID, frequency, signal, capability) plus its
   information elements (SSID, RSN→WPA2/WPA3 via SAE, WPA vendor IE, and the WPS IE).
3. **WPS IEs** — WPS attributes are gathered from **both** the probe‑response and beacon IEs (and
   across fragmented vendor elements), so the **AP Setup Locked** attribute is found wherever the AP
   advertises it.
4. **Interface bring‑up** — before a Wi‑Fi‑off scan it best‑effort clears `rfkill` and brings the
   interface up (`ip link set wlan0 up`).
5. **Parsing** — the binary prints `iw`‑style text which the pure, unit‑tested
   `ScanOutputParser` turns into `ScannedNetwork`/`WpsDetails`.

The binary is invoked as `libiwscan.so <iface> scan` (trigger + dump) or `libiwscan.so <iface> dump`
(cached only).

## Limitations & caveats

- **Driver dependent.** Bringing `wlan0` up with the framework Wi‑Fi off is chipset‑specific; on
  some devices the firmware only loads via the Wi‑Fi HAL and root alone can't revive it. The library
  returns an empty list in that case — fall back to a framework scan.
- **Lock state is only as good as the beacon.** Many routers **don't advertise** "AP Setup Locked"
  in their beacons at all; for those, locked status is only discoverable by actually attempting WPS
  (which WpsConnectionLibrary reports). iwScan‑NDK reports it only when the AP broadcasts it.
- **Root required.** Without root, `isAvailable()` is `false` and `scan()`/`wpsInfo()` return empty.

## Building from source

```bash
./gradlew assembleRelease        # builds the AAR (native compiled for all ABIs)
./gradlew testDebugUnitTest      # runs the parser unit tests
./gradlew publishToMavenLocal    # publishes to ~/.m2 for local consumption
```

Requires the Android SDK with **NDK** and **CMake 3.22.1** (`sdkmanager "ndk;25.0.8775105" "cmake;3.22.1"`).

## License

See [LICENSE](LICENSE).

## Credits

Companion to [WpsConnectionLibrary](https://github.com/fulvius31/WpsConnectionLibrary).
Root shell by [libsu](https://github.com/topjohnwu/libsu).
