//! Adapter that scans WiFi BSSIDs on Linux by invoking `iw dev <iface> scan`.
//!
//! This is the Linux counterpart to [`NetshBssidScanner`](super::NetshBssidScanner)
//! on Windows and [`MacosCoreWlanScanner`](super::MacosCoreWlanScanner) on macOS.
//!
//! # Design
//!
//! The adapter shells out to `iw dev <interface> scan` (or `iw dev <interface> scan dump`
//! to read cached results without triggering a new scan, which requires root).
//! The output is parsed into [`BssidObservation`] values using the same domain
//! types shared by all platform adapters.
//!
//! # Permissions
//!
//! - `iw dev <iface> scan` / `scan trigger` require `CAP_NET_ADMIN` (typically root).
//! - `iw dev <iface> scan dump` reads cached results and works without root.
//! - `iw dev <iface> link` (associated-AP RSSI) works without root.
//!
//! # Sampling model ([`LinuxWifiSampler`])
//!
//! A blocking `iw dev <iface> scan` can take seconds and, on some vendor drivers
//! (e.g. Realtek `rtl88x2ce`), never returns while the interface is associated.
//! The sampler therefore never blocks on a scan: it reads the associated AP's
//! RSSI from `iw link` on every tick (milliseconds), and refreshes the
//! multi-BSSID table from `scan dump` on each tick, requesting a fresh scan with
//! `scan trigger` every `scan_interval`. Without `CAP_NET_ADMIN` the trigger is
//! skipped and the table only refreshes when something else (NetworkManager,
//! wpa_supplicant) scans; the associated AP stays live either way.
//!
//! # Platform
//!
//! Linux only. Gated behind `#[cfg(target_os = "linux")]` at the module level.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::domain::bssid::{BandType, BssidId, BssidObservation, RadioType};
use crate::error::WifiScanError;

// ---------------------------------------------------------------------------
// LinuxIwScanner
// ---------------------------------------------------------------------------

/// Synchronous WiFi scanner that shells out to `iw dev <interface> scan`.
///
/// Each call to [`scan_sync`](Self::scan_sync) spawns a subprocess, captures
/// stdout, and parses the BSS stanzas into [`BssidObservation`] values.
pub struct LinuxIwScanner {
    /// Wireless interface name (e.g. `"wlan0"`, `"wlp2s0"`).
    interface: String,
    /// If true, use `scan dump` (cached results) instead of triggering a new
    /// scan. This avoids the root requirement but may return stale data.
    use_dump: bool,
}

impl LinuxIwScanner {
    /// Create a scanner for the default interface `wlan0`.
    pub fn new() -> Self {
        Self {
            interface: "wlan0".to_owned(),
            use_dump: false,
        }
    }

    /// Create a scanner for a specific wireless interface.
    pub fn with_interface(iface: impl Into<String>) -> Self {
        Self {
            interface: iface.into(),
            use_dump: false,
        }
    }

    /// Use `scan dump` instead of `scan` to read cached results without root.
    #[must_use]
    pub fn use_cached(mut self) -> Self {
        self.use_dump = true;
        self
    }

    /// Create a scanner for the first managed wireless interface reported by
    /// `iw dev` (preferring one that is currently associated). Falls back to
    /// `wlan0` when `iw dev` is unavailable or lists nothing.
    pub fn auto_detect() -> Self {
        let iface = detect_interface().unwrap_or_else(|| "wlan0".to_owned());
        Self::with_interface(iface)
    }

    /// The wireless interface this scanner operates on.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Run `iw dev <iface> scan` and parse the output synchronously.
    ///
    /// Returns one [`BssidObservation`] per BSS stanza in the output.
    pub fn scan_sync(&self) -> Result<Vec<BssidObservation>, WifiScanError> {
        // iw uses "scan dump" not "scan scan dump"
        let args = if self.use_dump {
            vec!["dev", &self.interface, "scan", "dump"]
        } else {
            vec!["dev", &self.interface, "scan"]
        };
        let stdout = run_iw(&args)?;
        parse_iw_scan_output(&stdout)
    }

    /// Ask the driver to start a scan without waiting for it (`iw ... scan trigger`).
    ///
    /// Needs `CAP_NET_ADMIN`. A driver that is already scanning answers
    /// `EBUSY`, which is reported as [`WifiScanError::ScanFailed`] like any
    /// other failure; callers that only want "best effort" can ignore the error.
    pub fn trigger_scan(&self) -> Result<(), WifiScanError> {
        run_iw(&["dev", &self.interface, "scan", "trigger"]).map(|_| ())
    }

    /// Read the associated AP's RSSI from `iw dev <iface> link` (no privilege needed).
    ///
    /// Returns `Ok(None)` when the interface is not associated.
    pub fn link_sync(&self) -> Result<Option<BssidObservation>, WifiScanError> {
        let stdout = run_iw(&["dev", &self.interface, "link"])?;
        Ok(parse_iw_link_output(&stdout))
    }
}

fn run_iw(args: &[&str]) -> Result<String, WifiScanError> {
    let output = Command::new("iw").args(args).output().map_err(|e| {
        WifiScanError::ProcessError(format!("failed to run `iw {}`: {e}", args.join(" ")))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WifiScanError::ScanFailed {
            reason: format!("iw {} exited with {}: {}", args.join(" "), output.status, stderr.trim()),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Pick a wireless interface from `iw dev` output: the first managed interface
/// that is associated (has an `ssid` line), else the first managed interface.
fn detect_interface() -> Option<String> {
    let out = run_iw(&["dev"]).ok()?;
    pick_interface(&out)
}

/// Pure parser behind [`detect_interface`].
pub fn pick_interface(iw_dev_output: &str) -> Option<String> {
    let mut first_managed: Option<String> = None;
    let mut current: Option<(String, bool, bool)> = None; // (name, managed, associated)

    let flush = |cur: &mut Option<(String, bool, bool)>, first: &mut Option<String>| -> Option<String> {
        if let Some((name, managed, associated)) = cur.take() {
            if managed {
                if associated {
                    return Some(name);
                }
                first.get_or_insert(name);
            }
        }
        None
    };

    for line in iw_dev_output.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix("Interface ") {
            if let Some(found) = flush(&mut current, &mut first_managed) {
                return Some(found);
            }
            current = Some((name.trim().to_owned(), false, false));
        } else if let Some(cur) = current.as_mut() {
            if let Some(ty) = t.strip_prefix("type ") {
                cur.1 = ty.trim() == "managed";
            } else if t.starts_with("ssid ") {
                cur.2 = true;
            }
        }
    }
    if let Some(found) = flush(&mut current, &mut first_managed) {
        return Some(found);
    }
    first_managed
}

/// Parse `iw dev <iface> link` output into a single observation of the associated AP.
///
/// ```text
/// Connected to 36:5d:9e:f0:87:64 (on wlP1p1s0)
///         SSID: Moss
///         freq: 5785
///         signal: -47 dBm
/// ```
/// Returns `None` for `Not connected.` or unparseable output.
pub fn parse_iw_link_output(output: &str) -> Option<BssidObservation> {
    let mut stanza = BssStanza::default();
    for line in output.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Connected to ") {
            let mac = rest.split_whitespace().next()?;
            if mac.len() == 17 {
                stanza.bssid = Some(mac.to_lowercase());
            }
        } else if let Some(rest) = t.strip_prefix("SSID:") {
            stanza.ssid = Some(rest.trim().to_owned());
        } else if let Some(rest) = t.strip_prefix("freq:") {
            stanza.freq_mhz = parse_freq_mhz(rest);
        } else if let Some(rest) = t.strip_prefix("signal:") {
            stanza.signal_dbm = parse_signal_dbm(rest);
        }
    }
    stanza.bssid.as_ref()?;
    stanza.signal_dbm?;
    stanza.flush(Instant::now())
}

// ---------------------------------------------------------------------------
// LinuxWifiSampler
// ---------------------------------------------------------------------------

/// Stateful, non-blocking multi-BSSID sampler for Linux (see module docs).
pub struct LinuxWifiSampler {
    scanner: LinuxIwScanner,
    scan_interval: Duration,
    last_trigger: Option<Instant>,
    /// Whether `scan trigger` is believed to work (cleared on EPERM so we stop
    /// spawning a failing process every interval).
    can_trigger: bool,
    /// Last-known observation per BSSID from `scan dump`.
    table: HashMap<BssidId, BssidObservation>,
}

impl LinuxWifiSampler {
    /// Create a sampler on `iface`; `scan_interval` of zero disables scan
    /// triggering (link-only plus whatever the kernel cache already holds).
    pub fn new(iface: impl Into<String>, scan_interval: Duration) -> Self {
        Self {
            scanner: LinuxIwScanner::with_interface(iface),
            scan_interval,
            last_trigger: None,
            can_trigger: !scan_interval.is_zero(),
            table: HashMap::new(),
        }
    }

    /// The wireless interface being sampled.
    pub fn interface(&self) -> &str {
        self.scanner.interface()
    }

    /// Whether scan triggering is still enabled (it is disabled permanently
    /// after the first permission failure).
    pub fn scanning_enabled(&self) -> bool {
        self.can_trigger
    }

    /// One tick: returns the current BSSID observations, associated AP first
    /// with a fresh RSSI, then the other cached BSSIDs ordered by RSSI.
    ///
    /// Errors only when the interface cannot be queried at all.
    pub fn sample(&mut self) -> Result<Vec<BssidObservation>, WifiScanError> {
        let link = self.scanner.link_sync()?;

        if self.can_trigger
            && self
                .last_trigger
                .is_none_or(|t| t.elapsed() >= self.scan_interval)
        {
            match self.scanner.trigger_scan() {
                Ok(()) => {}
                Err(WifiScanError::ScanFailed { reason }) if reason.contains("Operation not permitted") => {
                    tracing::warn!(
                        "iw scan trigger not permitted on {} (needs CAP_NET_ADMIN); \
                         continuing with associated-AP RSSI plus cached scan results",
                        self.scanner.interface()
                    );
                    self.can_trigger = false;
                }
                Err(e) => tracing::debug!("iw scan trigger: {e}"), // EBUSY etc.
            }
            self.last_trigger = Some(Instant::now());
        }

        if let Ok(dump) = self.scanner.clone_cached().scan_sync() {
            for obs in dump {
                self.table.insert(obs.bssid, obs);
            }
        }

        let mut out: Vec<BssidObservation> = Vec::with_capacity(self.table.len() + 1);
        if let Some(link) = link {
            // live RSSI for the associated AP replaces the cached entry
            self.table.remove(&link.bssid);
            out.push(link);
        }
        let mut rest: Vec<BssidObservation> = self.table.values().cloned().collect();
        rest.sort_by(|a, b| b.rssi_dbm.total_cmp(&a.rssi_dbm));
        out.extend(rest);
        Ok(out)
    }
}

impl LinuxIwScanner {
    fn clone_cached(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            use_dump: true,
        }
    }
}

impl Default for LinuxIwScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Intermediate accumulator for fields within a single BSS stanza.
#[derive(Default)]
struct BssStanza {
    bssid: Option<String>,
    ssid: Option<String>,
    signal_dbm: Option<f64>,
    freq_mhz: Option<u32>,
    channel: Option<u8>,
}

impl BssStanza {
    /// Flush this stanza into a [`BssidObservation`], if we have enough data.
    fn flush(self, timestamp: Instant) -> Option<BssidObservation> {
        let bssid_str = self.bssid?;
        let bssid = BssidId::parse(&bssid_str).ok()?;
        let rssi_dbm = self.signal_dbm.unwrap_or(-90.0);

        // Determine channel from explicit field or frequency.
        let channel = self
            .channel
            .or_else(|| self.freq_mhz.map(freq_to_channel))
            .unwrap_or(0);

        let band = BandType::from_channel(channel);
        let radio_type = infer_radio_type_from_freq(self.freq_mhz.unwrap_or(0));
        let signal_pct = ((rssi_dbm + 100.0) * 2.0).clamp(0.0, 100.0);

        Some(BssidObservation {
            bssid,
            rssi_dbm,
            signal_pct,
            channel,
            band,
            radio_type,
            ssid: self.ssid.unwrap_or_default(),
            timestamp,
        })
    }
}

/// Parse the text output of `iw dev <iface> scan [dump]`.
///
/// The output consists of BSS stanzas, each starting with:
/// ```text
/// BSS aa:bb:cc:dd:ee:ff(on wlan0)
/// ```
/// followed by indented key-value lines.
pub fn parse_iw_scan_output(output: &str) -> Result<Vec<BssidObservation>, WifiScanError> {
    let now = Instant::now();
    let mut results = Vec::new();
    let mut current: Option<BssStanza> = None;

    for line in output.lines() {
        // New BSS stanza starts with "BSS " at column 0.
        if let Some(rest) = line.strip_prefix("BSS ") {
            // Flush previous stanza.
            if let Some(stanza) = current.take() {
                if let Some(obs) = stanza.flush(now) {
                    results.push(obs);
                }
            }

            // Parse BSSID from "BSS aa:bb:cc:dd:ee:ff(on wlan0)" or
            // "BSS aa:bb:cc:dd:ee:ff -- associated".
            let mac_end = rest
                .find(|c: char| !c.is_ascii_hexdigit() && c != ':')
                .unwrap_or(rest.len());
            let mac = &rest[..mac_end];

            if mac.len() == 17 {
                current = Some(BssStanza {
                    bssid: Some(mac.to_lowercase()),
                    ..Default::default()
                });
            }
            continue;
        }

        // Indented lines belong to the current stanza.
        let trimmed = line.trim();
        if let Some(ref mut stanza) = current {
            if let Some(rest) = trimmed.strip_prefix("SSID:") {
                stanza.ssid = Some(rest.trim().to_owned());
            } else if let Some(rest) = trimmed.strip_prefix("signal:") {
                // "signal: -52.00 dBm"
                stanza.signal_dbm = parse_signal_dbm(rest);
            } else if let Some(rest) = trimmed.strip_prefix("freq:") {
                // "freq: 5180" (iw <= 5.x) or "freq: 5180.0" (iw >= 6.x prints kHz precision)
                stanza.freq_mhz = parse_freq_mhz(rest);
            } else if let Some(rest) = trimmed.strip_prefix("DS Parameter set: channel") {
                // "DS Parameter set: channel 6"
                stanza.channel = rest.trim().parse().ok();
            }
        }
    }

    // Flush the last stanza.
    if let Some(stanza) = current.take() {
        if let Some(obs) = stanza.flush(now) {
            results.push(obs);
        }
    }

    Ok(results)
}

/// Convert a frequency in MHz to an 802.11 channel number.
fn freq_to_channel(freq_mhz: u32) -> u8 {
    match freq_mhz {
        // 2.4 GHz: channels 1-14.  Max result (2472-2407)/5 = 13 — fits u8.
        2412..=2472 => u8::try_from((freq_mhz - 2407) / 5).unwrap_or(0),
        2484 => 14,
        // 5 GHz: channels 36-177. Max result (5885-5000)/5 = 177 — fits u8.
        5170..=5885 => u8::try_from((freq_mhz - 5000) / 5).unwrap_or(0),
        // 6 GHz (Wi-Fi 6E).       Max result (7115-5950)/5 = 233 — fits u8.
        5955..=7115 => u8::try_from((freq_mhz - 5950) / 5).unwrap_or(0),
        _ => 0,
    }
}

/// Parse a frequency field like "5180", "5180.0" or "5180 MHz" into whole MHz.
fn parse_freq_mhz(s: &str) -> Option<u32> {
    let num = s.split_whitespace().next()?;
    let f: f64 = num.parse().ok()?;
    // Range-checked above u32 precision concerns: 0 < f < 1e6 so the cast is exact.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    if f.is_finite() && f > 0.0 && f < 1.0e6 {
        Some(f.round() as u32)
    } else {
        None
    }
}

/// Parse a signal strength string like "-52.00 dBm" into dBm.
fn parse_signal_dbm(s: &str) -> Option<f64> {
    let s = s.trim();
    // Take everything up to " dBm" or just parse the number.
    let num_part = s.split_whitespace().next()?;
    num_part.parse().ok()
}

/// Infer radio type from frequency (best effort).
fn infer_radio_type_from_freq(freq_mhz: u32) -> RadioType {
    match freq_mhz {
        5955..=7115 => RadioType::Ax, // 6 GHz → Wi-Fi 6E
        5170..=5885 => RadioType::Ac, // 5 GHz → likely 802.11ac
        _ => RadioType::N,            // 2.4 GHz → at least 802.11n
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-world `iw dev wlan0 scan` output (truncated to 3 BSSes).
    const SAMPLE_IW_OUTPUT: &str = "\
BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tTSF: 123456789 usec
\tfreq: 5180
\tbeacon interval: 100 TUs
\tcapability: ESS Privacy (0x0011)
\tsignal: -52.00 dBm
\tSSID: HomeNetwork
\tDS Parameter set: channel 36
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 2437
\tsignal: -71.00 dBm
\tSSID: GuestWifi
\tDS Parameter set: channel 6
BSS de:ad:be:ef:ca:fe(on wlan0) -- associated
\tfreq: 5745
\tsignal: -45.00 dBm
\tSSID: OfficeNet
";

    #[test]
    fn parse_three_bss_stanzas() {
        let obs = parse_iw_scan_output(SAMPLE_IW_OUTPUT).unwrap();
        assert_eq!(obs.len(), 3);

        // First BSS.
        assert_eq!(obs[0].ssid, "HomeNetwork");
        assert_eq!(obs[0].bssid.to_string(), "aa:bb:cc:dd:ee:ff");
        assert!((obs[0].rssi_dbm - (-52.0)).abs() < f64::EPSILON);
        assert_eq!(obs[0].channel, 36);
        assert_eq!(obs[0].band, BandType::Band5GHz);

        // Second BSS: 2.4 GHz.
        assert_eq!(obs[1].ssid, "GuestWifi");
        assert_eq!(obs[1].channel, 6);
        assert_eq!(obs[1].band, BandType::Band2_4GHz);
        assert_eq!(obs[1].radio_type, RadioType::N);

        // Third BSS: "-- associated" suffix.
        assert_eq!(obs[2].ssid, "OfficeNet");
        assert_eq!(obs[2].bssid.to_string(), "de:ad:be:ef:ca:fe");
        assert!((obs[2].rssi_dbm - (-45.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn freq_to_channel_conversion() {
        assert_eq!(freq_to_channel(2412), 1);
        assert_eq!(freq_to_channel(2437), 6);
        assert_eq!(freq_to_channel(2462), 11);
        assert_eq!(freq_to_channel(2484), 14);
        assert_eq!(freq_to_channel(5180), 36);
        assert_eq!(freq_to_channel(5745), 149);
        assert_eq!(freq_to_channel(5955), 1); // 6 GHz channel 1
        assert_eq!(freq_to_channel(9999), 0); // Unknown
    }

    #[test]
    fn parse_signal_dbm_values() {
        assert!((parse_signal_dbm(" -52.00 dBm").unwrap() - (-52.0)).abs() < f64::EPSILON);
        assert!((parse_signal_dbm("-71.00 dBm").unwrap() - (-71.0)).abs() < f64::EPSILON);
        assert!((parse_signal_dbm("-45.00").unwrap() - (-45.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_output() {
        let obs = parse_iw_scan_output("").unwrap();
        assert!(obs.is_empty());
    }

    #[test]
    fn missing_ssid_defaults_to_empty() {
        let output = "\
BSS 11:22:33:44:55:66(on wlan0)
\tfreq: 2437
\tsignal: -60.00 dBm
";
        let obs = parse_iw_scan_output(output).unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].ssid, "");
    }

    /// iw 6.x (and vendor drivers such as rtl88x2ce) print `freq: 5785.0`.
    #[test]
    fn fractional_freq_is_parsed() {
        let output = "\
BSS 36:5d:9e:f0:87:64(on wlP1p1s0) -- associated
\tfreq: 5785.0
\tsignal: -43.00 dBm
\tSSID: Moss
BSS d8:44:89:df:4a:a0(on wlP1p1s0)
\tfreq: 2412.0
\tsignal: -29.00 dBm
\tSSID: Moss3
";
        let obs = parse_iw_scan_output(output).unwrap();
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].channel, 157);
        assert_eq!(obs[0].band, BandType::Band5GHz);
        assert_eq!(obs[1].channel, 1);
        assert_eq!(obs[1].band, BandType::Band2_4GHz);
        assert_eq!(parse_freq_mhz(" 2437 MHz"), Some(2437));
        assert_eq!(parse_freq_mhz("garbage"), None);
    }

    #[test]
    fn parse_link_output_connected() {
        let output = "\
Connected to 36:5d:9e:f0:87:64 (on wlP1p1s0)
\tSSID: Moss
\tfreq: 5785
\tRX: 123456 bytes (789 packets)
\tTX: 2345 bytes (67 packets)
\tsignal: -47 dBm
\trx bitrate: 390.0 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1
";
        let obs = parse_iw_link_output(output).expect("associated");
        assert_eq!(obs.bssid.to_string(), "36:5d:9e:f0:87:64");
        assert_eq!(obs.ssid, "Moss");
        assert_eq!(obs.channel, 157);
        assert!((obs.rssi_dbm - (-47.0)).abs() < f64::EPSILON);
        // (-47 + 100) * 2 = 106 → clamped to 100
        assert!((obs.signal_pct - 100.0).abs() < 1e-9, "signal_pct={}", obs.signal_pct);
    }

    #[test]
    fn parse_link_output_not_connected() {
        assert!(parse_iw_link_output("Not connected.\n").is_none());
        assert!(parse_iw_link_output("").is_none());
    }

    #[test]
    fn pick_interface_prefers_associated_managed() {
        let output = "\
phy#1
\tInterface wlan1
\t\tifindex 5
\t\ttype managed
phy#0
\tInterface p2p-dev-wlP1p1s0
\t\ttype P2P-device
\tInterface wlP1p1s0
\t\tifindex 3
\t\taddr 48:8f:4c:d5:eb:40
\t\tssid Moss
\t\ttype managed
\t\tchannel 157 (5785 MHz), width: 80 MHz, center1: 5775 MHz
";
        assert_eq!(pick_interface(output).as_deref(), Some("wlP1p1s0"));
        // No associated interface: first managed one wins.
        let output2 = "phy#0\n\tInterface wlan0\n\t\ttype managed\n\tInterface mon0\n\t\ttype monitor\n";
        assert_eq!(pick_interface(output2).as_deref(), Some("wlan0"));
        assert_eq!(pick_interface(""), None);
    }

    #[test]
    fn channel_from_freq_when_ds_param_missing() {
        let output = "\
BSS aa:bb:cc:dd:ee:ff(on wlan0)
\tfreq: 5180
\tsignal: -50.00 dBm
\tSSID: NoDS
";
        let obs = parse_iw_scan_output(output).unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].channel, 36); // Derived from 5180 MHz.
    }
}
