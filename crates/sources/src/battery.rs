//! The battery report: `powercfg /batteryreport /xml`.
//!
//! ADR 0002 allows `powercfg` here and nowhere else, because this output has a schema
//! (`http://schemas.microsoft.com/battery/2012`). Nothing in this module reads display text: the
//! XML is parsed by element and attribute name, and unknown elements are ignored.
//!
//! The file on disk is UTF-16 with a byte order mark although its XML declaration says `utf-8`
//! (docs/PLAN.md, "Facts from the first live probe"). [`decode_report`] reads the bytes and decodes
//! them itself; the declaration is never trusted.
//!
//! [`parse_battery_report`] is pure and runs over `fixtures/battery/battery-report.xml` on any
//! platform. [`read_battery_report`] runs `powercfg` and exists on Windows only.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use jiff::{Span, SpanRelativeTo, Timestamp};
#[cfg(windows)]
use pcsleuth_core::{Access, SourceId, Sourced};
use quick_xml::Reader;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};

/// Everything the report holds that pcsleuth answers questions with.
///
/// Capacities are in mWh and rates in mW, as the report states them. Local-time attributes in the
/// XML are ignored: every instant here is the report's UTC one.
#[derive(Debug, Clone, PartialEq)]
pub struct BatteryReport {
    /// When the report was generated.
    pub scanned_at: Option<Timestamp>,
    /// Start of the window covered by `recent_usage` and `energy_drains`.
    pub report_start: Option<Timestamp>,
    /// `Mobile`, `Desktop`, ... as Windows names the platform role.
    pub platform_role: Option<String>,
    /// Whether the report says the machine uses Modern Standby.
    pub connected_standby: Option<bool>,
    pub batteries: Vec<Battery>,
    pub runtime_estimates: Vec<RuntimeEstimate>,
    pub recent_usage: Vec<UsageEntry>,
    pub energy_drains: Vec<EnergyDrain>,
    /// Weekly history of capacity and cycle count, oldest first (`<History>` in the XML).
    pub capacity_history: Vec<CapacityPeriod>,
    /// Entries in the XML that were dropped because a required attribute was missing or invalid.
    pub skipped_entries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Battery {
    pub manufacturer: Option<String>,
    pub chemistry: Option<String>,
    pub design_capacity_mwh: Option<u64>,
    pub full_charge_capacity_mwh: Option<u64>,
    pub cycle_count: Option<u32>,
}

impl Battery {
    /// How much of the design capacity is gone, in percent. `None` when either capacity is
    /// missing or the design capacity is zero.
    pub fn wear_percent(&self) -> Option<f64> {
        let design = self.design_capacity_mwh.filter(|d| *d > 0)? as f64;
        let full = self.full_charge_capacity_mwh? as f64;
        Some(((design - full) / design * 100.0).max(0.0))
    }
}

/// Which capacity an estimate assumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBasis {
    Design,
    FullCharge,
}

/// How long a full battery of the given capacity lasts at the measured average draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEstimate {
    pub basis: RuntimeBasis,
    pub capacity_mwh: Option<u64>,
    pub active_runtime: Option<Duration>,
    pub connected_standby_runtime: Option<Duration>,
}

/// What the machine was doing during one stretch of the recent usage log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageKind {
    Active,
    Suspend,
    ConnectedStandby,
    /// The last row, written when the report was generated.
    ReportGenerated,
    /// Any other `EntryType`, kept as the XML spelled it.
    Other(String),
}

impl UsageKind {
    fn from_xml(value: &str) -> UsageKind {
        match value {
            "Active" => UsageKind::Active,
            "Suspend" => UsageKind::Suspend,
            "ConnectedStandby" => UsageKind::ConnectedStandby,
            "ReportGenerated" => UsageKind::ReportGenerated,
            other => UsageKind::Other(other.to_owned()),
        }
    }
}

/// One row of `<RecentUsage>`: a state that began at `at` and lasted `duration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageEntry {
    pub at: Timestamp,
    pub duration: Duration,
    pub on_ac: bool,
    pub kind: UsageKind,
    pub charge_capacity_mwh: Option<u64>,
    /// Negative while charging.
    pub discharge_mw: Option<i64>,
    pub full_charge_capacity_mwh: Option<u64>,
}

/// One row of `<EnergyDrains>`: charge at the start and end of a stretch on battery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnergyDrain {
    pub start: Timestamp,
    pub end: Timestamp,
    pub start_charge_mwh: Option<u64>,
    pub start_full_charge_mwh: Option<u64>,
    pub end_charge_mwh: Option<u64>,
    pub end_full_charge_mwh: Option<u64>,
}

impl EnergyDrain {
    /// Energy lost over the stretch, in mWh. `None` when either charge is missing.
    pub fn drained_mwh(&self) -> Option<i64> {
        Some(self.start_charge_mwh? as i64 - self.end_charge_mwh? as i64)
    }
}

/// One row of `<History>`: capacity and use over a period of days to weeks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityPeriod {
    pub start: Timestamp,
    pub end: Timestamp,
    pub design_capacity_mwh: Option<u64>,
    pub full_charge_capacity_mwh: Option<u64>,
    pub cycle_count: Option<u32>,
    pub active_ac_time: Option<Duration>,
    pub active_dc_time: Option<Duration>,
    pub connected_standby_ac_time: Option<Duration>,
    pub connected_standby_dc_time: Option<Duration>,
    pub active_dc_energy_mwh: Option<u64>,
    pub estimated_design_active_time: Option<Duration>,
    pub estimated_full_charge_active_time: Option<Duration>,
}

/// Why a report could not be parsed. Always data for the caller, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatteryReportError {
    /// The bytes are not text in an encoding this module knows.
    Encoding(&'static str),
    /// The XML is malformed.
    Xml(String),
    /// The XML parsed but its root is not `BatteryReport`.
    NotABatteryReport,
}

impl fmt::Display for BatteryReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatteryReportError::Encoding(what) => write!(f, "battery report encoding: {what}"),
            BatteryReportError::Xml(what) => write!(f, "battery report XML: {what}"),
            BatteryReportError::NotABatteryReport => f.write_str("not a battery report"),
        }
    }
}

impl std::error::Error for BatteryReportError {}

/// Decode the bytes of a report file into text.
///
/// `powercfg` writes UTF-16LE with a byte order mark. UTF-16BE, UTF-8 with or without a mark, and
/// UTF-16LE without a mark are accepted too. A trailing odd byte, which cannot be a UTF-16 code
/// unit, is ignored.
pub fn decode_report(bytes: &[u8]) -> Result<String, BatteryReportError> {
    let utf16 = |body: &[u8], from_pair: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| from_pair(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, body @ ..] => Ok(utf16(body, u16::from_le_bytes)),
        [0xFE, 0xFF, body @ ..] => Ok(utf16(body, u16::from_be_bytes)),
        [0xEF, 0xBB, 0xBF, body @ ..] => utf8(body),
        // No mark: XML starts with '<', so a zero in the second byte means UTF-16LE.
        [b'<', 0, ..] => Ok(utf16(bytes, u16::from_le_bytes)),
        [] => Err(BatteryReportError::Encoding("empty file")),
        _ => utf8(bytes),
    }
}

fn utf8(bytes: &[u8]) -> Result<String, BatteryReportError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| BatteryReportError::Encoding("neither UTF-16 nor UTF-8"))
}

/// Parse a report from the bytes of the file, decoding as [`decode_report`] does.
pub fn parse_battery_report_bytes(bytes: &[u8]) -> Result<BatteryReport, BatteryReportError> {
    parse_battery_report(&decode_report(bytes)?)
}

/// Parse decoded report text.
///
/// Elements and attributes are matched by name only, so a newer report version with extra fields
/// still parses. A row missing the timestamp that places it on a timeline is dropped and counted in
/// [`BatteryReport::skipped_entries`].
pub fn parse_battery_report(xml: &str) -> Result<BatteryReport, BatteryReportError> {
    let mut report = BatteryReport {
        scanned_at: None,
        report_start: None,
        platform_role: None,
        connected_standby: None,
        batteries: Vec::new(),
        runtime_estimates: Vec::new(),
        recent_usage: Vec::new(),
        energy_drains: Vec::new(),
        capacity_history: Vec::new(),
        skipped_entries: 0,
    };
    let mut reader = Reader::from_str(xml);
    let mut path: Vec<String> = Vec::new();
    let mut text = String::new();
    let mut battery: Option<Battery> = None;
    let mut estimate: Option<RuntimeEstimate> = None;
    let mut saw_root = false;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| BatteryReportError::Xml(e.to_string()))?;
        match event {
            Event::Start(start) => {
                path.push(local_name(&start));
                text.clear();
                if path.len() == 1 {
                    if path[0] != "BatteryReport" {
                        return Err(BatteryReportError::NotABatteryReport);
                    }
                    saw_root = true;
                }
                match path_str(&path).as_slice() {
                    ["BatteryReport", "Batteries", "Battery"] => {
                        battery = Some(Battery {
                            manufacturer: None,
                            chemistry: None,
                            design_capacity_mwh: None,
                            full_charge_capacity_mwh: None,
                            cycle_count: None,
                        });
                    }
                    [
                        "BatteryReport",
                        "RuntimeEstimates",
                        basis @ ("DesignCapacity" | "FullChargeCapacity"),
                    ] => {
                        estimate = Some(RuntimeEstimate {
                            basis: if *basis == "DesignCapacity" {
                                RuntimeBasis::Design
                            } else {
                                RuntimeBasis::FullCharge
                            },
                            capacity_mwh: None,
                            active_runtime: None,
                            connected_standby_runtime: None,
                        });
                    }
                    _ => {}
                }
                // A row written as <Row a="1"></Row> instead of <Row a="1"/> is the same row.
                row(&path, &start, &mut report);
            }
            Event::Empty(start) => {
                path.push(local_name(&start));
                if path.len() == 1 {
                    if path[0] != "BatteryReport" {
                        return Err(BatteryReportError::NotABatteryReport);
                    }
                    saw_root = true;
                }
                row(&path, &start, &mut report);
                path.pop();
            }
            Event::Text(t) => text.push_str(&t.xml10_content()),
            Event::GeneralRef(r) => {
                // Only the five predefined entities and character references can appear here.
                if let Ok(Some(c)) = r.resolve_char_ref() {
                    text.push(c);
                } else if let Some(s) = resolve_predefined_entity(&r.xml10_content()) {
                    text.push_str(s);
                }
            }
            Event::End(_) => {
                let value = text.trim();
                match path_str(&path).as_slice() {
                    ["BatteryReport", "ReportInformation", "ScanTime"] => {
                        report.scanned_at = value.parse().ok();
                    }
                    ["BatteryReport", "ReportInformation", "ReportStartTime"] => {
                        report.report_start = value.parse().ok();
                    }
                    ["BatteryReport", "SystemInformation", "PlatformRole"] => {
                        report.platform_role = non_empty(value);
                    }
                    ["BatteryReport", "SystemInformation", "ConnectedStandby"] => {
                        report.connected_standby = parse_flag(value);
                    }
                    ["BatteryReport", "Batteries", "Battery", field] => {
                        if let Some(b) = battery.as_mut() {
                            match *field {
                                "Manufacturer" => b.manufacturer = non_empty(value),
                                "Chemistry" => b.chemistry = non_empty(value),
                                "DesignCapacity" => b.design_capacity_mwh = value.parse().ok(),
                                "FullChargeCapacity" => {
                                    b.full_charge_capacity_mwh = value.parse().ok();
                                }
                                "CycleCount" => b.cycle_count = value.parse().ok(),
                                _ => {}
                            }
                        }
                    }
                    ["BatteryReport", "Batteries", "Battery"] => {
                        report.batteries.extend(battery.take());
                    }
                    ["BatteryReport", "RuntimeEstimates", _, field] => {
                        if let Some(e) = estimate.as_mut() {
                            match *field {
                                "Capacity" => e.capacity_mwh = value.parse().ok(),
                                "ActiveRuntime" => e.active_runtime = parse_iso_duration(value),
                                "ConnectedStandbyRuntime" => {
                                    e.connected_standby_runtime = parse_iso_duration(value);
                                }
                                _ => {}
                            }
                        }
                    }
                    ["BatteryReport", "RuntimeEstimates", _] => {
                        report.runtime_estimates.extend(estimate.take());
                    }
                    _ => {}
                }
                path.pop();
                text.clear();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !saw_root {
        return Err(BatteryReportError::NotABatteryReport);
    }
    Ok(report)
}

fn local_name(start: &BytesStart<'_>) -> String {
    let name = start.local_name();
    let name: &str = name.as_ref();
    name.to_owned()
}

fn path_str(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_flag(value: &str) -> Option<bool> {
    match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// `PT3H40M14S` or `P3DT8H3M14S`. Days count as 24 hours.
fn parse_iso_duration(value: &str) -> Option<Duration> {
    let span: Span = value.parse().ok()?;
    let signed = span.to_duration(SpanRelativeTo::days_are_24_hours()).ok()?;
    Duration::try_from(signed).ok()
}

/// A duration in the report's usage rows: 100 ns ticks.
fn ticks(value: Option<&String>) -> Option<Duration> {
    let ticks: u64 = value?.parse().ok()?;
    Some(Duration::from_nanos(ticks.checked_mul(100)?))
}

/// Handle the attribute rows of the three row-shaped sections.
fn row(path: &[String], start: &BytesStart<'_>, report: &mut BatteryReport) {
    let section = match path_str(path).as_slice() {
        ["BatteryReport", "RecentUsage", "UsageEntry"] => Section::Usage,
        ["BatteryReport", "EnergyDrains", "Drain"] => Section::Drain,
        ["BatteryReport", "History", "HistoryEntry"] => Section::History,
        _ => return,
    };
    let attrs = attributes(start);
    let ts = |name: &str| attrs.get(name).and_then(|v| v.parse::<Timestamp>().ok());
    let u64_of = |name: &str| attrs.get(name).and_then(|v| v.parse::<u64>().ok());
    let u32_of = |name: &str| attrs.get(name).and_then(|v| v.parse::<u32>().ok());
    let iso = |name: &str| attrs.get(name).and_then(|v| parse_iso_duration(v));
    match section {
        Section::Usage => match ts("Timestamp") {
            Some(at) => report.recent_usage.push(UsageEntry {
                at,
                duration: ticks(attrs.get("Duration")).unwrap_or_default(),
                on_ac: attrs.get("Ac").map(String::as_str) == Some("1"),
                kind: UsageKind::from_xml(attrs.get("EntryType").map_or("", String::as_str)),
                charge_capacity_mwh: u64_of("ChargeCapacity"),
                discharge_mw: attrs.get("Discharge").and_then(|v| v.parse().ok()),
                full_charge_capacity_mwh: u64_of("FullChargeCapacity"),
            }),
            None => report.skipped_entries += 1,
        },
        Section::Drain => match (ts("StartTimestamp"), ts("EndTimestamp")) {
            (Some(start), Some(end)) => report.energy_drains.push(EnergyDrain {
                start,
                end,
                start_charge_mwh: u64_of("StartChargeCapacity"),
                start_full_charge_mwh: u64_of("StartFullChargeCapacity"),
                end_charge_mwh: u64_of("EndChargeCapacity"),
                end_full_charge_mwh: u64_of("EndFullChargeCapacity"),
            }),
            _ => report.skipped_entries += 1,
        },
        Section::History => match (ts("StartDate"), ts("EndDate")) {
            (Some(start), Some(end)) => report.capacity_history.push(CapacityPeriod {
                start,
                end,
                design_capacity_mwh: u64_of("DesignCapacity"),
                full_charge_capacity_mwh: u64_of("FullChargeCapacity"),
                cycle_count: u32_of("CycleCount"),
                active_ac_time: iso("ActiveAcTime"),
                active_dc_time: iso("ActiveDcTime"),
                connected_standby_ac_time: iso("CsAcTime"),
                connected_standby_dc_time: iso("CsDcTime"),
                active_dc_energy_mwh: u64_of("ActiveDcEnergy"),
                estimated_design_active_time: iso("EstimatedDesignActiveTime"),
                estimated_full_charge_active_time: iso("EstimatedFullChargeActiveTime"),
            }),
            _ => report.skipped_entries += 1,
        },
    }
}

enum Section {
    Usage,
    Drain,
    History,
}

fn attributes(start: &BytesStart<'_>) -> HashMap<String, String> {
    start
        .attributes()
        .flatten()
        .filter_map(|attr| {
            let key = attr.key.local_name();
            let key: &str = key.as_ref();
            let key = key.to_owned();
            let value = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .ok()?
                .into_owned();
            Some((key, value))
        })
        .collect()
}

/// Run `powercfg /batteryreport /xml` and parse what it wrote.
///
/// A machine with no battery gives [`Access::Missing`], decided from the power status API rather
/// than from `powercfg` output. The temporary report is created per run and deleted before
/// returning. The report window is whatever `powercfg` chooses (the last seven days here).
#[cfg(windows)]
pub fn read_battery_report() -> Sourced<BatteryReport> {
    use crate::power;

    let source = SourceId::BatteryReport;
    // Native check first, so a desktop is "missing" and not a failed `powercfg` run.
    let status = power::power_source();
    if status
        .data
        .first()
        .is_some_and(|s| s.battery_present == Some(false))
    {
        return Sourced::unreadable(source, Access::Missing);
    }
    let file = match run::generate() {
        Ok(file) => file,
        Err(access) => return Sourced::unreadable(source, access),
    };
    let bytes = match std::fs::read(file.path()) {
        Ok(bytes) => bytes,
        Err(e) => return Sourced::unreadable(source, run::io_access(&e)),
    };
    drop(file);
    match parse_battery_report_bytes(&bytes) {
        Ok(report) if report.batteries.is_empty() => Sourced::unreadable(source, Access::Missing),
        Ok(report) => Sourced::ok(source, vec![report]),
        Err(e) => Sourced::unreadable(
            source,
            Access::Failed {
                code: 0,
                message: e.to_string(),
            },
        ),
    }
}

#[cfg(windows)]
mod run {
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use pcsleuth_core::Access;

    /// `powercfg` normally finishes in a second or two.
    const TIMEOUT: Duration = Duration::from_secs(30);
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// A per-run report file inside a fresh directory with a random 128-bit name, so no other
    /// process can guess the path ahead of time (this may run elevated, writing under the user's
    /// temp folder). The directory and the file are deleted when this is dropped, also on early
    /// return.
    pub(super) struct TempReport {
        dir: PathBuf,
        file: PathBuf,
    }

    impl TempReport {
        pub(super) fn new() -> std::io::Result<TempReport> {
            let dir = crate::power::create_output_dir()?;
            let file = dir.join("battery.xml");
            Ok(TempReport { dir, file })
        }

        pub(super) fn path(&self) -> &Path {
            &self.file
        }
    }

    impl Drop for TempReport {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub(super) fn io_access(e: &std::io::Error) -> Access {
        match e.kind() {
            std::io::ErrorKind::NotFound => Access::Missing,
            std::io::ErrorKind::PermissionDenied => Access::NeedsAdmin,
            _ => Access::Failed {
                code: e.raw_os_error().unwrap_or(0) as u32,
                message: e.to_string(),
            },
        }
    }

    /// Run `powercfg` by full path and return the file it wrote. The system directory comes from
    /// `GetSystemDirectoryW`, never from an environment variable, because this may run elevated.
    pub(super) fn generate() -> Result<TempReport, Access> {
        let exe = crate::power::system_directory()
            .map_err(|e| io_access(&e))?
            .join("powercfg.exe");
        let file = TempReport::new().map_err(|e| io_access(&e))?;
        let mut child = Command::new(&exe)
            .args(["/batteryreport", "/xml", "/output"])
            .arg(file.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| io_access(&e))?;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < TIMEOUT => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Access::Failed {
                        code: 0,
                        message: "powercfg did not finish within 30 seconds".into(),
                    });
                }
                Err(e) => {
                    // Do not leave a child running that nobody is waiting for.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io_access(&e));
                }
            }
        };
        if status.success() && file.path().exists() {
            Ok(file)
        } else {
            Err(Access::Failed {
                code: status.code().unwrap_or(0) as u32,
                message: format!("powercfg exited with {status}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../../fixtures/battery/battery-report.xml");

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn fixture_is_utf16_with_a_mark_and_decodes() {
        assert_eq!(&FIXTURE[..2], &[0xFF, 0xFE]);
        let text = decode_report(FIXTURE).unwrap();
        assert!(text.starts_with("<?xml"));
        assert!(text.trim_end().ends_with("</BatteryReport>"));
    }

    #[test]
    fn decode_tolerates_a_trailing_odd_byte_and_other_encodings() {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend("<a/>".encode_utf16().flat_map(u16::to_le_bytes));
        bytes.push(0x0A);
        assert_eq!(decode_report(&bytes).unwrap(), "<a/>");

        let mut be = vec![0xFE, 0xFF];
        be.extend("<a/>".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode_report(&be).unwrap(), "<a/>");

        let mut bom8 = vec![0xEF, 0xBB, 0xBF];
        bom8.extend("<a/>".as_bytes());
        assert_eq!(decode_report(&bom8).unwrap(), "<a/>");

        let no_mark: Vec<u8> = "<a/>".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_report(&no_mark).unwrap(), "<a/>");
        assert_eq!(decode_report(b"<a/>").unwrap(), "<a/>");
        assert!(decode_report(&[]).is_err());
        assert!(decode_report(&[0xC3, 0x28]).is_err());
    }

    #[test]
    fn fixture_batteries_runtime_and_report_header() {
        let report = parse_battery_report_bytes(FIXTURE).unwrap();
        assert_eq!(report.scanned_at, Some(ts("2026-11-03T18:06:08Z")));
        assert_eq!(report.report_start, Some(ts("2026-10-27T18:06:04Z")));
        assert_eq!(report.platform_role.as_deref(), Some("Mobile"));
        assert_eq!(report.connected_standby, Some(false));
        assert_eq!(report.skipped_entries, 0);

        assert_eq!(report.batteries.len(), 1);
        let battery = &report.batteries[0];
        assert_eq!(battery.chemistry.as_deref(), Some("LiP"));
        assert_eq!(battery.design_capacity_mwh, Some(80_000));
        assert_eq!(battery.full_charge_capacity_mwh, Some(69_340));
        assert_eq!(battery.cycle_count, Some(184));
        let wear = battery.wear_percent().unwrap();
        assert!((wear - 13.325).abs() < 1e-9, "{wear}");

        assert_eq!(report.runtime_estimates.len(), 2);
        let design = &report.runtime_estimates[0];
        assert_eq!(design.basis, RuntimeBasis::Design);
        assert_eq!(design.capacity_mwh, Some(80_000));
        assert_eq!(
            design.active_runtime,
            Some(Duration::from_secs(3 * 3600 + 40 * 60 + 14))
        );
        assert_eq!(design.connected_standby_runtime, Some(Duration::ZERO));
        let full = &report.runtime_estimates[1];
        assert_eq!(full.basis, RuntimeBasis::FullCharge);
        assert_eq!(
            full.active_runtime,
            Some(Duration::from_secs(3 * 3600 + 10 * 60 + 53))
        );
    }

    #[test]
    fn fixture_recent_usage() {
        let report = parse_battery_report_bytes(FIXTURE).unwrap();
        let usage = &report.recent_usage;
        assert!(usage.len() > 10, "{}", usage.len());
        let first = &usage[0];
        assert_eq!(first.at, ts("2026-10-27T18:46:00Z"));
        // 31_928_524_078 ticks of 100 ns.
        assert_eq!(first.duration, Duration::from_nanos(3_192_852_407_800));
        assert!(first.on_ac);
        assert_eq!(first.kind, UsageKind::Active);
        assert_eq!(first.charge_capacity_mwh, Some(68_460));
        assert_eq!(first.full_charge_capacity_mwh, Some(70_570));
        assert_eq!(first.discharge_mw, Some(0));

        assert_eq!(usage[1].discharge_mw, Some(1410));
        assert!(!usage[1].on_ac);
        assert_eq!(usage[3].kind, UsageKind::Suspend);
        let charging = usage
            .iter()
            .find(|u| u.at == ts("2026-11-03T16:31:26Z"))
            .unwrap();
        assert!(charging.on_ac);
        assert_eq!(charging.discharge_mw, Some(-36_050));
        assert_eq!(charging.charge_capacity_mwh, Some(33_290));
        let last = usage.last().unwrap();
        assert_eq!(last.kind, UsageKind::ReportGenerated);
        assert_eq!(last.at, ts("2026-11-03T18:06:04Z"));
        assert!(usage.windows(2).all(|w| w[0].at <= w[1].at));
    }

    #[test]
    fn fixture_energy_drains_and_capacity_history() {
        let report = parse_battery_report_bytes(FIXTURE).unwrap();
        assert!(!report.energy_drains.is_empty());
        let second = &report.energy_drains[1];
        assert_eq!(second.start, ts("2026-10-27T19:39:12Z"));
        assert_eq!(second.end, ts("2026-10-27T19:42:08Z"));
        assert_eq!(second.drained_mwh(), Some(68_460 - 67_750));
        assert_eq!(report.energy_drains[0].drained_mwh(), Some(0));

        let history = &report.capacity_history;
        assert!(history.len() > 50, "{}", history.len());
        let first = &history[0];
        assert_eq!(first.start, ts("2024-01-22T09:30:40Z"));
        assert_eq!(first.design_capacity_mwh, Some(80_000));
        assert_eq!(first.full_charge_capacity_mwh, Some(78_610));
        assert_eq!(first.cycle_count, Some(23));
        // P3DT8H3M14S
        assert_eq!(
            first.active_ac_time,
            Some(Duration::from_secs(3 * 86_400 + 8 * 3600 + 3 * 60 + 14))
        );
        assert_eq!(
            first.active_dc_time,
            Some(Duration::from_secs(3600 + 57 * 60 + 59))
        );
        assert_eq!(first.active_dc_energy_mwh, Some(29_080));
        // Capacity only goes down in the fixture, which is what the wear question reads.
        let last = history.last().unwrap();
        assert!(last.full_charge_capacity_mwh < first.full_charge_capacity_mwh);
        assert!(last.cycle_count > first.cycle_count);
    }

    #[test]
    fn no_battery_report_parses_with_no_batteries() {
        let xml = r#"<?xml version="1.0"?>
<BatteryReport xmlns="http://schemas.microsoft.com/battery/2012">
  <ReportInformation><ScanTime>2026-11-03T18:06:08Z</ScanTime></ReportInformation>
  <Batteries/>
</BatteryReport>"#;
        let report = parse_battery_report(xml).unwrap();
        assert!(report.batteries.is_empty());
        assert_eq!(report.scanned_at, Some(ts("2026-11-03T18:06:08Z")));
    }

    #[test]
    fn rows_without_a_timestamp_are_counted_not_fatal() {
        let xml = r#"<BatteryReport>
  <RecentUsage>
    <UsageEntry Timestamp="not a time" Duration="1" Ac="1" EntryType="Active"/>
    <UsageEntry Timestamp="2026-10-27T18:46:00Z" Duration="x" Ac="0" EntryType="Weird"/>
  </RecentUsage>
  <EnergyDrains><Drain StartTimestamp="2026-10-27T18:46:00Z"/></EnergyDrains>
</BatteryReport>"#;
        let report = parse_battery_report(xml).unwrap();
        assert_eq!(report.skipped_entries, 2);
        assert_eq!(report.recent_usage.len(), 1);
        let entry = &report.recent_usage[0];
        assert_eq!(entry.duration, Duration::ZERO);
        assert_eq!(entry.kind, UsageKind::Other("Weird".into()));
        assert!(!entry.on_ac);
    }

    #[test]
    fn escaped_text_is_resolved() {
        let xml = r#"<BatteryReport>
  <Batteries><Battery><Manufacturer>A &amp; B &#x41;</Manufacturer></Battery></Batteries>
</BatteryReport>"#;
        let report = parse_battery_report(xml).unwrap();
        assert_eq!(report.batteries[0].manufacturer.as_deref(), Some("A & B A"));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert_eq!(
            parse_battery_report("<other/>"),
            Err(BatteryReportError::NotABatteryReport)
        );
        assert_eq!(
            parse_battery_report("plain text"),
            Err(BatteryReportError::NotABatteryReport)
        );
        assert!(matches!(
            parse_battery_report("<BatteryReport><a></b></BatteryReport>"),
            Err(BatteryReportError::Xml(_))
        ));
        assert!(parse_battery_report_bytes(&[0xFF, 0xFE, 0x3C]).is_err());
    }

    #[test]
    fn wear_needs_both_capacities() {
        let mut battery = Battery {
            manufacturer: None,
            chemistry: None,
            design_capacity_mwh: Some(0),
            full_charge_capacity_mwh: Some(1),
            cycle_count: None,
        };
        assert_eq!(battery.wear_percent(), None);
        battery.design_capacity_mwh = Some(100);
        battery.full_charge_capacity_mwh = Some(120);
        assert_eq!(battery.wear_percent(), Some(0.0));
        battery.full_charge_capacity_mwh = None;
        assert_eq!(battery.wear_percent(), None);
    }

    #[cfg(windows)]
    #[test]
    fn temp_report_is_deleted_on_drop() {
        let file = run::TempReport::new().unwrap();
        std::fs::write(file.path(), b"x").unwrap();
        let path = file.path().to_path_buf();
        let dir = path.parent().unwrap().to_path_buf();
        assert!(path.exists());
        // Its own random directory, so the path cannot be planted in advance.
        assert!(crate::power::is_output_path(&path));
        drop(file);
        assert!(!path.exists());
        assert!(!dir.exists());
    }

    #[cfg(windows)]
    #[test]
    fn two_reports_never_share_a_directory() {
        let a = run::TempReport::new().unwrap();
        let b = run::TempReport::new().unwrap();
        assert_ne!(a.path().parent(), b.path().parent());
    }

    /// Live read. A machine without a battery gives `Missing`, which is also a pass: the point is
    /// that it is never `Failed` and never a panic.
    #[cfg(windows)]
    #[test]
    fn live_battery_report() {
        let read = read_battery_report();
        assert_eq!(read.source, SourceId::BatteryReport);
        match read.access {
            Access::Ok => {
                let report = &read.data[0];
                assert!(!report.batteries.is_empty());
                assert!(report.batteries[0].design_capacity_mwh.unwrap_or(0) > 0);
                assert!(report.scanned_at.is_some());
                eprintln!(
                    "battery: {} battery, {} usage rows, {} drains, {} history rows, wear {:?}",
                    report.batteries.len(),
                    report.recent_usage.len(),
                    report.energy_drains.len(),
                    report.capacity_history.len(),
                    report.batteries[0].wear_percent()
                );
            }
            Access::Missing => assert!(read.data.is_empty()),
            other => panic!("unexpected access {other}"),
        }
    }
}
