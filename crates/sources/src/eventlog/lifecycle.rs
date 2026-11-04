//! Boot, shutdown and crash records in the System channel: EventLog 6005, 6006, 6008 and 6009,
//! User32 1074 and WER-SystemErrorReporting 1001 (the bugcheck record).
//!
//! User32 1074 and the EventLog events carry localized text next to their structured fields
//! (ADR 0002). Only the structured fields are read for meaning; localized text is kept as opaque
//! values for display.

use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use pcsleuth_core::{Evidence, SourceId};

use super::common::{EvidenceExt, FromRawError, Meta};
use super::raw::{RawEvent, parse_number};

const EVENT_LOG: &[&str] = &["EventLog"];
const USER32: &[&str] = &["User32"];
/// Event Viewer shows the source of a bugcheck record as "BugCheck", the provider name is the first.
const BUGCHECK: &[&str] = &["Microsoft-Windows-WER-SystemErrorReporting", "BugCheck"];
const SYSTEM: SourceId = SourceId::EventLogSystem;

/// Whether the Event Log service started or stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Started,
    Stopped,
}

/// EventLog 6005 and 6006: the Event Log service started (a boot) or stopped (a clean shutdown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLogService {
    pub meta: Meta,
    pub state: ServiceState,
}

impl EventLogService {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "EventLog 6005 or 6006", EVENT_LOG, &[6005, 6006])?;
        let state = if raw.event_id == Some(6005) {
            ServiceState::Started
        } else {
            ServiceState::Stopped
        };
        Ok(Self { meta, state })
    }

    pub fn to_evidence(&self) -> Evidence {
        let (id, state) = match self.state {
            ServiceState::Started => (6005, "started"),
            ServiceState::Stopped => (6006, "stopped"),
        };
        self.meta
            .evidence(SYSTEM, id)
            .with_field("event_log_service", state)
    }
}

/// EventLog 6008: the previous shutdown was unexpected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedShutdown {
    pub meta: Meta,
    /// When the system was last known to be running, from the record's binary payload. The
    /// payload holds two SYSTEMTIME values, local time then UTC. Checked against the three
    /// records captured on this machine: the local value equals the localized time text in the
    /// record and the UTC value differs from it by the zone offset in force that day. Not a
    /// documented layout, so `None` when the payload is shorter than expected.
    pub previous_shutdown: Option<Timestamp>,
}

impl UnexpectedShutdown {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "EventLog 6008", EVENT_LOG, &[6008])?;
        let previous_shutdown = raw
            .binary
            .as_deref()
            .and_then(|b| b.get(16..32))
            .and_then(systemtime_to_timestamp);
        Ok(Self {
            meta,
            previous_shutdown,
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 6008)
            .opt("previous_shutdown", self.previous_shutdown)
    }
}

/// A Windows SYSTEMTIME (eight little-endian u16) in UTC.
fn systemtime_to_timestamp(bytes: &[u8]) -> Option<Timestamp> {
    let word = |i: usize| {
        bytes
            .get(i * 2..i * 2 + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let dt = DateTime::new(
        i16::try_from(word(0)?).ok()?,
        i8::try_from(word(1)?).ok()?,
        i8::try_from(word(3)?).ok()?,
        i8::try_from(word(4)?).ok()?,
        i8::try_from(word(5)?).ok()?,
        i8::try_from(word(6)?).ok()?,
        i32::from(word(7)?) * 1_000_000,
    )
    .ok()?;
    TimeZone::UTC.to_timestamp(dt).ok()
}

/// EventLog 6009: the operating system version at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsVersionAtBoot {
    pub meta: Meta,
    pub version: Option<String>,
    pub build: Option<String>,
    pub kernel_type: Option<String>,
}

impl OsVersionAtBoot {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "EventLog 6009", EVENT_LOG, &[6009])?;
        let at = |i| {
            raw.positional_at(i)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        Ok(Self {
            meta,
            version: at(0),
            build: at(1),
            kernel_type: at(3),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 6009)
            .opt("version", self.version.as_deref())
            .opt("build", self.build.as_deref())
            .opt("kernel_type", self.kernel_type.as_deref())
    }
}

/// User32 1074: a process asked Windows to shut down or restart.
///
/// `param3` (the reason text) and `param5` (the action: shut down, restart, power off) are
/// localized, and `param5` is the only place that says restart versus shutdown, so this type
/// cannot say which it was (ADR 0002). The process (`param1`), reason code (`param4`) and user
/// (`param7`) are structured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownInitiated {
    pub meta: Meta,
    /// Full path of the process that asked, without the trailing `(computer)` Windows appends.
    pub process: Option<String>,
    pub computer: Option<String>,
    pub reason_code: Option<u32>,
    pub user: Option<String>,
    /// `param3`. Localized, display only.
    pub reason_text: Option<String>,
    /// `param5`. Localized, display only.
    pub action_text: Option<String>,
    /// `param6`: the comment typed by whoever asked.
    pub comment: Option<String>,
}

impl ShutdownInitiated {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "User32 1074", USER32, &[1074])?;
        let param1 = raw
            .text("param1")
            .ok_or(FromRawError::MissingField("param1"))?;
        let computer = raw.text("param2");
        let process = computer
            .as_deref()
            .and_then(|c| param1.strip_suffix(&format!(" ({c})")))
            .unwrap_or(&param1)
            .to_owned();
        Ok(Self {
            meta,
            process: Some(process),
            computer,
            reason_code: raw.u32("param4"),
            user: raw.text("param7"),
            reason_text: raw.text("param3"),
            action_text: raw.text("param5"),
            comment: raw.text("param6"),
        })
    }

    /// The file name of the process, e.g. `StartMenuExperienceHost.exe`.
    pub fn process_name(&self) -> Option<&str> {
        self.process
            .as_deref()
            .map(|p| p.rsplit(['\\', '/']).next().unwrap_or(p))
    }

    /// True when the planned flag (0x80000000, SHTDN_REASON_FLAG_PLANNED in the Windows
    /// documentation of shutdown reason codes) is set in the reason code.
    pub fn is_planned(&self) -> Option<bool> {
        self.reason_code.map(|c| c & 0x8000_0000 != 0)
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 1074)
            .opt("process", self.process.as_deref())
            .opt("reason_code", self.reason_code.map(|c| format!("0x{c:x}")))
            .opt("planned", self.is_planned())
            .opt("user", self.user.as_deref())
            .opt("reason_text_localized", self.reason_text.as_deref())
            .opt("action_text_localized", self.action_text.as_deref())
            .opt("comment", self.comment.as_deref())
    }
}

/// WER-SystemErrorReporting 1001: the computer rebooted from a bugcheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bugcheck {
    pub meta: Meta,
    pub code: u32,
    pub parameters: Vec<u64>,
    pub dump_path: Option<String>,
    pub report_id: Option<String>,
}

impl Bugcheck {
    /// Reads `param1`, which Windows writes as `0x000000d1 (0x..., 0x..., 0x..., 0x...)`: hex
    /// numbers only, so it is structured even though it is a string.
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "WER-SystemErrorReporting 1001", BUGCHECK, &[1001])?;
        let mut numbers = raw
            .field("param1")
            .unwrap_or_default()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.starts_with("0x").then(|| parse_number(t)).flatten());
        let code = numbers
            .next()
            .flatten()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(FromRawError::MissingField("param1"))?;
        Ok(Self {
            meta,
            code,
            parameters: numbers.map_while(|n| n).collect(),
            dump_path: raw.text("param2"),
            report_id: raw.text("param3"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        let params = self
            .parameters
            .iter()
            .map(|p| format!("0x{p:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        self.meta
            .evidence(SYSTEM, 1001)
            .with_field("bugcheck_code", format!("0x{:08x}", self.code))
            .opt(
                "bugcheck_parameters",
                (!params.is_empty()).then_some(params),
            )
            .opt("dump_path", self.dump_path.as_deref())
            .opt("report_id", self.report_id.as_deref())
    }
}

/// Any boot, shutdown or crash record in the System channel that this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    EventLogService(EventLogService),
    UnexpectedShutdown(UnexpectedShutdown),
    OsVersionAtBoot(OsVersionAtBoot),
    ShutdownInitiated(ShutdownInitiated),
    Bugcheck(Bugcheck),
}

impl LifecycleEvent {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        match (raw.provider.as_deref(), raw.event_id) {
            (Some("EventLog"), Some(6005 | 6006)) => {
                EventLogService::from_raw(raw).map(Self::EventLogService)
            }
            (Some("EventLog"), Some(6008)) => {
                UnexpectedShutdown::from_raw(raw).map(Self::UnexpectedShutdown)
            }
            (Some("EventLog"), Some(6009)) => {
                OsVersionAtBoot::from_raw(raw).map(Self::OsVersionAtBoot)
            }
            (Some("User32"), Some(1074)) => {
                ShutdownInitiated::from_raw(raw).map(Self::ShutdownInitiated)
            }
            (_, Some(1001)) => Bugcheck::from_raw(raw).map(Self::Bugcheck),
            _ => Err(FromRawError::WrongEvent {
                expected: "EventLog 6005, 6006, 6008, 6009, User32 1074 or a bugcheck 1001",
                provider: raw.provider.clone(),
                event_id: raw.event_id,
            }),
        }
    }

    pub fn meta(&self) -> &Meta {
        match self {
            Self::EventLogService(e) => &e.meta,
            Self::UnexpectedShutdown(e) => &e.meta,
            Self::OsVersionAtBoot(e) => &e.meta,
            Self::ShutdownInitiated(e) => &e.meta,
            Self::Bugcheck(e) => &e.meta,
        }
    }

    pub fn to_evidence(&self) -> Evidence {
        match self {
            Self::EventLogService(e) => e.to_evidence(),
            Self::UnexpectedShutdown(e) => e.to_evidence(),
            Self::OsVersionAtBoot(e) => e.to_evidence(),
            Self::ShutdownInitiated(e) => e.to_evidence(),
            Self::Bugcheck(e) => e.to_evidence(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::{fixture_events, record};

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn event_log_service_and_os_version() {
        let events = fixture_events("eventlog-6005-6006-6008-6009.xml");
        let started = EventLogService::from_raw(&events[0]).unwrap();
        assert_eq!(started.state, ServiceState::Started);
        assert_eq!(started.to_evidence().fields["event_log_service"], "started");
        let stopped = EventLogService::from_raw(&events[2]).unwrap();
        assert_eq!(stopped.state, ServiceState::Stopped);
        assert_eq!(stopped.meta.time, Some(ts("2026-11-03T14:19:29.8707249Z")));
        let os = OsVersionAtBoot::from_raw(&events[1]).unwrap();
        assert_eq!(os.build.as_deref(), Some("26300"));
        assert_eq!(os.version.as_deref(), Some("10.00."));
        assert_eq!(os.kernel_type.as_deref(), Some("Multiprocessor Free"));
        assert!(EventLogService::from_raw(&events[1]).is_err());
    }

    /// The fixture re-types three real records of this laptop with the computer name redacted (the
    /// scripted capture had none in its window), so it is named synthetic and is not counted as
    /// a captured fixture.
    #[test]
    fn unexpected_shutdown_time_comes_from_the_binary_payload_not_the_localized_text() {
        let events = fixture_events("synthetic-eventlog-6008.xml");
        let times: Vec<_> = events
            .iter()
            .map(|r| UnexpectedShutdown::from_raw(r).unwrap().previous_shutdown)
            .collect();
        // Local text in the records: 0:02:43 on 01.11.2026 (UTC+2), 21:44:11 on 30.10.2026 and
        // 15:07:26 on 27.10.2026 (UTC+2 on both: summer time ended on 25 October).
        assert_eq!(times[0], Some(ts("2026-10-31T22:02:43.187Z")));
        assert_eq!(times[1], Some(ts("2026-10-30T19:44:11.827Z")));
        assert_eq!(times[2], Some(ts("2026-10-27T13:07:26.763Z")));
        let mut short = events[0].clone();
        short.binary = Some(vec![1, 2, 3]);
        assert_eq!(
            UnexpectedShutdown::from_raw(&short)
                .unwrap()
                .previous_shutdown,
            None
        );
        short.binary = None;
        assert_eq!(
            UnexpectedShutdown::from_raw(&short)
                .unwrap()
                .previous_shutdown,
            None
        );
    }

    #[test]
    fn user32_1074_gives_process_and_reason_code() {
        let r = ShutdownInitiated::from_raw(&record("user32-1074.xml", 365367)).unwrap();
        assert_eq!(
            r.process.as_deref(),
            Some(
                r"C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe"
            )
        );
        assert_eq!(r.process_name(), Some("StartMenuExperienceHost.exe"));
        assert_eq!(r.reason_code, Some(0));
        assert_eq!(r.is_planned(), Some(false));
        assert_eq!(r.user.as_deref(), Some(r"REDACTED-PC\REDACTED-USER"));
        assert_eq!(r.meta.record_id, Some(365367));
        let e = r.to_evidence();
        assert_eq!(e.fields["reason_code"], "0x0");
        assert_eq!(e.fields["planned"], "false");
    }

    #[test]
    fn user32_1074_meaning_never_depends_on_the_localized_params() {
        let real = record("user32-1074.xml", 365158);
        let baseline = ShutdownInitiated::from_raw(&real).unwrap();
        // The real record has Ukrainian reason and action text; replace both with other text, then
        // with nothing at all. Process, reason code and user must not move.
        for replacement in ["Other (Unplanned)", "shut down", ""] {
            let mut changed = real.clone();
            for d in &mut changed.data {
                if matches!(d.name.as_deref(), Some("param3" | "param5")) {
                    d.value = replacement.into();
                }
            }
            let r = ShutdownInitiated::from_raw(&changed).unwrap();
            assert_eq!(r.process, baseline.process);
            assert_eq!(r.reason_code, baseline.reason_code);
            assert_eq!(r.user, baseline.user);
            assert_eq!(r.is_planned(), baseline.is_planned());
        }
        // The localized text is carried untouched, and only for display.
        assert_eq!(baseline.action_text.as_deref(), Some("перезапустити"));
        assert_eq!(
            baseline.reason_text.as_deref(),
            Some("Інше (незаплановане)")
        );
        assert_eq!(
            baseline.to_evidence().fields["action_text_localized"],
            "перезапустити"
        );
        // Restart and power off records differ only in localized text, so they are not told apart.
        let off = ShutdownInitiated::from_raw(&record("user32-1074.xml", 365367)).unwrap();
        assert_eq!(off.reason_code, baseline.reason_code);
        assert_ne!(off.action_text, baseline.action_text);
    }

    #[test]
    fn user32_1074_planned_flag_and_missing_process() {
        let mut raw = record("user32-1074.xml", 365158);
        for d in &mut raw.data {
            if d.name.as_deref() == Some("param4") {
                d.value = "0x80030002".into();
            }
        }
        assert_eq!(
            ShutdownInitiated::from_raw(&raw).unwrap().is_planned(),
            Some(true)
        );
        raw.data.retain(|d| d.name.as_deref() != Some("param1"));
        assert_eq!(
            ShutdownInitiated::from_raw(&raw),
            Err(FromRawError::MissingField("param1"))
        );
    }

    /// Built from the manifest of WER-SystemErrorReporting 1001, not real validation: this
    /// machine has no bugcheck history.
    #[test]
    fn synthetic_bugcheck_records_parse() {
        let events = fixture_events("synthetic-wer-systemerrorreporting-1001.xml");
        let b = Bugcheck::from_raw(&events[0]).unwrap();
        assert_eq!(b.code, 0x9f);
        assert_eq!(
            b.parameters,
            [
                3,
                0xffff_a30f_1234_5678,
                0xffff_f801_2345_0000,
                0xffff_a30f_2345_6789
            ]
        );
        assert_eq!(b.dump_path.as_deref(), Some(r"C:\Windows\MEMORY.DMP"));
        assert!(b.report_id.is_some());
        assert_eq!(b.to_evidence().fields["bugcheck_code"], "0x0000009f");
        let no_dump = Bugcheck::from_raw(&events[1]).unwrap();
        assert_eq!(no_dump.code, 0x133);
        assert_eq!(no_dump.dump_path, None);
        let mut garbage = events[0].clone();
        for d in &mut garbage.data {
            if d.name.as_deref() == Some("param1") {
                d.value = "something else".into();
            }
        }
        assert_eq!(
            Bugcheck::from_raw(&garbage),
            Err(FromRawError::MissingField("param1"))
        );
    }

    #[test]
    fn family_dispatch() {
        for name in [
            "eventlog-6005-6006-6008-6009.xml",
            "synthetic-eventlog-6008.xml",
            "user32-1074.xml",
            "synthetic-wer-systemerrorreporting-1001.xml",
        ] {
            for raw in fixture_events(name) {
                let e = LifecycleEvent::from_raw(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(e.meta().record_id, raw.record_id);
                assert!(e.to_evidence().record_id.is_some());
            }
        }
        // Windows Error Reporting 1001 in the Application channel is not a bugcheck.
        let wer = fixture_events("wer-1001.xml").remove(0);
        assert!(Bugcheck::from_raw(&wer).is_err());
    }
}
