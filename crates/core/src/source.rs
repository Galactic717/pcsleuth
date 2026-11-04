//! Sources, and what reading one can return.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Every place pcsleuth reads from. These are the sources named in the table of `docs/PLAN.md`.
///
/// Event logs are one variant per channel because access is decided per channel. When you add a
/// variant, also add it to [`SourceId::ALL`], [`SourceId::as_str`] and [`SourceId::elevation_adds`];
/// the last two are exhaustive matches, so the compiler points at them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceId {
    /// System channel: Power-Troubleshooter, Kernel-Power, Kernel-Processor-Power, EventLog,
    /// User32, BugCheck and storage events.
    EventLogSystem,
    /// Application channel: Application Error, Application Hang, Windows Error Reporting.
    EventLogApplication,
    /// Resource-Exhaustion-Detector channel.
    EventLogResourceExhaustion,
    /// Diagnostics-Performance channel (boot and shutdown culprits). Denied without admin.
    EventLogDiagnosticsPerformance,
    /// Sleep timeouts from the active power scheme (`PowerReadACValueIndex`).
    PowerSettings,
    /// Execution state flags, power source and last user input.
    PowerState,
    /// Devices armed to wake the machine (`DevicePowerEnumDevices`).
    ArmedDevices,
    /// Live power requests with their owners. Needs admin.
    PowerRequests,
    /// Live wake timers. Needs admin.
    WakeTimers,
    /// Battery report XML from `powercfg /batteryreport /xml`.
    BatteryReport,
    /// SRUM database: per-app energy, IO and network use. Needs admin.
    Srum,
    /// Scheduled tasks that may wake the machine.
    ScheduledTasks,
    /// Running processes by CPU, memory and IO.
    Processes,
    /// The opt-in recorder's ring file.
    Recorder,
}

impl SourceId {
    /// Every variant, for commands that report on all sources such as `doctor`.
    pub const ALL: [SourceId; 14] = [
        SourceId::EventLogSystem,
        SourceId::EventLogApplication,
        SourceId::EventLogResourceExhaustion,
        SourceId::EventLogDiagnosticsPerformance,
        SourceId::PowerSettings,
        SourceId::PowerState,
        SourceId::ArmedDevices,
        SourceId::PowerRequests,
        SourceId::WakeTimers,
        SourceId::BatteryReport,
        SourceId::Srum,
        SourceId::ScheduledTasks,
        SourceId::Processes,
        SourceId::Recorder,
    ];

    /// The name used in JSON and in the command line output.
    pub const fn as_str(self) -> &'static str {
        match self {
            SourceId::EventLogSystem => "event_log_system",
            SourceId::EventLogApplication => "event_log_application",
            SourceId::EventLogResourceExhaustion => "event_log_resource_exhaustion",
            SourceId::EventLogDiagnosticsPerformance => "event_log_diagnostics_performance",
            SourceId::PowerSettings => "power_settings",
            SourceId::PowerState => "power_state",
            SourceId::ArmedDevices => "armed_devices",
            SourceId::PowerRequests => "power_requests",
            SourceId::WakeTimers => "wake_timers",
            SourceId::BatteryReport => "battery_report",
            SourceId::Srum => "srum",
            SourceId::ScheduledTasks => "scheduled_tasks",
            SourceId::Processes => "processes",
            SourceId::Recorder => "recorder",
        }
    }

    /// What running elevated would add for this source, as a short phrase, or `None` when
    /// elevation adds nothing.
    pub const fn elevation_adds(self) -> Option<&'static str> {
        match self {
            SourceId::EventLogDiagnosticsPerformance => Some("boot and shutdown culprits"),
            SourceId::PowerRequests => Some("live power requests with their owners"),
            SourceId::WakeTimers => Some("live wake timers"),
            SourceId::Srum => Some("per-app energy, IO and network use"),
            SourceId::ScheduledTasks => Some("scheduled tasks hidden from this user"),
            SourceId::EventLogSystem
            | SourceId::EventLogApplication
            | SourceId::EventLogResourceExhaustion
            | SourceId::PowerSettings
            | SourceId::PowerState
            | SourceId::ArmedDevices
            | SourceId::BatteryReport
            | SourceId::Processes
            | SourceId::Recorder => None,
        }
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a source could or could not do. It is data, never a panic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Access {
    /// Fully readable.
    Ok,
    /// Windows denied the read; an elevated run may succeed.
    NeedsAdmin,
    /// The log exists but is switched off, so nothing was recorded.
    LogDisabled,
    /// The log, file or feature does not exist on this machine.
    Missing,
    /// Read, but not all of it: records were unreadable or a limit was hit. `data` holds what was
    /// read, and `message` says what is missing.
    Partial { message: String },
    /// Anything else. `code` is the Win32 error or HRESULT, `message` is opaque text for display.
    Failed { code: u32, message: String },
}

impl Access {
    /// True when the source was fully readable.
    pub fn is_ok(&self) -> bool {
        matches!(self, Access::Ok)
    }

    /// True when an elevated run could read what this run could not.
    pub fn elevation_helps(&self) -> bool {
        matches!(self, Access::NeedsAdmin)
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Access::Ok => f.write_str("ok"),
            Access::NeedsAdmin => f.write_str("needs admin"),
            Access::LogDisabled => f.write_str("log disabled"),
            Access::Missing => f.write_str("missing"),
            Access::Partial { message } => write!(f, "partial: {message}"),
            Access::Failed { code, message } => write!(f, "failed (0x{code:08x}): {message}"),
        }
    }
}

/// What a source could not do, and what elevation would add. One per unreadable source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    pub source: SourceId,
    pub access: Access,
    /// What an elevated run would add. Set only when elevation helps, otherwise `None`.
    pub adds: Option<String>,
}

impl Limit {
    /// The limit for a read that ended with `access`, or `None` when the source was fully readable.
    pub fn new(source: SourceId, access: Access) -> Option<Limit> {
        if access.is_ok() {
            return None;
        }
        let adds = access
            .elevation_helps()
            .then(|| source.elevation_adds())
            .flatten()
            .map(String::from);
        Some(Limit {
            source,
            access,
            adds,
        })
    }
}

/// The result of reading one source. Every source read returns this, so an unreadable source is
/// data the engine can report, not an error it must handle.
///
/// `data` may hold some records even when `access` is not [`Access::Ok`], for example when a read
/// failed part way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sourced<T> {
    pub source: SourceId,
    pub access: Access,
    pub data: Vec<T>,
}

impl<T> Sourced<T> {
    /// A fully readable source. `data` may be empty: nothing happened in the window.
    pub fn ok(source: SourceId, data: Vec<T>) -> Self {
        Sourced {
            source,
            access: Access::Ok,
            data,
        }
    }

    /// A source that could not be read (or not fully), with no records.
    pub fn unreadable(source: SourceId, access: Access) -> Self {
        Sourced {
            source,
            access,
            data: Vec::new(),
        }
    }

    /// The limit to report for this read, or `None` when it was fully readable.
    pub fn limit(&self) -> Option<Limit> {
        Limit::new(self.source, self.access.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn all_lists_each_source_once_and_names_match_json() {
        let names: BTreeSet<_> = SourceId::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), SourceId::ALL.len());
        for source in SourceId::ALL {
            let json = serde_json::to_string(&source).unwrap();
            assert_eq!(json, format!("\"{}\"", source.as_str()));
        }
    }

    #[test]
    fn access_json_shape() {
        let failed = Access::Failed {
            code: 5,
            message: "Access is denied".into(),
        };
        assert_eq!(
            serde_json::to_string(&failed).unwrap(),
            r#"{"kind":"failed","code":5,"message":"Access is denied"}"#
        );
        assert_eq!(
            serde_json::to_string(&Access::NeedsAdmin).unwrap(),
            r#"{"kind":"needs_admin"}"#
        );
        let back: Access = serde_json::from_str(r#"{"kind":"log_disabled"}"#).unwrap();
        assert_eq!(back, Access::LogDisabled);
    }

    #[test]
    fn readable_source_has_no_limit() {
        let read = Sourced::ok(SourceId::EventLogSystem, vec![1, 2, 3]);
        assert_eq!(read.limit(), None);
    }

    #[test]
    fn needs_admin_limit_says_what_elevation_adds() {
        let read: Sourced<u8> = Sourced::unreadable(SourceId::PowerRequests, Access::NeedsAdmin);
        let limit = read.limit().unwrap();
        assert_eq!(
            limit.adds.as_deref(),
            Some("live power requests with their owners")
        );
        assert!(read.data.is_empty());
    }

    #[test]
    fn other_limits_do_not_promise_elevation() {
        for access in [
            Access::LogDisabled,
            Access::Missing,
            Access::Failed {
                code: 1,
                message: "x".into(),
            },
        ] {
            let limit = Limit::new(SourceId::Srum, access).unwrap();
            assert_eq!(limit.adds, None);
        }
    }

    #[test]
    fn access_display_is_plain() {
        assert_eq!(Access::NeedsAdmin.to_string(), "needs admin");
        let failed = Access::Failed {
            code: 0x8007_0005,
            message: "denied".into(),
        };
        assert_eq!(failed.to_string(), "failed (0x80070005): denied");
    }
}
