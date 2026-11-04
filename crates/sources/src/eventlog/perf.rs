//! Microsoft-Windows-Diagnostics-Performance/Operational: boot and shutdown summaries (100, 200)
//! and the culprits that slowed them (101 to 110, 201 to 203).
//!
//! The channel is denied without admin. The fixtures were captured once, elevated, by the owner.
//!
//! The meaning of each culprit event id comes from the provider manifest's event descriptions
//! (`ProviderMetadata`, en-US): 101 application, 102 driver, 103 startup service, 104 core
//! system, 105 foreground prefetch optimizations, 106 background prefetch optimizations,
//! 107 machine policy, 108 user policy, 109 device, 110 session manager initialization; for
//! shutdown 201 application, 202 device, 203 service.

use jiff::Timestamp;
use pcsleuth_core::{Evidence, SourceId};

use super::common::{EvidenceExt, FromRawError, Meta, req_u32};
use super::raw::RawEvent;

const PROVIDER: &[&str] = &["Microsoft-Windows-Diagnostics-Performance"];
const SOURCE: SourceId = SourceId::EventLogDiagnosticsPerformance;

/// Boot or shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfPhase {
    Boot,
    Shutdown,
}

/// What kind of thing slowed the phase down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CulpritKind {
    Application,
    Driver,
    Service,
    CoreSystem,
    ForegroundPrefetch,
    BackgroundPrefetch,
    MachinePolicy,
    UserPolicy,
    Device,
    SessionManagerInit,
}

impl CulpritKind {
    fn label(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Driver => "driver",
            Self::Service => "service",
            Self::CoreSystem => "core system",
            Self::ForegroundPrefetch => "foreground prefetch",
            Self::BackgroundPrefetch => "background prefetch",
            Self::MachinePolicy => "machine policy",
            Self::UserPolicy => "user policy",
            Self::Device => "device",
            Self::SessionManagerInit => "session manager initialization",
        }
    }
}

/// The phase and kind an event id stands for, `None` for ids that are not culprits.
fn culprit(event_id: u32) -> Option<(PerfPhase, CulpritKind)> {
    use CulpritKind::*;
    use PerfPhase::*;
    Some(match event_id {
        101 => (Boot, Application),
        102 => (Boot, Driver),
        103 => (Boot, Service),
        104 => (Boot, CoreSystem),
        105 => (Boot, ForegroundPrefetch),
        106 => (Boot, BackgroundPrefetch),
        107 => (Boot, MachinePolicy),
        108 => (Boot, UserPolicy),
        109 => (Boot, Device),
        110 => (Boot, SessionManagerInit),
        201 => (Shutdown, Application),
        202 => (Shutdown, Device),
        203 => (Shutdown, Service),
        _ => return None,
    })
}

/// Event 100: how long a boot took. All times are milliseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSummary {
    pub meta: Meta,
    pub boot_start: Option<Timestamp>,
    pub boot_end: Option<Timestamp>,
    pub boot_time_ms: u32,
    pub main_path_boot_time_ms: Option<u32>,
    pub post_boot_time_ms: Option<u32>,
    pub smss_init_ms: Option<u32>,
    pub explorer_init_ms: Option<u32>,
    pub startup_apps: Option<u32>,
    pub is_degradation: Option<bool>,
    pub degradation_delta_ms: Option<u32>,
    pub root_cause_identified: Option<bool>,
}

impl BootSummary {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Diagnostics-Performance 100", PROVIDER, &[100])?;
        Ok(Self {
            meta,
            boot_start: raw.timestamp("BootStartTime"),
            boot_end: raw.timestamp("BootEndTime"),
            boot_time_ms: req_u32(raw, "BootTime")?,
            main_path_boot_time_ms: raw.u32("MainPathBootTime"),
            post_boot_time_ms: raw.u32("BootPostBootTime"),
            smss_init_ms: raw.u32("BootSmssInitTime"),
            explorer_init_ms: raw.u32("BootExplorerInitTime"),
            startup_apps: raw.u32("BootNumStartupApps"),
            is_degradation: raw.bool("BootIsDegradation"),
            degradation_delta_ms: raw.u32("BootDegradationDelta"),
            root_cause_identified: raw.bool("BootIsRootCauseIdentified"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SOURCE, 100)
            .opt("boot_start", self.boot_start)
            .opt("boot_end", self.boot_end)
            .with_field("boot_time_ms", self.boot_time_ms.to_string())
            .opt("main_path_boot_time_ms", self.main_path_boot_time_ms)
            .opt("post_boot_time_ms", self.post_boot_time_ms)
            .opt("smss_init_ms", self.smss_init_ms)
            .opt("explorer_init_ms", self.explorer_init_ms)
            .opt("startup_apps", self.startup_apps)
            .opt("is_degradation", self.is_degradation)
            .opt("degradation_delta_ms", self.degradation_delta_ms)
            .opt("root_cause_identified", self.root_cause_identified)
    }
}

/// Event 200: how long a shutdown took. All times are milliseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownSummary {
    pub meta: Meta,
    pub shutdown_start: Option<Timestamp>,
    pub shutdown_end: Option<Timestamp>,
    pub shutdown_time_ms: u32,
    pub user_session_ms: Option<u32>,
    pub system_sessions_ms: Option<u32>,
    pub pre_shutdown_notifications_ms: Option<u32>,
    pub services_ms: Option<u32>,
    pub kernel_ms: Option<u32>,
    pub is_degradation: Option<bool>,
    /// Change from the usual shutdown time. May be negative.
    pub time_change_ms: Option<i64>,
}

impl ShutdownSummary {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Diagnostics-Performance 200", PROVIDER, &[200])?;
        Ok(Self {
            meta,
            shutdown_start: raw.timestamp("ShutdownStartTime"),
            shutdown_end: raw.timestamp("ShutdownEndTime"),
            shutdown_time_ms: req_u32(raw, "ShutdownTime")?,
            user_session_ms: raw.u32("ShutdownUserSessionTime"),
            system_sessions_ms: raw.u32("ShutdownSystemSessionsTime"),
            pre_shutdown_notifications_ms: raw.u32("ShutdownPreShutdownNotificationsTime"),
            services_ms: raw.u32("ShutdownServicesTime"),
            kernel_ms: raw.u32("ShutdownKernelTime"),
            is_degradation: raw.bool("ShutdownIsDegradation"),
            time_change_ms: raw
                .field("ShutdownTimeChange")
                .and_then(|v| v.trim().parse().ok()),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SOURCE, 200)
            .opt("shutdown_start", self.shutdown_start)
            .opt("shutdown_end", self.shutdown_end)
            .with_field("shutdown_time_ms", self.shutdown_time_ms.to_string())
            .opt("user_session_ms", self.user_session_ms)
            .opt("system_sessions_ms", self.system_sessions_ms)
            .opt(
                "pre_shutdown_notifications_ms",
                self.pre_shutdown_notifications_ms,
            )
            .opt("services_ms", self.services_ms)
            .opt("kernel_ms", self.kernel_ms)
            .opt("is_degradation", self.is_degradation)
            .opt("time_change_ms", self.time_change_ms)
    }
}

/// Events 101 to 110 and 201 to 203: something made a boot or shutdown slower. Times are
/// milliseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfCulprit {
    pub meta: Meta,
    pub event_id: u32,
    pub phase: PerfPhase,
    pub kind: CulpritKind,
    /// File name, or the name of the phase for kinds that have no file (104 to 108, 110).
    pub name: String,
    /// Display text from the file's version resource, possibly localized.
    pub friendly_name: Option<String>,
    pub version: Option<String>,
    pub path: Option<String>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub start_time: Option<Timestamp>,
    pub total_time_ms: Option<u32>,
    pub degradation_time_ms: Option<u32>,
}

impl PerfCulprit {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let wrong = || FromRawError::WrongEvent {
            expected: "Diagnostics-Performance 101 to 110 or 201 to 203",
            provider: raw.provider.clone(),
            event_id: raw.event_id,
        };
        let event_id = raw.event_id.ok_or_else(wrong)?;
        let (phase, kind) = culprit(event_id).ok_or_else(wrong)?;
        let meta = Meta::expect(
            raw,
            "Diagnostics-Performance culprit",
            PROVIDER,
            &[event_id],
        )?;
        Ok(Self {
            meta,
            event_id,
            phase,
            kind,
            name: raw.text("Name").ok_or(FromRawError::MissingField("Name"))?,
            friendly_name: raw.text("FriendlyName"),
            version: raw.text("Version"),
            path: raw.text("Path"),
            product_name: raw.text("ProductName"),
            company_name: raw.text("CompanyName"),
            start_time: raw.timestamp("StartTime"),
            total_time_ms: raw.u32("TotalTime"),
            degradation_time_ms: raw.u32("DegradationTime"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SOURCE, self.event_id)
            .with_field(
                "phase",
                match self.phase {
                    PerfPhase::Boot => "boot",
                    PerfPhase::Shutdown => "shutdown",
                },
            )
            .with_field("kind", self.kind.label())
            .with_field("name", self.name.as_str())
            .opt("friendly_name", self.friendly_name.as_deref())
            .opt("version", self.version.as_deref())
            .opt("path", self.path.as_deref())
            .opt("product_name", self.product_name.as_deref())
            .opt("company_name", self.company_name.as_deref())
            .opt("start_time", self.start_time)
            .opt("total_time_ms", self.total_time_ms)
            .opt("degradation_time_ms", self.degradation_time_ms)
    }
}

/// Any Diagnostics-Performance record that this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerfEvent {
    Boot(BootSummary),
    Shutdown(ShutdownSummary),
    Culprit(PerfCulprit),
}

impl PerfEvent {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        match raw.event_id {
            Some(100) => BootSummary::from_raw(raw).map(Self::Boot),
            Some(200) => ShutdownSummary::from_raw(raw).map(Self::Shutdown),
            _ => PerfCulprit::from_raw(raw).map(Self::Culprit),
        }
    }

    pub fn meta(&self) -> &Meta {
        match self {
            Self::Boot(e) => &e.meta,
            Self::Shutdown(e) => &e.meta,
            Self::Culprit(e) => &e.meta,
        }
    }

    pub fn to_evidence(&self) -> Evidence {
        match self {
            Self::Boot(e) => e.to_evidence(),
            Self::Shutdown(e) => e.to_evidence(),
            Self::Culprit(e) => e.to_evidence(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::{fixture_events, record};

    #[test]
    fn boot_summary_from_event_100_version_2() {
        let b = BootSummary::from_raw(&record("diagnostics-performance-boot.xml", 4334)).unwrap();
        assert_eq!(b.meta.version, Some(2));
        assert_eq!(b.boot_time_ms, 63278);
        assert_eq!(b.main_path_boot_time_ms, Some(51478));
        assert_eq!(b.smss_init_ms, Some(20928));
        assert_eq!(b.startup_apps, Some(0));
        assert_eq!(b.is_degradation, Some(false));
        assert_eq!(
            b.boot_end,
            Some("2026-11-03T16:32:57.1701047Z".parse().unwrap())
        );
        let slow =
            BootSummary::from_raw(&record("diagnostics-performance-boot.xml", 4328)).unwrap();
        assert_eq!(slow.is_degradation, Some(true));
        assert_eq!(slow.degradation_delta_ms, Some(10712));
        assert_eq!(slow.root_cause_identified, Some(true));
        assert_eq!(slow.to_evidence().fields["boot_time_ms"], "68168");
    }

    #[test]
    fn culprits_know_their_phase_and_kind_from_the_event_id() {
        let events = fixture_events("diagnostics-performance-boot.xml");
        let c = PerfCulprit::from_raw(&events[0]).unwrap();
        assert_eq!(
            (c.phase, c.kind),
            (PerfPhase::Boot, CulpritKind::Application)
        );
        assert_eq!(c.name, "TiWorker.exe");
        assert_eq!(
            c.friendly_name.as_deref(),
            Some("Windows Modules Installer Worker")
        );
        assert_eq!(
            (c.total_time_ms, c.degradation_time_ms),
            (Some(5126), Some(2630))
        );
        assert_eq!(c.company_name.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(c.to_evidence().fields["kind"], "application");
        // Event 110 has only a name and two times.
        let smss =
            PerfCulprit::from_raw(&record("diagnostics-performance-boot.xml", 4332)).unwrap();
        assert_eq!(smss.kind, CulpritKind::SessionManagerInit);
        assert_eq!(smss.name, "SMSSInit");
        assert_eq!(smss.path, None);
        // Event 203 is a shutdown service, from the shutdown fixture.
        let svc = PerfCulprit::from_raw(&record(
            "diagnostics-performance-shutdown-standby.xml",
            4311,
        ))
        .unwrap();
        assert_eq!(
            (svc.phase, svc.kind),
            (PerfPhase::Shutdown, CulpritKind::Service)
        );
        assert_eq!(svc.degradation_time_ms, Some(915));
    }

    #[test]
    fn shutdown_summary() {
        let s = ShutdownSummary::from_raw(&record(
            "diagnostics-performance-shutdown-standby.xml",
            4333,
        ))
        .unwrap();
        assert_eq!(s.shutdown_time_ms, 9957);
        assert_eq!(s.user_session_ms, Some(3685));
        assert_eq!(s.kernel_ms, Some(735));
        assert_eq!(s.is_degradation, Some(false));
        assert_eq!(s.time_change_ms, Some(0));
        assert_eq!(
            s.to_evidence().source,
            SourceId::EventLogDiagnosticsPerformance
        );
    }

    #[test]
    fn every_fixture_event_is_understood() {
        for name in [
            "diagnostics-performance-boot.xml",
            "diagnostics-performance-shutdown-standby.xml",
        ] {
            for raw in fixture_events(name) {
                let e = PerfEvent::from_raw(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(e.meta().record_id, raw.record_id);
            }
        }
        let other = fixture_events("kernel-power-41.xml").remove(0);
        assert!(PerfEvent::from_raw(&other).is_err());
        // An id that is not a culprit is refused rather than guessed.
        let mut unknown = fixture_events("diagnostics-performance-boot.xml").remove(0);
        unknown.event_id = Some(150);
        assert!(PerfEvent::from_raw(&unknown).is_err());
    }
}
