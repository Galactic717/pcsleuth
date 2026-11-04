//! What to ask the Event Log for, and how to read its answers. Pure: the OS calls are in
//! `native.rs`.

use jiff::Timestamp;
use jiff::tz::TimeZone;
use pcsleuth_core::{Access, SourceId};

pub const SYSTEM: &str = "System";
pub const APPLICATION: &str = "Application";
pub const RESOURCE_EXHAUSTION: &str = "Microsoft-Windows-Resource-Exhaustion-Detector/Operational";
pub const DIAGNOSTICS_PERFORMANCE: &str = "Microsoft-Windows-Diagnostics-Performance/Operational";
pub const TASK_SCHEDULER: &str = "Microsoft-Windows-TaskScheduler/Operational";

/// The source a channel is reported as, `None` for channels this crate does not know.
pub fn source_for_channel(channel: &str) -> Option<SourceId> {
    let is = |name: &str| channel.eq_ignore_ascii_case(name);
    if is(SYSTEM) {
        Some(SourceId::EventLogSystem)
    } else if is(APPLICATION) {
        Some(SourceId::EventLogApplication)
    } else if is(RESOURCE_EXHAUSTION) {
        Some(SourceId::EventLogResourceExhaustion)
    } else if is(DIAGNOSTICS_PERFORMANCE) {
        Some(SourceId::EventLogDiagnosticsPerformance)
    } else if is(TASK_SCHEDULER) {
        Some(SourceId::ScheduledTasks)
    } else {
        None
    }
}

/// The channel behind an event log source, for `doctor` to pass to `channel_status`.
pub fn channel_for_source(source: SourceId) -> Option<&'static str> {
    match source {
        SourceId::EventLogSystem => Some(SYSTEM),
        SourceId::EventLogApplication => Some(APPLICATION),
        SourceId::EventLogResourceExhaustion => Some(RESOURCE_EXHAUSTION),
        SourceId::EventLogDiagnosticsPerformance => Some(DIAGNOSTICS_PERFORMANCE),
        SourceId::ScheduledTasks => Some(TASK_SCHEDULER),
        _ => None,
    }
}

/// A group of records that one typed reader wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Power-Troubleshooter 1.
    Wakes,
    /// Kernel-Power 41, 42, 105, 107, 172, 506, 507.
    KernelPower,
    /// Kernel-Processor-Power 37.
    ProcessorPower,
    /// EventLog 6005, 6006, 6008, 6009, User32 1074 and bugcheck 1001.
    Lifecycle,
    /// Application Error 1000, Application Hang 1002, Windows Error Reporting 1001.
    Applications,
    /// Resource-Exhaustion-Detector 2004.
    ResourceExhaustion,
    /// Diagnostics-Performance 100 to 110 and 200 to 203.
    Performance,
    /// Task Scheduler 100, 102, 107, 110, 200, 201.
    Tasks,
}

/// Provider name and inclusive event id ranges.
type Filter = (&'static str, &'static [(u32, u32)]);

impl Family {
    /// The source the results are reported as.
    pub fn source(self) -> SourceId {
        match self {
            Family::Wakes | Family::KernelPower | Family::ProcessorPower | Family::Lifecycle => {
                SourceId::EventLogSystem
            }
            Family::Applications => SourceId::EventLogApplication,
            Family::ResourceExhaustion => SourceId::EventLogResourceExhaustion,
            Family::Performance => SourceId::EventLogDiagnosticsPerformance,
            Family::Tasks => SourceId::ScheduledTasks,
        }
    }

    /// Channels to read, in order. Event 2004 is placed in the System channel by its manifest, the
    /// Operational channel is the one the source stands for, so both are read.
    pub fn channels(self) -> &'static [&'static str] {
        match self {
            Family::Wakes | Family::KernelPower | Family::ProcessorPower | Family::Lifecycle => {
                &[SYSTEM]
            }
            Family::Applications => &[APPLICATION],
            Family::ResourceExhaustion => &[RESOURCE_EXHAUSTION, SYSTEM],
            Family::Performance => &[DIAGNOSTICS_PERFORMANCE],
            Family::Tasks => &[TASK_SCHEDULER],
        }
    }

    fn filters(self) -> &'static [Filter] {
        match self {
            Family::Wakes => &[("Microsoft-Windows-Power-Troubleshooter", &[(1, 1)])],
            Family::KernelPower => &[(
                "Microsoft-Windows-Kernel-Power",
                &[(41, 42), (105, 105), (107, 107), (172, 172), (506, 507)],
            )],
            Family::ProcessorPower => &[("Microsoft-Windows-Kernel-Processor-Power", &[(37, 37)])],
            Family::Lifecycle => &[
                ("EventLog", &[(6005, 6006), (6008, 6009)]),
                ("User32", &[(1074, 1074)]),
                (
                    "Microsoft-Windows-WER-SystemErrorReporting",
                    &[(1001, 1001)],
                ),
            ],
            Family::Applications => &[
                ("Application Error", &[(1000, 1000)]),
                ("Application Hang", &[(1002, 1002)]),
                ("Windows Error Reporting", &[(1001, 1001)]),
            ],
            Family::ResourceExhaustion => &[(
                "Microsoft-Windows-Resource-Exhaustion-Detector",
                &[(2004, 2004)],
            )],
            Family::Performance => &[(
                "Microsoft-Windows-Diagnostics-Performance",
                &[(100, 110), (200, 203)],
            )],
            Family::Tasks => &[(
                "Microsoft-Windows-TaskScheduler",
                &[(100, 100), (102, 102), (107, 107), (110, 110), (200, 201)],
            )],
        }
    }

    /// The XPath for this family, optionally limited to records at or after `since`.
    pub fn xpath(self, since: Option<Timestamp>) -> String {
        let providers: Vec<String> = self
            .filters()
            .iter()
            .map(|(provider, ranges)| {
                let ids: Vec<String> = ranges
                    .iter()
                    .map(|&(lo, hi)| {
                        if lo == hi {
                            format!("EventID={lo}")
                        } else {
                            format!("(EventID>={lo} and EventID<={hi})")
                        }
                    })
                    .collect();
                format!("(Provider[@Name='{provider}'] and ({}))", ids.join(" or "))
            })
            .collect();
        let mut predicate = format!("({})", providers.join(" or "));
        if let Some(t) = since {
            predicate.push_str(&format!(
                " and TimeCreated[@SystemTime>='{}']",
                xpath_time(t)
            ));
        }
        format!("*[System[{predicate}]]")
    }
}

/// `2026-10-28T14:30:00.000Z`, the form the Event Log's XPath compares against.
pub fn xpath_time(t: Timestamp) -> String {
    let z = t.to_zoned(TimeZone::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        z.year(),
        z.month(),
        z.day(),
        z.hour(),
        z.minute(),
        z.second(),
        z.subsec_nanosecond() / 1_000_000
    )
}

/// `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
/// `ERROR_EVT_CHANNEL_NOT_FOUND`, what `EvtQuery` and `EvtOpenChannelConfig` return for a channel
/// that is not registered.
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

/// The Win32 error inside an HRESULT, or the HRESULT itself when it is not a Win32 one.
pub fn win32_code(hresult: i32) -> u32 {
    let h = hresult as u32;
    if h >> 16 == 0x8007 { h & 0xFFFF } else { h }
}

/// Turn an Event Log error into the access result the contract wants. `message` is Windows's own
/// text for the error, kept for display only.
pub fn access_from_code(code: u32, message: &str) -> Access {
    match code {
        ERROR_ACCESS_DENIED => Access::NeedsAdmin,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_EVT_CHANNEL_NOT_FOUND => {
            Access::Missing
        }
        code => Access::Failed {
            code,
            message: message.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels_and_sources_agree() {
        for source in [
            SourceId::EventLogSystem,
            SourceId::EventLogApplication,
            SourceId::EventLogResourceExhaustion,
            SourceId::EventLogDiagnosticsPerformance,
            SourceId::ScheduledTasks,
        ] {
            assert_eq!(
                source_for_channel(channel_for_source(source).unwrap()),
                Some(source)
            );
        }
        assert_eq!(source_for_channel("system"), Some(SourceId::EventLogSystem));
        assert_eq!(source_for_channel("Security"), None);
        assert_eq!(channel_for_source(SourceId::Srum), None);
    }

    #[test]
    fn since_is_written_the_way_xpath_compares_it() {
        let t: Timestamp = "2026-10-28T14:30:32.4608457Z".parse().unwrap();
        assert_eq!(xpath_time(t), "2026-10-28T14:30:32.460Z");
        let whole: Timestamp = "2026-01-02T03:04:05Z".parse().unwrap();
        assert_eq!(xpath_time(whole), "2026-01-02T03:04:05.000Z");
    }

    #[test]
    fn xpath_names_providers_ids_and_time() {
        assert_eq!(
            Family::Wakes.xpath(None),
            "*[System[((Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and (EventID=1)))]]"
        );
        let since: Timestamp = "2026-10-28T00:00:00Z".parse().unwrap();
        let xp = Family::KernelPower.xpath(Some(since));
        assert!(xp.contains("(EventID>=41 and EventID<=42) or EventID=105 or EventID=107"));
        assert!(xp.ends_with("and TimeCreated[@SystemTime>='2026-10-28T00:00:00.000Z']]]"));
        // Several providers are ORed, each with its own ids.
        let xp = Family::Lifecycle.xpath(None);
        assert!(xp.contains("Provider[@Name='User32'] and (EventID=1074)"));
        assert!(xp.contains("Provider[@Name='EventLog'] and ((EventID>=6005 and EventID<=6006) or (EventID>=6008 and EventID<=6009))"));
    }

    #[test]
    fn every_family_has_a_channel_a_source_and_a_balanced_xpath() {
        for family in [
            Family::Wakes,
            Family::KernelPower,
            Family::ProcessorPower,
            Family::Lifecycle,
            Family::Applications,
            Family::ResourceExhaustion,
            Family::Performance,
            Family::Tasks,
        ] {
            assert!(!family.channels().is_empty());
            let xp = family.xpath(Some(Timestamp::UNIX_EPOCH));
            assert_eq!(
                xp.matches('(').count(),
                xp.matches(')').count(),
                "{family:?}"
            );
            assert_eq!(
                xp.matches('[').count(),
                xp.matches(']').count(),
                "{family:?}"
            );
            assert!(xp.starts_with("*[System["), "{family:?}");
            assert!(channel_for_source(family.source()).is_some());
        }
    }

    #[test]
    fn errors_map_to_access() {
        assert_eq!(access_from_code(5, "denied"), Access::NeedsAdmin);
        assert_eq!(access_from_code(15007, "x"), Access::Missing);
        assert_eq!(access_from_code(2, "x"), Access::Missing);
        assert_eq!(
            access_from_code(1722, "rpc"),
            Access::Failed {
                code: 1722,
                message: "rpc".into()
            }
        );
        // HRESULT_FROM_WIN32(5) and a non-Win32 HRESULT.
        assert_eq!(win32_code(0x8007_0005_u32 as i32), 5);
        assert_eq!(win32_code(0x8000_4005_u32 as i32), 0x8000_4005);
    }
}
