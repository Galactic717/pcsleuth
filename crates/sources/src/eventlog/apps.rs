//! Application channel records: Application Error 1000, Application Hang 1002 and Windows Error
//! Reporting 1001.

use pcsleuth_core::{Evidence, SourceId};

use super::common::{EvidenceExt, FromRawError, Meta};
use super::raw::RawEvent;

const APPLICATION_ERROR: &[&str] = &["Application Error"];
const APPLICATION_HANG: &[&str] = &["Application Hang"];
const WER: &[&str] = &["Windows Error Reporting"];
const APPLICATION: SourceId = SourceId::EventLogApplication;

/// Application Error 1000: a program crashed.
///
/// `ExceptionCode` and `FaultingOffset` are written as bare hex (`c0000005`), `ProcessId` as `0x`
/// hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppCrash {
    pub meta: Meta,
    pub app_name: String,
    pub app_version: Option<String>,
    pub module_name: Option<String>,
    pub module_version: Option<String>,
    pub exception_code: Option<u32>,
    pub fault_offset: Option<u64>,
    pub process_id: Option<u32>,
    pub app_path: Option<String>,
    pub module_path: Option<String>,
    pub report_id: Option<String>,
    pub package_full_name: Option<String>,
}

impl AppCrash {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Application Error 1000", APPLICATION_ERROR, &[1000])?;
        Ok(Self {
            meta,
            app_name: raw
                .text("AppName")
                .ok_or(FromRawError::MissingField("AppName"))?,
            app_version: raw.text("AppVersion"),
            module_name: raw.text("ModuleName"),
            module_version: raw.text("ModuleVersion"),
            exception_code: raw
                .bare_hex("ExceptionCode")
                .and_then(|n| u32::try_from(n).ok()),
            fault_offset: raw.bare_hex("FaultingOffset"),
            process_id: raw.u32("ProcessId"),
            app_path: raw.text("AppPath"),
            module_path: raw.text("ModulePath"),
            report_id: raw.text("IntegratorReportId"),
            package_full_name: raw.text("PackageFullName"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(APPLICATION, 1000)
            .with_field("app_name", self.app_name.as_str())
            .opt("app_version", self.app_version.as_deref())
            .opt("module_name", self.module_name.as_deref())
            .opt("module_version", self.module_version.as_deref())
            .opt(
                "exception_code",
                self.exception_code.map(|c| format!("0x{c:08x}")),
            )
            .opt(
                "fault_offset",
                self.fault_offset.map(|o| format!("0x{o:x}")),
            )
            .opt("process_id", self.process_id)
            .opt("app_path", self.app_path.as_deref())
            .opt("module_path", self.module_path.as_deref())
            .opt("report_id", self.report_id.as_deref())
            .opt("package_full_name", self.package_full_name.as_deref())
    }
}

/// Application Hang 1002: a program stopped responding and was closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppHang {
    pub meta: Meta,
    pub app_name: String,
    pub app_version: Option<String>,
    pub process_id: Option<u32>,
    pub exe_path: Option<String>,
    pub report_id: Option<String>,
    pub package_full_name: Option<String>,
    /// `HangType`: text such as `Quiesce` or `Cross-thread`. Opaque; the values have not been
    /// enumerated.
    pub hang_type: Option<String>,
}

impl AppHang {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Application Hang 1002", APPLICATION_HANG, &[1002])?;
        Ok(Self {
            meta,
            app_name: raw
                .text("AppName")
                .ok_or(FromRawError::MissingField("AppName"))?,
            app_version: raw.text("AppVersion"),
            process_id: raw.u32("ProcessId"),
            exe_path: raw.text("ExeFileName"),
            report_id: raw.text("ReportId"),
            package_full_name: raw.text("PackageFullName"),
            hang_type: raw.text("HangType"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(APPLICATION, 1002)
            .with_field("app_name", self.app_name.as_str())
            .opt("app_version", self.app_version.as_deref())
            .opt("process_id", self.process_id)
            .opt("exe_path", self.exe_path.as_deref())
            .opt("report_id", self.report_id.as_deref())
            .opt("package_full_name", self.package_full_name.as_deref())
            .opt("hang_type", self.hang_type.as_deref())
    }
}

/// Windows Error Reporting 1001: a report was filed for a crash, hang or other fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WerReport {
    pub meta: Meta,
    pub event_name: String,
    pub bucket: Option<String>,
    pub bucket_type: Option<u32>,
    /// `P1` to `P10` up to the last non-empty one. For an application crash `P1` is usually the
    /// program, but the meaning of each position depends on `event_name`.
    pub parameters: Vec<String>,
    pub report_id: Option<String>,
    pub report_status: Option<u32>,
    /// `Response`. Localized, display only.
    pub response: Option<String>,
}

impl WerReport {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Windows Error Reporting 1001", WER, &[1001])?;
        let mut parameters: Vec<String> = (1..=10)
            .map(|n| raw.field(&format!("P{n}")).unwrap_or_default().to_owned())
            .collect();
        while parameters.last().is_some_and(String::is_empty) {
            parameters.pop();
        }
        Ok(Self {
            meta,
            event_name: raw
                .text("EventName")
                .ok_or(FromRawError::MissingField("EventName"))?,
            bucket: raw.text("Bucket"),
            bucket_type: raw.u32("BucketType"),
            parameters,
            report_id: raw.text("ReportId"),
            report_status: raw.u32("ReportStatus"),
            response: raw.text("Response"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        let mut e = self
            .meta
            .evidence(APPLICATION, 1001)
            .with_field("event_name", self.event_name.as_str())
            .opt("bucket", self.bucket.as_deref())
            .opt("bucket_type", self.bucket_type)
            .opt("report_id", self.report_id.as_deref())
            .opt(
                "report_status",
                self.report_status.map(|s| format!("0x{s:x}")),
            )
            .opt("response_localized", self.response.as_deref());
        for (i, p) in self.parameters.iter().enumerate() {
            if !p.is_empty() {
                e = e.with_field(format!("p{}", i + 1), p.as_str());
            }
        }
        e
    }
}

/// Any Application channel record that this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationEvent {
    Crash(AppCrash),
    Hang(AppHang),
    Report(WerReport),
}

impl ApplicationEvent {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        match (raw.provider.as_deref(), raw.event_id) {
            (Some("Application Error"), Some(1000)) => AppCrash::from_raw(raw).map(Self::Crash),
            (Some("Application Hang"), Some(1002)) => AppHang::from_raw(raw).map(Self::Hang),
            (Some("Windows Error Reporting"), Some(1001)) => {
                WerReport::from_raw(raw).map(Self::Report)
            }
            _ => Err(FromRawError::WrongEvent {
                expected: "Application Error 1000, Application Hang 1002 or Windows Error Reporting 1001",
                provider: raw.provider.clone(),
                event_id: raw.event_id,
            }),
        }
    }

    pub fn meta(&self) -> &Meta {
        match self {
            Self::Crash(e) => &e.meta,
            Self::Hang(e) => &e.meta,
            Self::Report(e) => &e.meta,
        }
    }

    pub fn to_evidence(&self) -> Evidence {
        match self {
            Self::Crash(e) => e.to_evidence(),
            Self::Hang(e) => e.to_evidence(),
            Self::Report(e) => e.to_evidence(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::{fixture_events, record};

    #[test]
    fn app_crash_reads_hex_codes() {
        let c = AppCrash::from_raw(&record("application-error-1000.xml", 168745)).unwrap();
        assert_eq!(c.app_name, "RedactedApp.exe");
        assert_eq!(c.module_name.as_deref(), Some("ntdll.dll"));
        assert_eq!(c.exception_code, Some(0xc000_0006));
        assert_eq!(c.fault_offset, Some(0x489d7));
        assert_eq!(c.process_id, Some(0x7428));
        assert_eq!(
            c.module_path.as_deref(),
            Some(r"C:\WINDOWS\SYSTEM32\ntdll.dll")
        );
        let e = c.to_evidence();
        assert_eq!(e.source, SourceId::EventLogApplication);
        assert_eq!(e.fields["exception_code"], "0xc0000006");
        assert!(
            !e.fields.contains_key("package_full_name"),
            "blank fields leave no evidence"
        );
        let all: Vec<_> = fixture_events("application-error-1000.xml");
        assert_eq!(all.len(), 6);
        assert!(all.iter().all(|r| AppCrash::from_raw(r).is_ok()));
    }

    #[test]
    fn app_hang_keeps_hang_type_as_text() {
        let h = AppHang::from_raw(&record("application-hang-1002.xml", 169007)).unwrap();
        assert_eq!(h.app_name, "dllhost.exe");
        assert_eq!(h.hang_type.as_deref(), Some("Quiesce"));
        assert_eq!(h.process_id, Some(0x2e80));
        assert_eq!(
            h.package_full_name
                .as_deref()
                .map(|p| p.starts_with("Microsoft.OneDriveSync")),
            Some(true)
        );
        let types: Vec<_> = fixture_events("application-hang-1002.xml")
            .iter()
            .map(|r| AppHang::from_raw(r).unwrap().hang_type.unwrap())
            .collect();
        assert!(
            types.contains(&"Cross-thread".to_owned())
                && types.contains(&"Top level window is idle".to_owned())
        );
    }

    #[test]
    fn wer_report_keeps_localized_response_as_opaque_text() {
        let events = fixture_events("wer-1001.xml");
        assert_eq!(events.len(), 3);
        let w = WerReport::from_raw(&events[0]).unwrap();
        assert_eq!(w.event_name, "crashpad_log");
        assert_eq!(w.parameters[0], "MicrosoftEdgeUpdate.exe");
        assert_eq!(
            w.parameters.len(),
            4,
            "empty trailing parameters are dropped"
        );
        assert_eq!(w.bucket, None);
        assert_eq!(w.report_status, Some(268_697_600));
        assert_eq!(w.response.as_deref(), Some("Недоступно"));
        let e = w.to_evidence();
        assert_eq!(e.fields["p1"], "MicrosoftEdgeUpdate.exe");
        assert!(!e.fields.contains_key("p5"));
        assert_eq!(e.fields["response_localized"], "Недоступно");
        // Changing the localized response changes nothing else.
        let mut other = events[0].clone();
        other.data.iter_mut().for_each(|d| {
            if d.name.as_deref() == Some("Response") {
                d.value = "Not available".into();
            }
        });
        let o = WerReport::from_raw(&other).unwrap();
        assert_eq!(
            (&o.event_name, &o.parameters, o.report_status),
            (&w.event_name, &w.parameters, w.report_status)
        );
        assert!(events.iter().all(|r| WerReport::from_raw(r).is_ok()));
    }

    #[test]
    fn family_dispatch_and_wrong_events() {
        for name in [
            "application-error-1000.xml",
            "application-hang-1002.xml",
            "wer-1001.xml",
        ] {
            for raw in fixture_events(name) {
                let e = ApplicationEvent::from_raw(&raw).unwrap();
                assert_eq!(e.meta().record_id, raw.record_id);
                assert_eq!(e.to_evidence().source, SourceId::EventLogApplication);
            }
        }
        let system_event = fixture_events("user32-1074.xml").remove(0);
        assert!(ApplicationEvent::from_raw(&system_event).is_err());
        let mut nameless = record("application-hang-1002.xml", 169007);
        nameless
            .data
            .retain(|d| d.name.as_deref() != Some("AppName"));
        assert_eq!(
            AppHang::from_raw(&nameless),
            Err(FromRawError::MissingField("AppName"))
        );
    }
}
