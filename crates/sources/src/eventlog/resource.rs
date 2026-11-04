//! Resource-Exhaustion-Detector 2004: Windows diagnosed a low virtual memory condition.
//!
//! The manifest places event 2004 in the System channel; the Resource-Exhaustion-Detector
//! Operational channel holds other ids (1001, 1002, 1003 on the development machine). The native
//! reader looks in both. This machine has never logged a 2004, so the parser is built from the
//! manifest and exercised on a synthetic fixture only.

use jiff::Timestamp;
use pcsleuth_core::{Evidence, SourceId};

use super::common::{EvidenceExt, FromRawError, Meta};
use super::raw::RawEvent;

const PROVIDER: &[&str] = &["Microsoft-Windows-Resource-Exhaustion-Detector"];

/// One of the programs that consumed the most virtual memory. The manifest lists up to six.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExhaustingProcess {
    pub name: String,
    pub id: Option<u32>,
    pub created: Option<Timestamp>,
    /// Bytes: the event's own message says "consumed N bytes" for this value.
    pub commit_charge: Option<u64>,
    pub handle_count: Option<u32>,
    pub version: Option<String>,
}

/// Resource-Exhaustion-Detector 2004.
///
/// The system-wide counters are carried as reported. Their unit is not proven (the message only
/// states bytes for the per-process values), so compare them to each other, not to a size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceExhaustion {
    pub meta: Meta,
    pub system_commit_limit: Option<u64>,
    pub system_commit_charge: Option<u64>,
    pub process_commit_charge: Option<u64>,
    pub paged_pool_usage: Option<u64>,
    pub nonpaged_pool_usage: Option<u64>,
    pub physical_memory_size: Option<u64>,
    pub physical_memory_usage: Option<u64>,
    pub total_processes: Option<u32>,
    /// Largest consumers first, as the event lists them.
    pub processes: Vec<ExhaustingProcess>,
    pub generated: Option<Timestamp>,
}

impl ResourceExhaustion {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Resource-Exhaustion-Detector 2004", PROVIDER, &[2004])?;
        let processes = (1..=6)
            .filter_map(|n| {
                let p = |field: &str| format!("Process_{n}_{field}");
                Some(ExhaustingProcess {
                    name: raw.text(&p("Name"))?,
                    id: raw.u32(&p("ID")),
                    created: raw.timestamp(&p("CreationTime")),
                    commit_charge: raw.u64(&p("CommitCharge")),
                    handle_count: raw.u32(&p("HandleCount")),
                    version: raw.text(&p("Version")),
                })
            })
            .collect();
        Ok(Self {
            meta,
            system_commit_limit: raw.u64("SystemCommitLimit"),
            system_commit_charge: raw.u64("SystemCommitCharge"),
            process_commit_charge: raw.u64("ProcessCommitCharge"),
            paged_pool_usage: raw.u64("PagedPoolUsage"),
            nonpaged_pool_usage: raw.u64("NonPagedPoolUsage"),
            physical_memory_size: raw.u64("PhysicalMemorySize"),
            physical_memory_usage: raw.u64("PhysicalMemoryUsage"),
            total_processes: raw.u32("TotalProcesses"),
            processes,
            generated: raw.timestamp("EventGenerationTime"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        let mut e = self
            .meta
            .evidence(SourceId::EventLogResourceExhaustion, 2004)
            .opt("system_commit_limit", self.system_commit_limit)
            .opt("system_commit_charge", self.system_commit_charge)
            .opt("process_commit_charge", self.process_commit_charge)
            .opt("paged_pool_usage", self.paged_pool_usage)
            .opt("nonpaged_pool_usage", self.nonpaged_pool_usage)
            .opt("physical_memory_size", self.physical_memory_size)
            .opt("physical_memory_usage", self.physical_memory_usage)
            .opt("total_processes", self.total_processes)
            .opt("generated", self.generated);
        for (i, p) in self.processes.iter().enumerate() {
            let n = i + 1;
            e = e
                .with_field(format!("process_{n}"), p.name.as_str())
                .opt(&format!("process_{n}_id"), p.id)
                .opt(&format!("process_{n}_commit_bytes"), p.commit_charge)
                .opt(&format!("process_{n}_handles"), p.handle_count);
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::fixture_events;

    /// Built from the manifest of event 2004, not real validation: this machine has never run
    /// out of virtual memory.
    #[test]
    fn synthetic_2004_lists_the_biggest_consumers_in_order() {
        let raw = fixture_events("synthetic-resource-exhaustion-2004.xml").remove(0);
        let r = ResourceExhaustion::from_raw(&raw).unwrap();
        assert_eq!(r.system_commit_limit, Some(50_331_648));
        assert_eq!(r.total_processes, Some(212));
        assert_eq!(r.processes.len(), 3, "empty process slots are skipped");
        assert_eq!(r.processes[0].name, "leaky.exe");
        assert_eq!(r.processes[0].commit_charge, Some(21_474_836_480));
        assert_eq!(r.processes[0].id, Some(4242));
        assert_eq!(r.processes[2].name, "editor.exe");
        assert_eq!(r.generated, Some("2026-11-04T07:00:00.6Z".parse().unwrap()));
        let e = r.to_evidence();
        assert_eq!(e.source, SourceId::EventLogResourceExhaustion);
        assert_eq!(e.fields["process_1"], "leaky.exe");
        assert_eq!(e.fields["process_1_commit_bytes"], "21474836480");
        assert!(!e.fields.contains_key("process_4"));
    }

    #[test]
    fn other_events_are_refused() {
        let raw = fixture_events("kernel-processor-power-37.xml").remove(0);
        assert!(ResourceExhaustion::from_raw(&raw).is_err());
    }
}
