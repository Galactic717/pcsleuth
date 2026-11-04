//! `slow`: why is the PC slow?
//!
//! What Windows keeps: boot and shutdown culprits (admin only), hangs, a processor slowed by the
//! firmware and Windows' own low-memory warnings. What it does not keep is which program used the
//! CPU or disk in the past, so that is "not recorded" unless the recorder (or SRUM, with admin)
//! saw it.

use pcsleuth_core::{
    Answer, Evidence, Finding, FindingError, NotRecorded, Question, RecorderRow, SourceId, Sourced,
};
use pcsleuth_sources::eventlog::{
    ApplicationEvent, BootSummary, CulpritKind, PerfCulprit, PerfEvent, PerfPhase, ProcessorCapped,
    ResourceExhaustion, ShutdownSummary,
};
use pcsleuth_sources::srum::{AppUsage, aggregate};

use crate::common::{Findings, Limits, Window, bytes, exe_name, finish, seconds_ms, stamped};
use crate::crash::{hang_evidence, hang_finding};
use crate::recorded;

pub struct Input {
    pub perf: Sourced<PerfEvent>,
    pub applications: Sourced<ApplicationEvent>,
    pub processor_caps: Sourced<ProcessorCapped>,
    pub resource: Sourced<ResourceExhaustion>,
    pub srum: Sourced<AppUsage>,
    pub recorder: Sourced<RecorderRow>,
}

/// A culprit that made a boot or shutdown less than this much slower than usual is left out.
const CULPRIT_MIN_EXTRA_MS: u32 = 2000;

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.perf);
    limits.note(&input.applications);
    limits.note(&input.processor_caps);
    limits.note(&input.resource);
    limits.note(&input.srum);
    limits.note(&input.recorder);

    let mut out = event_findings(
        &input.perf,
        &input.applications,
        &input.processor_caps,
        &input.resource,
        window,
    );
    srum_findings(&input.srum, window, &mut out);
    let rows = recorded::rows_in_window(&input.recorder, window);
    if !recorded::busy_findings(&rows, &mut out) {
        past_hogs(&input.srum, &mut out);
    }
    finish(Question::Slow, window, out.0, limits)
}

/// Everything in the logs, no live state, so the timeline can use it.
pub fn event_findings(
    perf: &Sourced<PerfEvent>,
    applications: &Sourced<ApplicationEvent>,
    processor_caps: &Sourced<ProcessorCapped>,
    resource: &Sourced<ResourceExhaustion>,
    window: &Window,
) -> Findings {
    let mut out = Findings::default();
    for event in &perf.data {
        match event {
            // Only what Windows calls slower than usual is a finding; an ordinary boot is not.
            PerfEvent::Boot(boot)
                if window.contains(boot.meta.time) && boot.is_degradation == Some(true) =>
            {
                out.push(boot_summary(boot));
            }
            PerfEvent::Shutdown(shutdown)
                if window.contains(shutdown.meta.time) && shutdown.is_degradation == Some(true) =>
            {
                out.push(shutdown_summary(shutdown));
            }
            PerfEvent::Culprit(culprit)
                if window.contains(culprit.meta.time)
                    && culprit.degradation_time_ms.unwrap_or(0) >= CULPRIT_MIN_EXTRA_MS =>
            {
                out.push(culprit_finding(culprit));
            }
            _ => {}
        }
    }
    for event in &applications.data {
        if let ApplicationEvent::Hang(hang) = event
            && window.contains(hang.meta.time)
        {
            out.push(hang_finding(
                Question::Slow,
                "slow.app_hang",
                hang,
                vec![hang_evidence(hang)],
            ));
        }
    }
    capped_processors(processor_caps, window, &mut out);
    for exhaustion in resource
        .data
        .iter()
        .filter(|e| window.contains(e.meta.time))
    {
        out.push(low_memory(exhaustion));
    }
    out
}

fn timed(finding: Finding, time: Option<jiff::Timestamp>) -> Finding {
    match time {
        Some(time) => finding.at(time),
        None => finding,
    }
}

fn boot_summary(boot: &BootSummary) -> Result<Finding, FindingError> {
    let extra = boot
        .degradation_delta_ms
        .map(|ms| format!(", {} slower than usual", seconds_ms(u64::from(ms))))
        .unwrap_or_default();
    Finding::recorded(
        "slow.boot",
        Question::Slow,
        format!(
            "The boot took {}{extra}",
            seconds_ms(u64::from(boot.boot_time_ms))
        ),
        "Windows' boot log (Diagnostics-Performance, event 100) marks this boot as slower than \
         usual. The items that slowed it are listed separately when Windows named them.",
        [stamped(boot.to_evidence(), &boot.meta)],
    )
    .map(|f| timed(f, boot.boot_end.or(boot.meta.time)))
}

fn shutdown_summary(shutdown: &ShutdownSummary) -> Result<Finding, FindingError> {
    let extra = shutdown
        .time_change_ms
        .filter(|ms| *ms > 0)
        .map(|ms| format!(", {} slower than usual", seconds_ms(ms as u64)))
        .unwrap_or_default();
    Finding::recorded(
        "slow.shutdown",
        Question::Slow,
        format!(
            "The shutdown took {}{extra}",
            seconds_ms(u64::from(shutdown.shutdown_time_ms))
        ),
        "Windows' shutdown log (Diagnostics-Performance, event 200) marks this shutdown as \
         slower than usual.",
        [stamped(shutdown.to_evidence(), &shutdown.meta)],
    )
    .map(|f| timed(f, shutdown.shutdown_end.or(shutdown.meta.time)))
}

fn culprit_finding(culprit: &PerfCulprit) -> Result<Finding, FindingError> {
    let phase = match culprit.phase {
        PerfPhase::Boot => "boot",
        PerfPhase::Shutdown => "shutdown",
    };
    let kind = match culprit.kind {
        CulpritKind::Application => "application",
        CulpritKind::Driver => "driver",
        CulpritKind::Service => "service",
        CulpritKind::CoreSystem => "core system step",
        CulpritKind::ForegroundPrefetch => "foreground prefetch step",
        CulpritKind::BackgroundPrefetch => "background prefetch step",
        CulpritKind::MachinePolicy => "machine policy step",
        CulpritKind::UserPolicy => "user policy step",
        CulpritKind::Device => "device",
        CulpritKind::SessionManagerInit => "session manager start-up step",
    };
    // Only an application is a process. A driver, service or device is named in its own field,
    // and a start-up step is a phase of Windows, so it is named nowhere.
    let mut evidence: Evidence = stamped(culprit.to_evidence(), &culprit.meta);
    let field = match culprit.kind {
        CulpritKind::Application => Some("process"),
        CulpritKind::Driver => Some("driver"),
        CulpritKind::Service => Some("service"),
        CulpritKind::Device => Some("device"),
        _ => None,
    };
    if let Some(field) = field {
        evidence = evidence.with_field(field, culprit.name.clone());
    }
    let numbers = match (culprit.total_time_ms, culprit.degradation_time_ms) {
        (Some(total), Some(extra)) => format!(
            ", taking {}, which is {} more than usual",
            seconds_ms(u64::from(total)),
            seconds_ms(u64::from(extra))
        ),
        (Some(total), None) => format!(", taking {}", seconds_ms(u64::from(total))),
        _ => String::new(),
    };
    let friendly = culprit
        .friendly_name
        .as_deref()
        .map(|name| format!(" ({name})"))
        .unwrap_or_default();
    Finding::recorded(
        format!("slow.{phase}_culprit"),
        Question::Slow,
        format!("{} slowed the {phase}", culprit.name),
        format!(
            "Windows' {phase} log (Diagnostics-Performance, event {}) lists {}{friendly} as a \
             {kind} that slowed the {phase}{numbers}.",
            culprit.event_id, culprit.name
        ),
        [evidence],
    )
    .map(|f| timed(f, culprit.meta.time))
}

fn capped_processors(caps: &Sourced<ProcessorCapped>, window: &Window, out: &mut Findings) {
    let mut records: Vec<&ProcessorCapped> = caps
        .data
        .iter()
        .filter(|c| window.contains(c.meta.time))
        .collect();
    records.sort_by_key(|c| c.meta.time);
    let mut group: Vec<&ProcessorCapped> = Vec::new();
    for record in records {
        let separate = group.last().is_some_and(|last| {
            crate::common::between(last.meta.time, record.meta.time)
                .is_none_or(|gap| gap > std::time::Duration::from_secs(60))
        });
        if separate {
            out.push(cap_finding(&group));
            group.clear();
        }
        group.push(record);
    }
    if !group.is_empty() {
        out.push(cap_finding(&group));
    }
}

fn cap_finding(group: &[&ProcessorCapped]) -> Result<Finding, FindingError> {
    let mut numbers: Vec<u32> = group.iter().map(|c| c.processor).collect();
    numbers.sort_unstable();
    numbers.dedup();
    let longest = group.iter().filter_map(|c| c.cap_duration_seconds).max();
    let count = numbers.len();
    let for_up_to = longest
        .map(|secs| format!(" for up to {secs} s"))
        .unwrap_or_default();
    Finding::recorded(
        "slow.cpu_capped",
        Question::Slow,
        format!(
            "The firmware slowed {count} {}{for_up_to}",
            if count == 1 {
                "processor"
            } else {
                "processors"
            }
        ),
        format!(
            "Windows logged (Kernel-Processor-Power, event 37) that the firmware, the PC's \
             built-in software, asked these processors to run slower: {}.",
            numbers
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        group.iter().map(|c| stamped(c.to_evidence(), &c.meta)),
    )
    .and_then(|f| {
        f.with_gap(NotRecorded::new(
            "why the firmware slowed the processors",
            "the laptop maker's own tools or firmware logs; Windows does not record the reason",
        ))
    })
    .map(|f| timed(f, group.first().and_then(|c| c.meta.time)))
}

fn low_memory(exhaustion: &ResourceExhaustion) -> Result<Finding, FindingError> {
    let base = |name: &str, commit: Option<u64>| {
        let mut e = Evidence::new(SourceId::EventLogResourceExhaustion).with_field("process", name);
        e.record_id = exhaustion.meta.record_id.map(|id| id.to_string());
        e.timestamp = exhaustion.meta.time;
        if let Some(commit) = commit {
            e = e.with_field("committed_bytes", commit.to_string());
        }
        e
    };
    let evidence: Vec<Evidence> = exhaustion
        .processes
        .iter()
        .map(|p| base(&p.name, p.commit_charge))
        .collect();
    let list: Vec<String> = exhaustion
        .processes
        .iter()
        .map(|p| match p.commit_charge {
            Some(commit) => format!("{} {}", p.name, bytes(commit)),
            None => p.name.clone(),
        })
        .collect();
    let headline = match exhaustion.processes.first() {
        Some(top) => format!(
            "Windows ran low on memory, and {} was using the most",
            top.name
        ),
        None => "Windows ran low on memory".to_owned(),
    };
    let evidence = if evidence.is_empty() {
        vec![stamped(exhaustion.to_evidence(), &exhaustion.meta)]
    } else {
        evidence
    };
    Finding::recorded(
        "slow.low_memory",
        Question::Slow,
        headline,
        format!(
            "Windows' low-memory warning (Resource-Exhaustion-Detector, event 2004) named the \
             programs holding the most memory, in the memory each has asked Windows to set \
             aside: {}.",
            list.join(", ")
        ),
        evidence,
    )
    .map(|f| timed(f, exhaustion.meta.time))
}

/// The apps SRUM counted as heaviest on disk and CPU over the window.
fn srum_findings(srum: &Sourced<AppUsage>, window: &Window, out: &mut Findings) {
    if srum.data.is_empty() {
        return;
    }
    let until = window.now + jiff::SignedDuration::from_hours(1);
    let totals = aggregate(&srum.data, window.since, until);
    let all_bytes: u64 = totals
        .iter()
        .map(|t| t.usage.bytes_read.saturating_add(t.usage.bytes_written))
        .fold(0, u64::saturating_add);
    let all_cycles: u64 = totals
        .iter()
        .map(|t| t.usage.cpu_cycles())
        .fold(0, u64::saturating_add);

    for (id, disk) in [("slow.heavy_disk", true), ("slow.heavy_cpu", false)] {
        let amount = |t: &pcsleuth_sources::srum::AppTotal| {
            if disk {
                t.usage.bytes_read.saturating_add(t.usage.bytes_written)
            } else {
                t.usage.cpu_cycles()
            }
        };
        let grand = if disk { all_bytes } else { all_cycles };
        let mut ranked: Vec<_> = totals.iter().filter(|t| amount(t) > 0).collect();
        ranked.sort_by_key(|t| std::cmp::Reverse(amount(t)));
        for total in ranked.into_iter().take(3) {
            let share = amount(total) as f64 / grand.max(1) as f64 * 100.0;
            let last_hour = srum
                .data
                .iter()
                .filter(|b| {
                    b.app == total.app && b.user == total.user && window.contains(Some(b.hour))
                })
                .map(|b| b.hour)
                .max();
            let mut evidence = Evidence::new(SourceId::Srum)
                .with_field("app", total.app.as_str())
                .with_field("hours", total.hours.to_string());
            if let Some(hour) = last_hour {
                evidence = evidence.at(hour);
            }
            let name = match exe_name(&total.app) {
                Some(exe) => {
                    evidence = evidence.with_field("process", exe.clone());
                    exe
                }
                None => total.app.clone(),
            };
            let (headline, what) = if disk {
                (
                    format!("{name} read and wrote {}", bytes(amount(total))),
                    "disk",
                )
            } else {
                (
                    format!("{name} used {share:.0}% of the CPU cycles counted"),
                    "CPU",
                )
            };
            out.push(Finding::recorded(
                id,
                Question::Slow,
                headline,
                format!(
                    "Windows' own per-app usage records (SRUM) show this app as {share:.0}% of \
                     all {what} use counted for apps in this period. The records are hourly \
                     totals, so they show who used the most but not when within the hour."
                ),
                [evidence],
            ));
        }
    }
}

fn past_hogs(srum: &Sourced<AppUsage>, out: &mut Findings) {
    let would_capture = if srum.access.elevation_helps() {
        "the pcsleuth recorder (opt-in) samples the busiest programs every few seconds; \
         pcsleuth slow --elevate adds Windows' own hourly per-app usage records (SRUM)"
    } else {
        "the pcsleuth recorder (opt-in), which samples the busiest programs every few seconds"
    };
    out.push(Finding::not_recorded(
        "slow.past_hogs",
        Question::Slow,
        "Windows did not record which program used the CPU or disk earlier",
        "Windows shows what is busy right now, and keeps no history of it except hourly \
         per-app totals that need admin. That is why pcsleuth cannot name a program that was \
         busy and has stopped.",
        NotRecorded::new(
            "which program used the CPU or disk heavily in the past",
            would_capture,
        ),
    ));
}
