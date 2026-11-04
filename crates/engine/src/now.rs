//! `now`: what is the PC doing right now?
//!
//! Two process samples about a second apart rank the busiest processes by CPU, memory and IO.
//! Power state and the awake flags come with them, and so do live power requests and wake timers
//! when the run is elevated. All of it is a live read, so none of it is dated.

use pcsleuth_core::{Answer, Evidence, Finding, Question, SourceId, Sourced};
use pcsleuth_sources::power::{AcLine, ExecutionState, PowerRequest, PowerSource, WakeTimer};
use pcsleuth_sources::processes::{ProcessRate, ProcessSample, Top, top};

use crate::common::{Findings, Limits, Window, bytes, duration, finish, live};
use crate::live::{execution_state_finding, request_findings};
use crate::wake::timer_findings;

pub struct Input {
    pub first: Sourced<ProcessSample>,
    pub second: Sourced<ProcessSample>,
    pub power_source: Sourced<PowerSource>,
    pub execution_state: Sourced<ExecutionState>,
    pub requests: Sourced<PowerRequest>,
    pub timers: Sourced<WakeTimer>,
}

/// How many processes each ranking lists.
const SHOWN: usize = 5;

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.first);
    limits.note(&input.second);
    limits.note(&input.power_source);
    limits.note(&input.execution_state);
    limits.note(&input.requests);
    limits.note(&input.timers);

    let mut out = Findings::default();
    if let (Some(first), Some(second)) = (input.first.data.first(), input.second.data.first()) {
        rankings(&top(first, second, SHOWN), second, &mut out);
    }
    power_source_finding(&input.power_source, window, &mut out);
    execution_state_finding(&input.execution_state, Question::Now, window.now, &mut out);
    request_findings(&input.requests, Question::Now, window.now, &mut out);
    timer_findings(&input.timers, Question::Now, window, &mut out);
    finish(Question::Now, window, out.0, limits)
}

fn percent(value: f64) -> String {
    if value >= 10.0 {
        format!("{value:.0}%")
    } else {
        format!("{value:.1}%")
    }
}

fn process_evidence(second: &ProcessSample, rate: &ProcessRate) -> Evidence {
    Evidence::new(SourceId::Processes)
        .at(second.taken_at)
        .with_field("process", rate.name.as_str())
        .with_field("pid", rate.pid.to_string())
        .with_field("cpu_percent", format!("{:.1}", rate.cpu_percent))
        .with_field("working_set_bytes", rate.working_set_bytes.to_string())
        .with_field(
            "io_bytes_per_sec",
            format!(
                "{:.0}",
                rate.io_read_bytes_per_sec + rate.io_write_bytes_per_sec
            ),
        )
}

fn rankings(ranked: &Top, second: &ProcessSample, out: &mut Findings) {
    if ranked.interval.is_zero() {
        return;
    }
    let measured = format!(
        "Measured over the {:.1} s between two readings of Windows' own per-process counters.",
        ranked.interval.as_secs_f64()
    );
    let unread = if second.denied > 0 {
        format!(" {} protected processes could not be read.", second.denied)
    } else {
        String::new()
    };
    let io_rate = |r: &ProcessRate| r.io_read_bytes_per_sec + r.io_write_bytes_per_sec;
    let list = |rates: &[ProcessRate], show: &dyn Fn(&ProcessRate) -> String| {
        rates
            .iter()
            .enumerate()
            .map(|(i, r)| format!("{}. {} (pid {}) {}", i + 1, r.name, r.pid, show(r)))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let evidence = |rates: &[ProcessRate]| -> Vec<Evidence> {
        rates.iter().map(|r| process_evidence(second, r)).collect()
    };

    match ranked.by_cpu.first() {
        Some(first) => out.push(Finding::recorded(
            "now.top_cpu",
            Question::Now,
            format!(
                "Busiest on the CPU right now: {} ({} of the machine)",
                first.name,
                percent(first.cpu_percent)
            ),
            format!(
                "{measured} Shares are of the whole machine ({} logical processors). {}.{unread}",
                second.logical_cpus,
                list(&ranked.by_cpu, &|r| percent(r.cpu_percent)),
            ),
            evidence(&ranked.by_cpu),
        )),
        None => out.push(Finding::recorded(
            "now.top_cpu",
            Question::Now,
            "Nothing used noticeable CPU in the last second",
            format!("{measured} No process used any CPU time.{unread}"),
            [Evidence::new(SourceId::Processes)
                .at(second.taken_at)
                .with_field("processes_using_cpu", "0")],
        )),
    }
    if let Some(first) = ranked.by_memory.first() {
        out.push(Finding::recorded(
            "now.top_memory",
            Question::Now,
            format!(
                "Using the most memory right now: {} ({})",
                first.name,
                bytes(first.working_set_bytes)
            ),
            format!(
                "Memory is the working set, the part of a process currently held in RAM. {}.{unread}",
                list(&ranked.by_memory, &|r| bytes(r.working_set_bytes)),
            ),
            evidence(&ranked.by_memory),
        ));
    }
    if let Some(first) = ranked.by_io.first() {
        out.push(Finding::recorded(
            "now.top_io",
            Question::Now,
            format!(
                "Busiest on IO right now: {} ({}/s)",
                first.name,
                bytes(io_rate(first) as u64)
            ),
            format!(
                "{measured} IO counts disk, network and other transfers together, so a high rate \
                 does not by itself mean the disk. {}.{unread}",
                list(&ranked.by_io, &|r| format!(
                    "{}/s",
                    bytes(io_rate(r) as u64)
                )),
            ),
            evidence(&ranked.by_io),
        ));
    }
}

fn power_source_finding(source: &Sourced<PowerSource>, window: &Window, out: &mut Findings) {
    let Some(power) = source.data.first() else {
        return;
    };
    let level = power
        .battery_percent
        .map(|p| format!("{p}%"))
        .unwrap_or_default();
    let saver = if power.battery_saver {
        " (battery saver is on)"
    } else {
        ""
    };
    let headline = match (power.ac_line, power.battery_present) {
        (AcLine::Offline, _) => {
            let left = power
                .battery_remaining
                .map(|d| format!(", about {} left", duration(d)))
                .unwrap_or_default();
            if level.is_empty() {
                format!("Running on battery{left}{saver}")
            } else {
                format!("Running on battery: {level}{left}{saver}")
            }
        }
        (AcLine::Online, Some(true)) if power.charging => {
            format!("Plugged in and charging: {level}{saver}")
        }
        (AcLine::Online, Some(true)) if !level.is_empty() => {
            format!("Plugged in, not charging: {level}{saver}")
        }
        (AcLine::Online, _) => format!("Plugged in{saver}"),
        (AcLine::Unknown, _) => "Windows did not say whether the PC is plugged in".to_owned(),
    };
    out.push(Finding::recorded(
        "now.power_source",
        Question::Now,
        headline,
        "From Windows' power status.",
        [live(SourceId::PowerState, window.now)
            .with_field("ac_line", format!("{:?}", power.ac_line))
            .with_field("charging", power.charging.to_string())],
    ));
}
