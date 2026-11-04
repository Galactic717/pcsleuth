//! `now`: two process samples a second apart, plus power state. Samples are built by hand.

mod support;

use std::time::Duration;

use pcsleuth_core::{Access, Confidence, Question, SourceId, Sourced};
use pcsleuth_engine::now;
use pcsleuth_sources::power::{AcLine, ExecutionState, PowerSource};
use pcsleuth_sources::processes::{ProcessEntry, ProcessSample};
use support::{by_id, ts, window};

/// 10 s of CPU in 100 ns ticks.
const SECOND: u64 = 10_000_000;
const CREATED: u64 = 133_000_000_000_000_000;

fn entry(pid: u32, name: &str, cpu_secs: f64, working_set: u64, io: u64) -> ProcessEntry {
    ProcessEntry {
        pid,
        parent_pid: 1,
        name: name.into(),
        created: CREATED,
        cpu_time: (cpu_secs * SECOND as f64) as u64,
        working_set_bytes: working_set,
        private_bytes: working_set,
        io_read_bytes: io,
        io_write_bytes: 0,
    }
}

fn sample(at: &str, processes: Vec<ProcessEntry>, denied: u32) -> Sourced<ProcessSample> {
    Sourced::ok(
        SourceId::Processes,
        vec![ProcessSample {
            taken_at: ts(at),
            logical_cpus: 4,
            processes,
            denied,
            exited: 0,
        }],
    )
}

fn input() -> now::Input {
    let gb = 1_073_741_824;
    now::Input {
        first: sample(
            "2026-11-04T09:00:00Z",
            vec![
                entry(10, "hog.exe", 100.0, gb, 0),
                entry(11, "calm.exe", 5.0, 3 * gb / 2, 0),
                entry(12, "copier.exe", 7.0, gb / 4, 0),
                entry(13, "idle.exe", 1.0, gb / 8, 0),
            ],
            3,
        ),
        second: sample(
            "2026-11-04T09:00:01Z",
            vec![
                entry(10, "hog.exe", 102.0, gb, 0),
                entry(11, "calm.exe", 5.04, 3 * gb / 2, 0),
                entry(12, "copier.exe", 7.2, gb / 4, 32 * 1024 * 1024),
                entry(13, "idle.exe", 1.0, gb / 8, 0),
            ],
            3,
        ),
        power_source: Sourced::unreadable(SourceId::PowerState, Access::Missing),
        execution_state: Sourced::unreadable(SourceId::PowerState, Access::Missing),
        requests: Sourced::unreadable(SourceId::PowerRequests, Access::NeedsAdmin),
        timers: Sourced::unreadable(SourceId::WakeTimers, Access::NeedsAdmin),
    }
}

#[test]
fn the_busiest_process_by_cpu_is_named_with_its_share_of_the_machine() {
    let answer = now::answer(&input(), &window("2026-11-04T00:00:00Z"));
    let cpu = by_id(&answer.findings, "now.top_cpu")[0];
    assert_eq!(cpu.question(), Question::Now);
    assert_eq!(cpu.confidence(), Confidence::Recorded);
    assert_eq!(
        cpu.headline(),
        "Busiest on the CPU right now: hog.exe (50% of the machine)"
    );
    assert!(cpu.explanation().contains("1.0 s between two readings"));
    assert!(cpu.explanation().contains("4 logical processors"));
    assert!(
        cpu.explanation()
            .contains("3 protected processes could not be read")
    );
    let names: Vec<_> = cpu
        .evidence()
        .iter()
        .map(|e| e.fields["process"].as_str())
        .collect();
    assert_eq!(names, ["hog.exe", "copier.exe", "calm.exe"]);
    assert!(
        cpu.evidence()
            .iter()
            .all(|e| e.timestamp == Some(ts("2026-11-04T09:00:01Z")))
    );
    assert_eq!(cpu.evidence()[0].fields["pid"], "10");
    assert!(cpu.time().is_none());
}

#[test]
fn memory_and_io_rank_the_same_processes_differently() {
    let answer = now::answer(&input(), &window("2026-11-04T00:00:00Z"));
    let memory = by_id(&answer.findings, "now.top_memory")[0];
    assert_eq!(
        memory.headline(),
        "Using the most memory right now: calm.exe (1.5 GB)"
    );
    assert_eq!(memory.evidence()[0].fields["process"], "calm.exe");
    let io = by_id(&answer.findings, "now.top_io")[0];
    assert_eq!(
        io.headline(),
        "Busiest on IO right now: copier.exe (32.0 MB/s)"
    );
    assert!(
        io.explanation()
            .contains("disk, network and other transfers together")
    );
    assert_eq!(io.evidence().len(), 1);
}

#[test]
fn when_nothing_is_busy_it_says_so_and_names_nobody() {
    let mut input = input();
    input.second = sample(
        "2026-11-04T09:00:01Z",
        vec![entry(10, "hog.exe", 100.0, 1, 0)],
        0,
    );
    let answer = now::answer(&input, &window("2026-11-04T00:00:00Z"));
    let cpu = by_id(&answer.findings, "now.top_cpu")[0];
    assert_eq!(
        cpu.headline(),
        "Nothing used noticeable CPU in the last second"
    );
    assert!(!cpu.evidence()[0].fields.contains_key("process"));
    assert!(by_id(&answer.findings, "now.top_io").is_empty());
}

#[test]
fn power_source_and_flags_are_reported() {
    let mut input = input();
    input.power_source = Sourced::ok(
        SourceId::PowerState,
        vec![PowerSource {
            ac_line: AcLine::Offline,
            battery_present: Some(true),
            charging: false,
            battery_percent: Some(63),
            battery_remaining: Some(Duration::from_secs(2 * 3600 + 5 * 60)),
            battery_saver: false,
        }],
    );
    input.execution_state = Sourced::ok(SourceId::PowerState, vec![ExecutionState::from_bits(0)]);
    let answer = now::answer(&input, &window("2026-11-04T00:00:00Z"));
    let power = by_id(&answer.findings, "now.power_source")[0];
    assert_eq!(
        power.headline(),
        "Running on battery: 63%, about 2 h 5 min left"
    );
    assert_eq!(by_id(&answer.findings, "now.execution_state").len(), 1);

    input.power_source = Sourced::ok(
        SourceId::PowerState,
        vec![PowerSource {
            ac_line: AcLine::Online,
            battery_present: Some(true),
            charging: true,
            battery_percent: Some(40),
            battery_remaining: None,
            battery_saver: false,
        }],
    );
    let answer = now::answer(&input, &window("2026-11-04T00:00:00Z"));
    assert_eq!(
        by_id(&answer.findings, "now.power_source")[0].headline(),
        "Plugged in and charging: 40%"
    );
}

#[test]
fn elevated_only_reads_become_limits_when_unreadable() {
    let answer = now::answer(&input(), &window("2026-11-04T00:00:00Z"));
    let sources: Vec<_> = answer.limits.iter().map(|l| l.source).collect();
    assert!(sources.contains(&SourceId::PowerRequests));
    assert!(sources.contains(&SourceId::WakeTimers));
    assert!(sources.contains(&SourceId::PowerState));
    // Live requests and timers are not invented.
    assert!(by_id(&answer.findings, "now.power_request").is_empty());
    assert!(by_id(&answer.findings, "now.no_timers").is_empty());
}

#[test]
fn an_unreadable_process_list_is_a_limit_and_the_rest_still_answers() {
    let mut input = input();
    input.second = Sourced::unreadable(
        SourceId::Processes,
        Access::Failed {
            code: 5,
            message: "denied".into(),
        },
    );
    input.power_source = Sourced::ok(
        SourceId::PowerState,
        vec![PowerSource {
            ac_line: AcLine::Online,
            battery_present: Some(false),
            charging: false,
            battery_percent: None,
            battery_remaining: None,
            battery_saver: false,
        }],
    );
    let answer = now::answer(&input, &window("2026-11-04T00:00:00Z"));
    assert!(by_id(&answer.findings, "now.top_cpu").is_empty());
    assert_eq!(
        by_id(&answer.findings, "now.power_source")[0].headline(),
        "Plugged in"
    );
    assert!(
        answer
            .limits
            .iter()
            .any(|l| l.source == SourceId::Processes)
    );
}
