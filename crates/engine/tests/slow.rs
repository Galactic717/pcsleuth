//! `slow` over the fixtures. `synthetic-*` fixtures were built by hand from provider manifests.

mod support;

use pcsleuth_core::{Access, Confidence, RecordedProcess, RecorderRow, SourceId, Sourced};
use pcsleuth_engine::slow;
use pcsleuth_sources::eventlog::{
    AppHang, ApplicationEvent, PerfEvent, ProcessorCapped, ResourceExhaustion,
};
use pcsleuth_sources::srum::{AppUsage, Usage};
use support::{by_id, citing, events, ts, window};

fn nothing<T>(source: SourceId) -> Sourced<T> {
    Sourced::ok(source, vec![])
}

fn input() -> slow::Input {
    slow::Input {
        perf: Sourced::unreadable(SourceId::EventLogDiagnosticsPerformance, Access::NeedsAdmin),
        applications: nothing(SourceId::EventLogApplication),
        processor_caps: nothing(SourceId::EventLogSystem),
        resource: nothing(SourceId::EventLogResourceExhaustion),
        srum: Sourced::unreadable(SourceId::Srum, Access::NeedsAdmin),
        recorder: Sourced::unreadable(SourceId::Recorder, Access::Missing),
    }
}

fn perf() -> Sourced<PerfEvent> {
    events(
        "diagnostics-performance-boot.xml",
        SourceId::EventLogDiagnosticsPerformance,
        PerfEvent::from_raw,
    )
}

#[test]
fn a_boot_culprit_names_the_application_and_cites_its_record() {
    let mut input = input();
    input.perf = perf();
    let answer = slow::answer(&input, &window("2026-11-03T00:00:00Z"));
    let finding = citing(&answer.findings, "4338");
    assert_eq!(finding.id(), "slow.boot_culprit");
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(finding.headline(), "TiWorker.exe slowed the boot");
    assert!(finding.explanation().contains("5.1 s"));
    assert!(finding.explanation().contains("2.6 s more than usual"));
    assert_eq!(finding.evidence()[0].fields["process"], "TiWorker.exe");
    assert_eq!(
        finding.evidence()[0].source,
        SourceId::EventLogDiagnosticsPerformance
    );
    // Culprits under two seconds of extra time are left out as noise: record 4326 (1.4 s).
    assert!(
        answer
            .findings
            .iter()
            .all(|f| f.evidence().first().and_then(|e| e.record_id.as_deref()) != Some("4326"))
    );
}

#[test]
fn a_session_manager_step_is_not_called_a_process() {
    let mut input = input();
    input.perf = perf();
    let answer = slow::answer(&input, &window("2026-11-03T00:00:00Z"));
    let finding = citing(&answer.findings, "4332");
    assert_eq!(finding.id(), "slow.boot_culprit");
    assert!(!finding.evidence()[0].fields.contains_key("process"));
    assert!(finding.headline().contains("SMSSInit"));
}

#[test]
fn only_a_boot_windows_calls_slower_than_usual_gets_a_summary() {
    let mut input = input();
    input.perf = perf();
    let answer = slow::answer(&input, &window("2026-11-03T00:00:00Z"));
    let boots = by_id(&answer.findings, "slow.boot");
    assert_eq!(boots.len(), 1);
    let boot = citing(&answer.findings, "4328");
    assert_eq!(
        boot.headline(),
        "The boot took 68.2 s, 10.7 s slower than usual"
    );
    assert_eq!(boot.confidence(), Confidence::Recorded);
}

#[test]
fn a_slow_shutdown_is_reported_with_its_extra_time() {
    let mut input = input();
    input.perf = events(
        "diagnostics-performance-shutdown-standby.xml",
        SourceId::EventLogDiagnosticsPerformance,
        PerfEvent::from_raw,
    );
    for event in &mut input.perf.data {
        if let PerfEvent::Shutdown(shutdown) = event
            && shutdown.meta.record_id == Some(4308)
        {
            shutdown.is_degradation = Some(true);
            shutdown.time_change_ms = Some(6400);
        }
    }
    let answer = slow::answer(&input, &window("2026-11-01T00:00:00Z"));
    let finding = by_id(&answer.findings, "slow.shutdown")[0];
    assert_eq!(
        finding.headline(),
        "The shutdown took 17.3 s, 6.4 s slower than usual"
    );
    assert_eq!(by_id(&answer.findings, "slow.shutdown").len(), 1);
}

#[test]
fn without_admin_the_perf_log_is_a_limit_and_nothing_is_invented() {
    let answer = slow::answer(&input(), &window("2026-11-03T00:00:00Z"));
    let limit = answer
        .limits
        .iter()
        .find(|l| l.source == SourceId::EventLogDiagnosticsPerformance)
        .unwrap();
    assert_eq!(limit.adds.as_deref(), Some("boot and shutdown culprits"));
    assert!(
        answer
            .findings
            .iter()
            .all(|f| f.confidence() == Confidence::NotRecorded)
    );
}

#[test]
fn hangs_are_reported_with_the_program_name() {
    let mut input = input();
    input.applications = events(
        "application-hang-1002.xml",
        SourceId::EventLogApplication,
        ApplicationEvent::from_raw,
    );
    let answer = slow::answer(&input, &window("2026-10-26T00:00:00Z"));
    let finding = citing(&answer.findings, "169007");
    assert_eq!(finding.id(), "slow.app_hang");
    assert_eq!(finding.evidence()[0].fields["process"], "dllhost.exe");
    assert_eq!(by_id(&answer.findings, "slow.app_hang").len(), 2);
    // Keep the type in the import list honest.
    let _ = std::mem::size_of::<AppHang>();
}

#[test]
fn processors_slowed_by_the_firmware_are_one_finding_with_a_gap() {
    let mut input = input();
    input.processor_caps = events(
        "kernel-processor-power-37.xml",
        SourceId::EventLogSystem,
        ProcessorCapped::from_raw,
    );
    let answer = slow::answer(&input, &window("2026-11-03T00:00:00Z"));
    let caps = by_id(&answer.findings, "slow.cpu_capped");
    assert_eq!(caps.len(), 1);
    let finding = caps[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "The firmware slowed 3 processors for up to 71 s"
    );
    assert_eq!(finding.evidence().len(), 3);
    assert!(finding.explanation().contains("17, 18, 19"));
    assert!(finding.gap().unwrap().what.contains("why the firmware"));
    assert!(
        finding
            .evidence()
            .iter()
            .all(|e| !e.fields.contains_key("process"))
    );
}

#[test]
fn low_memory_names_the_programs_windows_listed() {
    let mut input = input();
    input.resource = events(
        "synthetic-resource-exhaustion-2004.xml",
        SourceId::EventLogResourceExhaustion,
        ResourceExhaustion::from_raw,
    );
    let answer = slow::answer(&input, &window("2026-11-04T00:00:00Z"));
    let finding = by_id(&answer.findings, "slow.low_memory")[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "Windows ran low on memory, and leaky.exe was using the most"
    );
    assert!(finding.explanation().contains("leaky.exe 20.0 GB"));
    let names: Vec<_> = finding
        .evidence()
        .iter()
        .map(|e| e.fields["process"].as_str())
        .collect();
    assert_eq!(names, ["leaky.exe", "browser.exe", "editor.exe"]);
    assert!(
        finding
            .evidence()
            .iter()
            .all(|e| e.record_id.as_deref() == Some("900030"))
    );
}

fn bucket(app: &str, hour: &str, usage: Usage) -> AppUsage {
    AppUsage {
        app: app.into(),
        user: None,
        hour: ts(hour),
        usage,
    }
}

#[test]
fn srum_totals_name_the_heaviest_apps_when_it_was_readable() {
    let gib = 1_073_741_824;
    let mut input = input();
    input.srum = Sourced::ok(
        SourceId::Srum,
        vec![
            bucket(
                r"\Device\HarddiskVolume3\Tools\copier.exe",
                "2026-11-03T10:00:00Z",
                Usage {
                    bytes_read: 3 * gib,
                    bytes_written: gib,
                    cpu_cycles_background: 1_000,
                    ..Usage::default()
                },
            ),
            bucket(
                r"\Device\HarddiskVolume3\Tools\copier.exe",
                "2026-11-03T11:00:00Z",
                Usage {
                    bytes_written: gib,
                    ..Usage::default()
                },
            ),
            bucket(
                "svchost.exe",
                "2026-11-03T11:00:00Z",
                Usage {
                    bytes_read: gib / 2,
                    cpu_cycles_foreground: 9_000,
                    ..Usage::default()
                },
            ),
            // Before the window: must not count.
            bucket(
                "old.exe",
                "2026-10-01T11:00:00Z",
                Usage {
                    bytes_read: 90 * gib,
                    ..Usage::default()
                },
            ),
        ],
    );
    let answer = slow::answer(&input, &window("2026-11-01T00:00:00Z"));
    let disk = by_id(&answer.findings, "slow.heavy_disk");
    assert_eq!(disk.len(), 2);
    assert_eq!(disk[0].evidence()[0].fields["process"], "copier.exe");
    assert_eq!(disk[0].headline(), "copier.exe read and wrote 5.0 GB");
    assert_eq!(disk[0].confidence(), Confidence::Recorded);
    assert_eq!(
        disk[0].evidence()[0].timestamp,
        Some(ts("2026-11-03T11:00:00Z"))
    );
    let cpu = by_id(&answer.findings, "slow.heavy_cpu");
    assert_eq!(cpu[0].evidence()[0].fields["process"], "svchost.exe");
    assert!(cpu[0].explanation().contains("90%"));
    assert!(answer.findings.iter().all(|f| {
        f.evidence()
            .iter()
            .all(|e| e.fields.get("process").map(String::as_str) != Some("old.exe"))
    }));
    // srum is readable so there is no limit for it.
    assert!(answer.limits.iter().all(|l| l.source != SourceId::Srum));
}

fn row(at: &str, cpu: &[(&str, u32)], io: &[(&str, u64)]) -> RecorderRow {
    let process = |name: &str, cpu_permille: u32, io: u64| RecordedProcess {
        name: name.into(),
        cpu_permille,
        io_bytes_per_sec: io,
    };
    RecorderRow {
        at: ts(at),
        interval_secs: 10,
        top_cpu: cpu.iter().map(|(n, c)| process(n, *c, 0)).collect(),
        top_io: io.iter().map(|(n, b)| process(n, 0, *b)).collect(),
        power_requests: vec![],
    }
}

#[test]
fn recorder_rows_make_sampled_findings_and_the_past_is_then_not_empty() {
    let mut input = input();
    input.recorder = Sourced::ok(
        SourceId::Recorder,
        vec![
            row(
                "2026-11-03T20:00:00Z",
                &[("build.exe", 400), ("calm.exe", 20)],
                &[],
            ),
            row(
                "2026-11-03T20:00:10Z",
                &[("build.exe", 600)],
                &[("copier.exe", 50_000_000)],
            ),
            row("2026-11-03T20:00:20Z", &[("calm.exe", 30)], &[]),
        ],
    );
    let answer = slow::answer(&input, &window("2026-11-03T00:00:00Z"));
    let cpu = by_id(&answer.findings, "slow.recorder_cpu");
    assert_eq!(cpu.len(), 1);
    assert_eq!(cpu[0].confidence(), Confidence::Sampled);
    assert_eq!(
        cpu[0].headline(),
        "build.exe was busy on the CPU in 2 of 3 recorder samples"
    );
    assert!(
        cpu[0]
            .explanation()
            .contains("50% of the whole machine on average")
    );
    assert!(cpu[0].explanation().contains("every 10 s"));
    assert_eq!(cpu[0].evidence()[0].fields["process"], "build.exe");
    assert_eq!(cpu[0].evidence()[0].fields["interval_secs"], "10");
    let io = by_id(&answer.findings, "slow.recorder_io");
    assert_eq!(io[0].evidence()[0].fields["process"], "copier.exe");
    assert!(by_id(&answer.findings, "slow.past_hogs").is_empty());
}

#[test]
fn past_hogs_are_not_recorded_and_the_answer_says_what_would_capture_them() {
    let answer = slow::answer(&input(), &window("2026-11-03T00:00:00Z"));
    let past = by_id(&answer.findings, "slow.past_hogs")[0];
    assert_eq!(past.confidence(), Confidence::NotRecorded);
    let gap = past.gap().unwrap();
    assert!(gap.what.contains("CPU or disk"));
    assert!(gap.would_capture.contains("recorder"));
    assert!(gap.would_capture.contains("--elevate"));
    for finding in &answer.findings {
        for evidence in finding.evidence() {
            assert!(!evidence.fields.contains_key("process"));
        }
    }
}
