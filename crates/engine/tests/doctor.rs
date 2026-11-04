//! `doctor`: one finding per source. Nothing is applied; fixes are printed.

mod support;

use pcsleuth_core::{Access, Confidence, SourceId};
use pcsleuth_engine::doctor::{self, Probe};
use support::{by_id, window};

fn probe(source: SourceId, access: Access) -> Probe {
    Probe {
        source,
        access,
        log: None,
    }
}

fn all_ok() -> Vec<Probe> {
    SourceId::ALL
        .iter()
        .map(|source| probe(*source, Access::Ok))
        .collect()
}

fn answer(probes: Vec<Probe>) -> pcsleuth_core::Answer {
    doctor::answer(&doctor::Input { probes }, &window("2026-11-01T00:00:00Z"))
}

#[test]
fn every_source_gets_one_finding_and_a_readable_one_says_what_it_adds() {
    let answer = answer(all_ok());
    assert_eq!(answer.findings.len(), SourceId::ALL.len());
    assert!(answer.limits.is_empty());
    let system = by_id(&answer.findings, "doctor.event_log_system")[0];
    assert_eq!(system.confidence(), Confidence::Recorded);
    assert_eq!(system.headline(), "System event log: can be read");
    assert!(system.explanation().contains("wake and sleep history"));
    assert_eq!(system.evidence()[0].source, SourceId::EventLogSystem);
    assert_eq!(system.evidence()[0].fields["access"], "ok");
    for finding in &answer.findings {
        assert!(finding.id().starts_with("doctor."));
        assert!(finding.fix().is_none());
    }
}

#[test]
fn a_source_that_needs_admin_says_what_elevation_adds_and_how_to_ask() {
    let mut probes = all_ok();
    probes[3] = probe(SourceId::EventLogDiagnosticsPerformance, Access::NeedsAdmin);
    let answer = answer(probes);
    let finding = by_id(&answer.findings, "doctor.event_log_diagnostics_performance")[0];
    assert_eq!(finding.confidence(), Confidence::NotRecorded);
    assert_eq!(
        finding.headline(),
        "Boot and shutdown timing log (Diagnostics-Performance): needs admin"
    );
    assert!(
        finding
            .explanation()
            .contains("what slowed boots and shutdowns")
    );
    let gap = finding.gap().unwrap();
    assert!(gap.would_capture.contains("--elevate"));
    assert_eq!(answer.limits.len(), 1);
    assert_eq!(
        answer.limits[0].adds.as_deref(),
        Some("boot and shutdown culprits")
    );
}

#[test]
fn a_switched_off_task_scheduler_log_gets_the_exact_command_and_its_cost() {
    let mut probes = all_ok();
    let tasks = probes
        .iter_mut()
        .find(|p| p.source == SourceId::ScheduledTasks)
        .unwrap();
    tasks.access = Access::NeedsAdmin;
    tasks.log = Some(Access::LogDisabled);
    let answer = answer(probes);
    let finding = by_id(&answer.findings, "doctor.scheduled_tasks")[0];
    let fix = finding.fix().unwrap();
    assert_eq!(
        fix.command,
        "wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true"
    );
    assert!(fix.needs_admin);
    assert!(fix.explanation.contains("a little disk"));
    assert!(
        fix.explanation
            .contains("from the moment it is switched on")
    );
    assert!(fix.explanation.contains("pcsleuth does not run this"));
    assert!(finding.headline().contains("needs admin"));
    assert!(finding.headline().contains("history log is switched off"));
}

#[test]
fn an_event_log_that_is_off_gets_its_own_command() {
    let mut probes = all_ok();
    probes[1] = probe(SourceId::EventLogApplication, Access::LogDisabled);
    let answer = answer(probes);
    let finding = by_id(&answer.findings, "doctor.event_log_application")[0];
    assert_eq!(
        finding.fix().unwrap().command,
        "wevtutil sl Application /e:true"
    );
    assert_eq!(finding.headline(), "Application event log: switched off");
    assert_eq!(finding.confidence(), Confidence::NotRecorded);
}

#[test]
fn a_missing_source_and_the_recorder_are_explained_without_a_command() {
    let mut probes = all_ok();
    for p in &mut probes {
        if p.source == SourceId::Recorder || p.source == SourceId::BatteryReport {
            p.access = Access::Missing;
        }
    }
    let answer = answer(probes);
    let recorder = by_id(&answer.findings, "doctor.recorder")[0];
    assert_eq!(recorder.headline(), "pcsleuth recorder: not set up");
    assert!(
        recorder
            .explanation()
            .contains("past CPU, disk and power-request detail")
    );
    assert!(recorder.fix().is_none());
    let battery = by_id(&answer.findings, "doctor.battery_report")[0];
    assert_eq!(battery.headline(), "Battery report: missing on this PC");
}

#[test]
fn a_partial_read_says_so_and_still_counts_as_readable() {
    let mut probes = all_ok();
    probes[0] = probe(
        SourceId::EventLogSystem,
        Access::Partial {
            message: "3 records could not be read".into(),
        },
    );
    let answer = answer(probes);
    let finding = by_id(&answer.findings, "doctor.event_log_system")[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "System event log: only partly readable (3 records could not be read)"
    );
    assert!(finding.gap().is_some());
}

#[test]
fn a_failed_read_shows_the_code_and_the_rest_still_answers() {
    let mut probes = all_ok();
    probes[12] = probe(
        SourceId::Processes,
        Access::Failed {
            code: 5,
            message: "Access is denied".into(),
        },
    );
    let answer = answer(probes);
    assert_eq!(answer.findings.len(), SourceId::ALL.len());
    let finding = by_id(&answer.findings, "doctor.processes")[0];
    assert!(
        finding
            .headline()
            .contains("could not be read (0x00000005)")
    );
}
