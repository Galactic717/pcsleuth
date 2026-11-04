//! `timeline`: every event-based finding, merged, oldest first, with nothing live in it.

mod support;

use pcsleuth_core::{Access, Confidence, Question, SourceId, Sourced};
use pcsleuth_engine::timeline;
use pcsleuth_sources::eventlog::{
    ApplicationEvent, KernelPowerEvent, LifecycleEvent, PowerTroubleshooterWake, ProcessorCapped,
    ResourceExhaustion,
};
use support::{by_id, citing, events, window};

fn nothing<T>(source: SourceId) -> Sourced<T> {
    Sourced::ok(source, vec![])
}

fn input() -> timeline::Input {
    timeline::Input {
        wakes: events(
            "power-troubleshooter-1.xml",
            SourceId::EventLogSystem,
            PowerTroubleshooterWake::from_raw,
        ),
        kernel_power: events(
            "kernel-power-41.xml",
            SourceId::EventLogSystem,
            KernelPowerEvent::from_raw,
        ),
        lifecycle: events(
            "user32-1074.xml",
            SourceId::EventLogSystem,
            LifecycleEvent::from_raw,
        ),
        applications: events(
            "application-hang-1002.xml",
            SourceId::EventLogApplication,
            ApplicationEvent::from_raw,
        ),
        perf: Sourced::unreadable(SourceId::EventLogDiagnosticsPerformance, Access::NeedsAdmin),
        processor_caps: events(
            "kernel-processor-power-37.xml",
            SourceId::EventLogSystem,
            ProcessorCapped::from_raw,
        ),
        resource: nothing::<ResourceExhaustion>(SourceId::EventLogResourceExhaustion),
    }
}

#[test]
fn findings_from_every_question_are_merged_oldest_first() {
    let answer = timeline::answer(&input(), &window("2026-10-26T00:00:00Z"));
    assert_eq!(answer.question, Question::Timeline);
    let times: Vec<_> = answer.findings.iter().filter_map(|f| f.time()).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    let questions: std::collections::BTreeSet<_> = answer
        .findings
        .iter()
        .map(|f| f.question().as_str())
        .collect();
    assert!(questions.contains("wake"));
    assert!(questions.contains("crash"));
    assert!(questions.contains("slow"));
    // The first real check shows up here too.
    assert_eq!(citing(&answer.findings, "360285").id(), "wake.power_button");
    assert_eq!(
        citing(&answer.findings, "364927").confidence(),
        Confidence::NotRecorded
    );
}

#[test]
fn a_hang_appears_once_even_though_crash_and_slow_both_know_it() {
    let answer = timeline::answer(&input(), &window("2026-10-26T00:00:00Z"));
    let hangs: Vec<_> = answer
        .findings
        .iter()
        .filter(|f| {
            f.evidence()
                .iter()
                .any(|e| e.record_id.as_deref() == Some("169007"))
        })
        .collect();
    assert_eq!(hangs.len(), 1);
    assert_eq!(hangs[0].id(), "crash.app_hang");
}

#[test]
fn nothing_live_is_in_the_timeline() {
    let answer = timeline::answer(&input(), &window("2026-10-01T00:00:00Z"));
    for finding in &answer.findings {
        assert!(
            finding.time().is_some() || finding.confidence() == Confidence::NotRecorded,
            "{} is live",
            finding.id()
        );
        for evidence in finding.evidence() {
            assert!(
                evidence.record_id.is_some() || evidence.timestamp.is_some(),
                "{}",
                finding.id()
            );
        }
        for live in [
            "armed_devices",
            "timer_armed",
            "no_timers",
            "power_request",
            "top_cpu",
        ] {
            assert!(!finding.id().contains(live), "{}", finding.id());
        }
    }
    assert!(by_id(&answer.findings, "slow.past_hogs").is_empty());
    assert!(by_id(&answer.findings, "nosleep.past_blockers").is_empty());
}

#[test]
fn each_failing_source_is_a_limit_and_the_rest_still_merge() {
    let answer = timeline::answer(&input(), &window("2026-10-26T00:00:00Z"));
    assert_eq!(answer.limits.len(), 1);
    assert_eq!(
        answer.limits[0].source,
        SourceId::EventLogDiagnosticsPerformance
    );
    assert!(!answer.findings.is_empty());
}

#[test]
fn the_limit_applies_to_the_whole_timeline() {
    let mut window = window("2026-10-01T00:00:00Z");
    window.limit = 3;
    let answer = timeline::answer(&input(), &window);
    // Three dated findings, still oldest first, and one undated note about the rest.
    let times: Vec<_> = answer.findings.iter().filter_map(|f| f.time()).collect();
    assert_eq!(times.len(), 3);
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(answer.findings.len(), 4);
    assert_eq!(answer.findings[3].id(), "timeline.left_out");
    // Restarts Windows could not explain are not pushed out by wakes or shutdown requests.
    assert!(answer.findings.iter().any(|f| f.id() == "crash.power_lost"));
}
