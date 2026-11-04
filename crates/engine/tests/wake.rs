//! `wake` over the fixtures. The first two tests are the first real check from docs/PLAN.md.

mod support;

use pcsleuth_core::{Access, Confidence, Question, SourceId, Sourced};
use pcsleuth_engine::wake;
use pcsleuth_sources::eventlog::{KernelPowerEvent, PowerTroubleshooterWake};
use pcsleuth_sources::power::{ArmedDevice, Requester, WakeTimer};
use support::{by_id, citing, events, ids, ts, window};

const WAKES: &str = "power-troubleshooter-1.xml";

fn real_wakes() -> Sourced<PowerTroubleshooterWake> {
    events(
        WAKES,
        SourceId::EventLogSystem,
        PowerTroubleshooterWake::from_raw,
    )
}

fn input(wakes: Sourced<PowerTroubleshooterWake>) -> wake::Input {
    wake::Input {
        wakes,
        kernel_power: Sourced::unreadable(SourceId::EventLogSystem, Access::Missing),
        timers: Sourced::unreadable(SourceId::WakeTimers, Access::NeedsAdmin),
        armed: Sourced::unreadable(SourceId::ArmedDevices, Access::Missing),
        tasks: Sourced::unreadable(SourceId::ScheduledTasks, Access::NeedsAdmin),
    }
}

fn answer() -> pcsleuth_core::Answer {
    wake::answer(&input(real_wakes()), &window("2026-09-01T00:00:00Z"))
}

/// First real check: record 360285 reads as a Power Button wake at 2026-10-28 14:30 UTC.
#[test]
fn record_360285_is_a_power_button_wake() {
    let answer = answer();
    let finding = citing(&answer.findings, "360285");
    assert_eq!(finding.id(), "wake.power_button");
    assert_eq!(finding.question(), Question::Wake);
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert!(
        finding
            .time()
            .unwrap()
            .to_string()
            .starts_with("2026-10-28T14:30:")
    );
    assert_eq!(
        finding.headline(),
        "Woke from sleep: the power button was pressed"
    );
    assert!(finding.explanation().contains("asleep for 1 h 27 min"));
    assert!(finding.gap().is_none());
    // A power button wake names no process and no device.
    let evidence = &finding.evidence()[0];
    assert_eq!(evidence.source, SourceId::EventLogSystem);
    assert!(!evidence.fields.contains_key("process"));
    assert!(!evidence.fields.contains_key("device"));
}

/// First real check: record 364927 is a wake from hibernate that Windows did not name.
#[test]
fn record_364927_is_a_not_recorded_wake_from_hibernate() {
    let answer = answer();
    let finding = citing(&answer.findings, "364927");
    assert_eq!(finding.id(), "wake.unknown_source");
    assert_eq!(finding.confidence(), Confidence::NotRecorded);
    assert!(
        finding
            .time()
            .unwrap()
            .to_string()
            .starts_with("2026-11-03T12:33:")
    );
    assert_eq!(
        finding.headline(),
        "Woke from hibernate: Windows did not record what woke it"
    );
    assert!(finding.explanation().contains("received no wake source"));
    assert!(finding.explanation().contains("hibernate"));
    // Only what is known: no "normal", no "nothing can capture it".
    let words = finding.explanation().to_lowercase();
    assert!(!words.contains("normal") && !words.contains("nothing in windows"));
    let gap = finding.gap().unwrap();
    assert!(gap.what.contains("hibernate"));
    assert!(!gap.would_capture.trim().is_empty());
    // It keeps its record, but names nothing.
    assert_eq!(finding.evidence()[0].record_id.as_deref(), Some("364927"));
    assert!(!finding.evidence()[0].fields.contains_key("process"));
    assert!(!finding.evidence()[0].fields.contains_key("device"));
}

#[test]
fn a_device_wake_names_the_device_and_prints_the_fix() {
    let answer = answer();
    let finding = citing(&answer.findings, "360247");
    assert_eq!(finding.id(), "wake.device");
    assert_eq!(finding.confidence(), Confidence::Recorded);
    let device = "Intel(R) USB 3.10 eXtensible Host Controller - 1.20 (Microsoft)";
    assert_eq!(finding.evidence()[0].fields["device"], device);
    assert!(finding.headline().contains(device));
    let fix = finding.fix().unwrap();
    assert_eq!(
        fix.command,
        format!("powercfg /devicedisablewake \"{device}\"")
    );
    assert!(fix.needs_admin);
    // A different device, with its own name.
    let keyboard = citing(&answer.findings, "358340");
    assert_eq!(keyboard.evidence()[0].fields["device"], "USB Input Device");
}

#[test]
fn a_device_name_that_cannot_be_quoted_safely_gets_no_fix() {
    let mut wakes = real_wakes();
    for wake in &mut wakes.data {
        if wake.meta.record_id == Some(358340) {
            wake.source_text = Some("Bad \"name\" %PATH%".into());
        }
    }
    let answer = wake::answer(&input(wakes), &window("2026-09-01T00:00:00Z"));
    let finding = citing(&answer.findings, "358340");
    assert_eq!(finding.id(), "wake.device");
    assert!(finding.fix().is_none());
    assert!(
        finding
            .explanation()
            .contains("powercfg /devicequery wake_armed")
    );
}

#[test]
fn the_s4_doze_record_is_windows_moving_to_hibernate_not_a_wake() {
    let answer = answer();
    for record in ["364908", "344155"] {
        let finding = citing(&answer.findings, record);
        assert_eq!(finding.id(), "wake.sleep_to_hibernate");
        assert_eq!(finding.confidence(), Confidence::Recorded);
        assert_eq!(
            finding.headline(),
            "Windows moved the PC from sleep to hibernate by itself"
        );
        assert!(finding.explanation().contains("not as a wake"));
    }
    // 11 records, 2 of them doze records, and nothing else is dropped.
    assert_eq!(answer.findings.len(), 11);
    assert_eq!(by_id(&answer.findings, "wake.sleep_to_hibernate").len(), 2);
}

#[test]
fn every_real_hibernate_resume_admits_the_gap_and_none_names_a_cause() {
    let answer = answer();
    let unknown = by_id(&answer.findings, "wake.unknown_source");
    assert_eq!(unknown.len(), 4);
    for finding in unknown {
        assert_eq!(finding.confidence(), Confidence::NotRecorded);
        assert!(finding.headline().contains("Woke from hibernate"));
    }
}

#[test]
fn findings_are_oldest_first_so_the_latest_is_at_the_bottom() {
    let answer = answer();
    let times: Vec<_> = answer.findings.iter().filter_map(|f| f.time()).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn nothing_older_than_the_window_is_used() {
    let answer = wake::answer(&input(real_wakes()), &window("2026-10-28T00:00:00Z"));
    for finding in &answer.findings {
        for evidence in finding.evidence() {
            assert!(evidence.timestamp.unwrap() >= ts("2026-10-28T00:00:00Z"));
        }
    }
    // Records 364927, 364908, 360285 and 360247 are the only ones on or after 28 October.
    assert_eq!(answer.findings.len(), 4);
    assert_eq!(by_id(&answer.findings, "wake.device").len(), 1);
}

#[test]
fn an_unseen_wake_source_type_is_shown_as_a_number_and_not_guessed() {
    let mut wakes = real_wakes();
    for wake in &mut wakes.data {
        if wake.meta.record_id == Some(360285) {
            wake.source = pcsleuth_sources::eventlog::WakeSourceType::from_code(7);
        }
    }
    let answer = wake::answer(&input(wakes), &window("2026-09-01T00:00:00Z"));
    let finding = citing(&answer.findings, "360285");
    assert_eq!(finding.id(), "wake.other_type");
    assert_eq!(finding.headline(), "Woke from sleep (wake source type 7)");
    assert!(finding.explanation().contains("will not guess"));
    assert!(finding.gap().is_some());
    assert!(!finding.evidence()[0].fields.contains_key("process"));
}

#[test]
fn a_timer_wake_names_the_owner_and_context() {
    let mut wakes = real_wakes();
    for wake in &mut wakes.data {
        if wake.meta.record_id == Some(360285) {
            wake.source = pcsleuth_sources::eventlog::WakeSourceType::from_code(7);
            wake.timer_owner =
                Some(r"\Device\HarddiskVolume3\Tools\pcsleuth-fault-wake-timer.exe".into());
            wake.timer_context = Some("nightly job".into());
        }
    }
    let answer = wake::answer(&input(wakes), &window("2026-09-01T00:00:00Z"));
    let finding = citing(&answer.findings, "360285");
    assert_eq!(finding.id(), "wake.timer");
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "Woke from sleep: a wake timer set by pcsleuth-fault-wake-timer.exe went off"
    );
    assert!(finding.explanation().contains("nightly job"));
    let evidence = &finding.evidence()[0];
    assert_eq!(evidence.fields["process"], "pcsleuth-fault-wake-timer.exe");
    assert_eq!(evidence.record_id.as_deref(), Some("360285"));
}

#[test]
fn a_timer_owner_that_is_not_a_program_is_shown_but_not_named_as_a_process() {
    let mut wakes = real_wakes();
    for wake in &mut wakes.data {
        if wake.meta.record_id == Some(360285) {
            wake.source = pcsleuth_sources::eventlog::WakeSourceType::from_code(7);
            wake.timer_owner = Some("Windows\\UpdateOrchestrator\\Reboot".into());
        }
    }
    let answer = wake::answer(&input(wakes), &window("2026-09-01T00:00:00Z"));
    let finding = citing(&answer.findings, "360285");
    assert_eq!(finding.id(), "wake.timer");
    let evidence = &finding.evidence()[0];
    assert!(!evidence.fields.contains_key("process"));
    assert_eq!(
        evidence.fields["timer_owner"],
        "Windows\\UpdateOrchestrator\\Reboot"
    );
}

#[test]
fn modern_standby_exit_is_reported_when_no_wake_record_covers_it() {
    let kernel_power = events(
        "synthetic-kernel-power-modern-standby.xml",
        SourceId::EventLogSystem,
        KernelPowerEvent::from_raw,
    );
    let mut input = input(Sourced::ok(SourceId::EventLogSystem, vec![]));
    input.kernel_power = kernel_power;
    let answer = wake::answer(&input, &window("2026-11-04T00:00:00Z"));
    let exits = by_id(&answer.findings, "wake.modern_standby");
    assert_eq!(exits.len(), 2);
    let finding = citing(&answer.findings, "900004");
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(finding.headline(), "Left Modern Standby after 2 h");
    assert!(finding.explanation().contains("deepest low-power state"));
    assert!(finding.explanation().contains("type 4"));
    assert!(finding.gap().is_some());
}

#[test]
fn live_wake_timers_name_their_owner() {
    let mut input = input(Sourced::ok(SourceId::EventLogSystem, vec![]));
    input.timers = Sourced::ok(
        SourceId::WakeTimers,
        vec![WakeTimer {
            due: Some(ts("2026-11-11T09:00:00Z")),
            due_raw: 0,
            period_ms: 0,
            owner: Requester::Process {
                pid: 10,
                image: Some(r"\Device\HarddiskVolume3\Tools\pcsleuth-fault-wake-timer.exe".into()),
            },
            reason: None,
        }],
    );
    let answer = wake::answer(&input, &window("2026-11-01T00:00:00Z"));
    let finding = by_id(&answer.findings, "wake.timer_armed")[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.evidence()[0].fields["process"],
        "pcsleuth-fault-wake-timer.exe"
    );
    assert!(finding.evidence()[0].timestamp.is_some());
    // The timers source was readable, so there is no limit for it.
    assert!(
        answer
            .limits
            .iter()
            .all(|l| l.source != SourceId::WakeTimers)
    );
}

#[test]
fn an_empty_timer_list_says_so() {
    let mut input = input(Sourced::ok(SourceId::EventLogSystem, vec![]));
    input.timers = Sourced::ok(SourceId::WakeTimers, vec![]);
    let answer = wake::answer(&input, &window("2026-11-01T00:00:00Z"));
    assert_eq!(by_id(&answer.findings, "wake.no_timers").len(), 1);
}

#[test]
fn armed_devices_are_listed_without_blaming_any_of_them() {
    let mut input = input(Sourced::ok(SourceId::EventLogSystem, vec![]));
    input.armed = Sourced::ok(
        SourceId::ArmedDevices,
        vec![
            ArmedDevice {
                name: "USB Input Device".into(),
            },
            ArmedDevice {
                name: "Intel(R) Ethernet".into(),
            },
        ],
    );
    let answer = wake::answer(&input, &window("2026-11-01T00:00:00Z"));
    let finding = by_id(&answer.findings, "wake.armed_devices")[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert!(finding.explanation().contains("USB Input Device"));
    assert!(finding.explanation().contains("Intel(R) Ethernet"));
    for evidence in finding.evidence() {
        // Allowed to wake is not the same as woke it, so never the attribution field.
        assert!(!evidence.fields.contains_key("device"));
        assert!(evidence.fields.contains_key("armed_device"));
    }
}

#[test]
fn unreadable_sources_become_limits_and_the_rest_still_answers() {
    let mut partial = real_wakes();
    partial.access = Access::Partial {
        message: "3 records could not be read".into(),
    };
    let answer = wake::answer(&input(partial), &window("2026-09-01T00:00:00Z"));
    assert_eq!(answer.findings.len(), 11);
    let sources: Vec<_> = answer.limits.iter().map(|l| l.source).collect();
    assert!(sources.contains(&SourceId::EventLogSystem));
    assert!(sources.contains(&SourceId::WakeTimers));
    assert!(sources.contains(&SourceId::ScheduledTasks));
    let partial = answer
        .limits
        .iter()
        .find(|l| matches!(l.access, Access::Partial { .. }))
        .unwrap();
    assert_eq!(partial.source, SourceId::EventLogSystem);
    let timers = answer
        .limits
        .iter()
        .find(|l| l.source == SourceId::WakeTimers)
        .unwrap();
    assert_eq!(timers.adds.as_deref(), Some("live wake timers"));
}

#[test]
fn the_limit_keeps_the_most_recent_dated_findings() {
    let mut window = window("2026-09-01T00:00:00Z");
    window.limit = 2;
    let answer = wake::answer(&input(real_wakes()), &window);
    let dated: Vec<_> = answer
        .findings
        .iter()
        .filter(|f| f.time().is_some())
        .collect();
    // Wakes outrank the doze records, so the two newest real wakes stay and the doze records go.
    assert_eq!(dated.len(), 2);
    assert!(ids(&answer.findings).contains(&"wake.unknown_source"));
    assert_eq!(dated[1].evidence()[0].record_id.as_deref(), Some("364927"));
    assert_eq!(dated[0].evidence()[0].record_id.as_deref(), Some("360285"));
    assert!(by_id(&answer.findings, "wake.sleep_to_hibernate").is_empty());
    // And the answer says what it left out and how to see it.
    let note = by_id(&answer.findings, "wake.left_out")[0];
    assert!(note.explanation().contains("--limit 11"));
}
