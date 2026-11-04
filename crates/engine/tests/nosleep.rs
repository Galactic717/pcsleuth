//! `nosleep`: sleep timeouts, live power requests, flags, recorder rows and the honest gap.

mod support;

use std::time::Duration;

use pcsleuth_core::{Access, Confidence, RecordedRequest, RecorderRow, SourceId, Sourced};
use pcsleuth_engine::nosleep;
use pcsleuth_sources::eventlog::PowerTroubleshooterWake;
use pcsleuth_sources::power::{
    AcDc, ExecutionState, LastInput, PowerRequest, Reason, RequestType, Requester, SleepSettings,
    Timeout, WakeTimerPolicy,
};
use support::{by_id, citing, events, ts, window};

fn nothing<T>(source: SourceId) -> Sourced<T> {
    Sourced::ok(source, vec![])
}

fn input() -> nosleep::Input {
    nosleep::Input {
        settings: Sourced::unreadable(SourceId::PowerSettings, Access::Missing),
        requests: Sourced::unreadable(SourceId::PowerRequests, Access::NeedsAdmin),
        execution_state: Sourced::unreadable(SourceId::PowerState, Access::Missing),
        last_input: Sourced::unreadable(SourceId::PowerState, Access::Missing),
        wakes: nothing(SourceId::EventLogSystem),
        recorder: Sourced::unreadable(SourceId::Recorder, Access::Missing),
    }
}

fn settings(ac: Timeout, dc: Timeout) -> Sourced<SleepSettings> {
    Sourced::ok(
        SourceId::PowerSettings,
        vec![SleepSettings {
            scheme: "381b4222-f694-41f0-9685-ff5bb260df2e".into(),
            standby_timeout: AcDc {
                ac: Some(ac),
                dc: Some(dc),
            },
            hibernate_timeout: AcDc { ac: None, dc: None },
            allow_wake_timers: AcDc {
                ac: Some(WakeTimerPolicy::Enable),
                dc: Some(WakeTimerPolicy::Enable),
            },
        }],
    )
}

fn minutes(n: u64) -> Timeout {
    Timeout::After(Duration::from_secs(n * 60))
}

#[test]
fn a_sleep_timeout_of_never_is_a_recorded_answer_with_the_command_printed() {
    let mut input = input();
    input.settings = settings(Timeout::Never, minutes(15));
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let finding = by_id(&answer.findings, "nosleep.timeout_never")[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "The sleep timeout is set to Never while plugged in, so Windows will not sleep on its own"
    );
    let fix = finding.fix().unwrap();
    assert_eq!(fix.command, "powercfg /change standby-timeout-ac 30");
    assert!(!fix.needs_admin);
    assert!(fix.explanation.contains("pcsleuth does not run this"));
    let evidence = &finding.evidence()[0];
    assert_eq!(evidence.source, SourceId::PowerSettings);
    assert_eq!(evidence.fields["standby_timeout_ac"], "never");
    // On battery it is 15 minutes, so no second never finding.
    assert_eq!(by_id(&answer.findings, "nosleep.timeout_never").len(), 1);
    assert!(by_id(&answer.findings, "nosleep.timeouts").is_empty());
}

#[test]
fn never_on_battery_gets_the_battery_command() {
    let mut input = input();
    input.settings = settings(minutes(30), Timeout::Never);
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let finding = by_id(&answer.findings, "nosleep.timeout_never")[0];
    assert!(finding.headline().contains("on battery"));
    assert_eq!(
        finding.fix().unwrap().command,
        "powercfg /change standby-timeout-dc 15"
    );
}

#[test]
fn ordinary_timeouts_are_shown_as_context() {
    let mut input = input();
    input.settings = settings(minutes(30), minutes(15));
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let finding = by_id(&answer.findings, "nosleep.timeouts")[0];
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert!(finding.explanation().contains("30 min while plugged in"));
    assert!(finding.explanation().contains("15 min on battery"));
    assert!(finding.fix().is_none());
}

#[test]
fn a_live_request_names_its_owner_and_says_what_it_holds() {
    let mut input = input();
    input.requests = Sourced::ok(
        SourceId::PowerRequests,
        vec![
            PowerRequest {
                requester: Requester::Process {
                    pid: 7,
                    image: Some(
                        r"\Device\HarddiskVolume3\Tools\pcsleuth-fault-power-request.exe".into(),
                    ),
                },
                active: vec![(RequestType::System, 1)],
                reason: Some(Reason::Text("rendering".into())),
            },
            PowerRequest {
                requester: Requester::Driver {
                    description: Some("Realtek Audio".into()),
                    device_path: None,
                },
                active: vec![(RequestType::Display, 1)],
                reason: None,
            },
        ],
    );
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let requests = by_id(&answer.findings, "nosleep.power_request");
    assert_eq!(requests.len(), 2);
    let process = requests[0];
    assert_eq!(process.confidence(), Confidence::Recorded);
    assert_eq!(
        process.headline(),
        "pcsleuth-fault-power-request.exe is keeping the PC from sleeping"
    );
    assert_eq!(
        process.evidence()[0].fields["process"],
        "pcsleuth-fault-power-request.exe"
    );
    assert!(process.explanation().contains("rendering"));
    let driver = requests[1];
    assert!(!driver.evidence()[0].fields.contains_key("process"));
    assert_eq!(driver.evidence()[0].fields["driver"], "Realtek Audio");
    assert_eq!(
        driver.headline(),
        "The driver Realtek Audio is keeping the screen on"
    );
    // Readable, so no power_requests limit.
    assert!(
        answer
            .limits
            .iter()
            .all(|l| l.source != SourceId::PowerRequests)
    );
}

#[test]
fn no_requests_is_said_plainly() {
    let mut input = input();
    input.requests = nothing(SourceId::PowerRequests);
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    assert_eq!(by_id(&answer.findings, "nosleep.no_requests").len(), 1);
}

#[test]
fn without_admin_the_live_requests_are_a_limit_and_the_past_is_not_recorded() {
    let answer = nosleep::answer(&input(), &window("2026-10-28T00:00:00Z"));
    let limit = answer
        .limits
        .iter()
        .find(|l| l.source == SourceId::PowerRequests)
        .unwrap();
    assert_eq!(
        limit.adds.as_deref(),
        Some("live power requests with their owners")
    );
    let past = by_id(&answer.findings, "nosleep.past_blockers")[0];
    assert_eq!(past.confidence(), Confidence::NotRecorded);
    let gap = past.gap().unwrap();
    assert!(gap.what.contains("held the PC awake"));
    assert!(gap.would_capture.contains("recorder"));
    assert!(gap.would_capture.contains("--elevate"));
    // Nothing here names a cause.
    for finding in &answer.findings {
        for evidence in finding.evidence() {
            assert!(!evidence.fields.contains_key("process"));
            assert!(!evidence.fields.contains_key("device"));
        }
    }
}

#[test]
fn the_awake_flags_are_reported_as_flags_and_not_as_who() {
    let mut input = input();
    input.execution_state = Sourced::ok(
        SourceId::PowerState,
        vec![ExecutionState::from_bits(0x8000_0003)],
    );
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let set = by_id(&answer.findings, "nosleep.execution_state")[0];
    assert_eq!(set.confidence(), Confidence::Recorded);
    assert_eq!(
        set.headline(),
        "Windows has a keep-awake flag set right now"
    );
    assert!(set.explanation().contains("system required"));
    assert!(set.explanation().contains("display required"));
    assert!(set.explanation().contains("does not say who"));

    input.execution_state = Sourced::ok(SourceId::PowerState, vec![ExecutionState::from_bits(0)]);
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let clear = by_id(&answer.findings, "nosleep.execution_state")[0];
    assert_eq!(
        clear.headline(),
        "Windows' keep-awake flags are all clear right now"
    );
    // A clear flag is not proof that nothing holds a request.
    assert!(clear.explanation().contains("does not rule out"));
}

#[test]
fn the_last_input_is_context() {
    let mut input = input();
    input.last_input = Sourced::ok(
        SourceId::PowerState,
        vec![LastInput {
            idle: Duration::from_secs(5 * 60 + 3),
            at: ts("2026-11-04T08:54:57Z"),
        }],
    );
    let answer = nosleep::answer(&input, &window("2026-10-28T00:00:00Z"));
    let finding = by_id(&answer.findings, "nosleep.last_input")[0];
    assert_eq!(
        finding.headline(),
        "The last keyboard or mouse input was 5 min ago"
    );
    assert_eq!(finding.confidence(), Confidence::Recorded);
}

#[test]
fn the_last_wake_in_the_log_says_when_the_pc_last_slept() {
    let mut input = input();
    input.wakes = events(
        "power-troubleshooter-1.xml",
        SourceId::EventLogSystem,
        PowerTroubleshooterWake::from_raw,
    );
    let answer = nosleep::answer(&input, &window("2026-10-01T00:00:00Z"));
    let finding = by_id(&answer.findings, "nosleep.last_sleep")[0];
    assert_eq!(
        finding.headline(),
        "The PC last woke from hibernate 20 h 26 min ago"
    );
    assert!(finding.explanation().contains("hibernating for 21 min"));
    assert!(finding.explanation().contains("no later wake"));
    assert_eq!(finding.evidence()[0].record_id.as_deref(), Some("364927"));
    // The doze record is not a wake, even though it is later than the one before it.
    citing(&answer.findings, "364927");
}

#[test]
fn recorder_rows_give_sampled_findings_that_state_the_interval() {
    let row = |at: &str, requests: Vec<RecordedRequest>| RecorderRow {
        at: ts(at),
        interval_secs: 30,
        top_cpu: vec![],
        top_io: vec![],
        power_requests: requests,
    };
    let held = || RecordedRequest {
        owner: "player.exe".into(),
        kind: "system".into(),
        reason: Some("playing".into()),
    };
    let mut input = input();
    input.recorder = Sourced::ok(
        SourceId::Recorder,
        vec![
            row("2026-11-03T20:00:00Z", vec![held()]),
            row("2026-11-03T20:00:30Z", vec![held()]),
            row("2026-11-03T20:01:00Z", vec![]),
            row("2026-11-03T20:01:30Z", vec![held()]),
        ],
    );
    let answer = nosleep::answer(&input, &window("2026-11-03T00:00:00Z"));
    let finding = by_id(&answer.findings, "nosleep.recorder_request")[0];
    assert_eq!(finding.confidence(), Confidence::Sampled);
    assert_eq!(
        finding.headline(),
        "player.exe held a system power request in 3 of 4 recorder samples"
    );
    assert!(finding.explanation().contains("every 30 s"));
    assert!(finding.explanation().contains("can be missed"));
    let evidence = &finding.evidence()[0];
    assert_eq!(evidence.source, SourceId::Recorder);
    assert_eq!(evidence.fields["process"], "player.exe");
    assert_eq!(evidence.fields["interval_secs"], "30");
    assert_eq!(evidence.fields["samples"], "3/4");
    assert_eq!(evidence.timestamp, Some(ts("2026-11-03T20:01:30Z")));
    // The recorder answered, so the past is no longer unrecorded.
    assert!(by_id(&answer.findings, "nosleep.past_blockers").is_empty());
}

#[test]
fn recorder_rows_before_the_window_are_ignored() {
    let mut input = input();
    input.recorder = Sourced::ok(
        SourceId::Recorder,
        vec![RecorderRow {
            at: ts("2026-10-01T20:00:00Z"),
            interval_secs: 30,
            top_cpu: vec![],
            top_io: vec![],
            power_requests: vec![RecordedRequest {
                owner: "old.exe".into(),
                kind: "system".into(),
                reason: None,
            }],
        }],
    );
    let answer = nosleep::answer(&input, &window("2026-11-03T00:00:00Z"));
    assert!(by_id(&answer.findings, "nosleep.recorder_request").is_empty());
    assert_eq!(by_id(&answer.findings, "nosleep.past_blockers").len(), 1);
}

#[test]
fn recorder_samples_that_saw_no_request_do_not_prove_there_was_none() {
    let mut input = input();
    input.recorder = Sourced::ok(
        SourceId::Recorder,
        vec![RecorderRow {
            at: ts("2026-11-03T20:00:00Z"),
            interval_secs: 30,
            top_cpu: vec![],
            top_io: vec![],
            power_requests: vec![],
        }],
    );
    let answer = nosleep::answer(&input, &window("2026-11-03T00:00:00Z"));
    let past = by_id(&answer.findings, "nosleep.past_blockers")[0];
    assert_eq!(past.confidence(), Confidence::NotRecorded);
    assert!(past.explanation().contains("1 recorder sample"));
    assert!(past.explanation().contains("owners"));
}
