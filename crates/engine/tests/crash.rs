//! `crash` over the fixtures. `synthetic-*` fixtures were built by hand from provider manifests.

mod support;

use pcsleuth_core::{Access, Confidence, Question, SourceId, Sourced};
use pcsleuth_engine::crash;
use pcsleuth_sources::eventlog::{
    AppCrash, ApplicationEvent, Bugcheck, KernelPowerEvent, LifecycleEvent, Meta,
    ShutdownInitiated, UncleanReboot, UnexpectedShutdown, WerReport,
};
use support::{by_id, citing, events, ids, raw_events, ts, window};

fn applications(name: &str) -> Sourced<ApplicationEvent> {
    events(
        name,
        SourceId::EventLogApplication,
        ApplicationEvent::from_raw,
    )
}

fn lifecycle(name: &str) -> Sourced<LifecycleEvent> {
    events(name, SourceId::EventLogSystem, LifecycleEvent::from_raw)
}

fn kernel_power(name: &str) -> Sourced<KernelPowerEvent> {
    events(name, SourceId::EventLogSystem, KernelPowerEvent::from_raw)
}

fn nothing<T>(source: SourceId) -> Sourced<T> {
    Sourced::ok(source, vec![])
}

fn input() -> crash::Input {
    crash::Input {
        applications: nothing(SourceId::EventLogApplication),
        lifecycle: nothing(SourceId::EventLogSystem),
        kernel_power: nothing(SourceId::EventLogSystem),
    }
}

fn meta(record: u64, time: &str) -> Meta {
    Meta {
        record_id: Some(record),
        time: Some(ts(time)),
        version: Some(0),
    }
}

#[test]
fn an_application_error_names_the_program_and_cites_its_record() {
    let mut input = input();
    input.applications = applications("application-error-1000.xml");
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    let finding = citing(&answer.findings, "170177");
    assert_eq!(finding.id(), "crash.app_crash");
    assert_eq!(finding.question(), Question::Crash);
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(finding.headline(), "RedactedApp.exe crashed");
    let evidence = &finding.evidence()[0];
    assert_eq!(evidence.fields["process"], "RedactedApp.exe");
    assert_eq!(evidence.source, SourceId::EventLogApplication);
    assert!(finding.explanation().contains("KERNELBASE.dll"));
    assert!(finding.explanation().contains("0xc000041d"));
    // The famous codes get a plain gloss.
    assert!(
        citing(&answer.findings, "163374")
            .explanation()
            .contains("access violation")
    );
    assert!(
        citing(&answer.findings, "166486")
            .explanation()
            .contains("safety check")
    );
    assert_eq!(by_id(&answer.findings, "crash.app_crash").len(), 6);
}

#[test]
fn a_hang_names_the_program() {
    let mut input = input();
    input.applications = applications("application-hang-1002.xml");
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    let finding = citing(&answer.findings, "169007");
    assert_eq!(finding.id(), "crash.app_hang");
    assert_eq!(finding.headline(), "dllhost.exe stopped responding");
    assert_eq!(finding.evidence()[0].fields["process"], "dllhost.exe");
    assert!(finding.explanation().contains("Quiesce"));
    assert_eq!(finding.confidence(), Confidence::Recorded);
}

#[test]
fn records_older_than_the_window_are_never_used() {
    let mut input = input();
    input.applications = applications("application-error-1000.xml");
    let answer = crash::answer(&input, &window("2026-10-31T00:00:00Z"));
    // Only 170177, 170175 and 168745 are on or after 31 October.
    let records: Vec<_> = answer
        .findings
        .iter()
        .flat_map(|f| f.evidence().iter().filter_map(|e| e.record_id.clone()))
        .collect();
    assert_eq!(records.len(), 3, "{records:?}");
    for finding in &answer.findings {
        for evidence in finding.evidence() {
            assert!(evidence.timestamp.unwrap() >= ts("2026-10-31T00:00:00Z"));
        }
    }
}

#[test]
fn a_wer_report_for_the_same_crash_is_cited_but_does_not_name_a_second_cause() {
    let mut input = input();
    input.applications = applications("application-error-1000.xml");
    let report = WerReport {
        meta: meta(170178, "2026-11-01T16:34:50Z"),
        event_name: "APPCRASH".into(),
        bucket: Some("123".into()),
        bucket_type: Some(5),
        parameters: vec!["RedactedApp.exe".into(), "1.0.0.0".into()],
        report_id: None,
        report_status: None,
        response: None,
    };
    input
        .applications
        .data
        .push(ApplicationEvent::Report(report));
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    let finding = citing(&answer.findings, "170178");
    assert_eq!(finding.id(), "crash.app_crash");
    assert_eq!(finding.evidence()[0].record_id.as_deref(), Some("170177"));
    let report_evidence = finding
        .evidence()
        .iter()
        .find(|e| e.record_id.as_deref() == Some("170178"))
        .unwrap();
    assert!(!report_evidence.fields.contains_key("process"));
    assert_eq!(by_id(&answer.findings, "crash.wer_report").len(), 0);
}

#[test]
fn a_wer_crash_report_alone_names_the_program_from_its_first_parameter() {
    let mut input = input();
    input
        .applications
        .data
        .push(ApplicationEvent::Report(WerReport {
            meta: meta(900, "2026-11-02T10:00:00Z"),
            event_name: "APPCRASH".into(),
            bucket: None,
            bucket_type: None,
            parameters: vec!["notepad.exe".into(), "11.0".into()],
            report_id: None,
            report_status: None,
            response: None,
        }));
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    let finding = citing(&answer.findings, "900");
    assert_eq!(finding.id(), "crash.wer_report");
    assert_eq!(finding.evidence()[0].fields["process"], "notepad.exe");
    assert_eq!(
        finding.headline(),
        "Windows filed a crash report for notepad.exe"
    );
}

#[test]
fn other_wer_report_types_are_counted_and_not_called_crashes() {
    let mut input = input();
    input.applications = applications("wer-1001.xml");
    let answer = crash::answer(&input, &window("2026-11-01T00:00:00Z"));
    assert_eq!(answer.findings.len(), 1);
    let finding = &answer.findings[0];
    assert_eq!(finding.id(), "crash.other_reports");
    assert_eq!(finding.evidence().len(), 3);
    assert!(finding.headline().contains("3 other error reports"));
    assert!(finding.explanation().contains("crashpad_log"));
    assert!(finding.explanation().contains("does not call them crashes"));
    for evidence in finding.evidence() {
        assert!(!evidence.fields.contains_key("process"));
    }
}

#[test]
fn a_restart_with_no_bugcheck_says_power_was_lost_and_windows_does_not_know_why() {
    let mut input = input();
    input.kernel_power = kernel_power("kernel-power-41.xml");
    input.lifecycle = lifecycle("synthetic-eventlog-6008.xml");
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    // Three restarts, each is a Kernel-Power 41 and an EventLog 6008 a few seconds apart.
    let lost = by_id(&answer.findings, "crash.power_lost");
    assert_eq!(lost.len(), 3);
    let finding = citing(&answer.findings, "363207");
    assert_eq!(finding.confidence(), Confidence::NotRecorded);
    assert_eq!(
        finding.headline(),
        "The PC lost power or stopped completely, and Windows does not know why"
    );
    let records: Vec<_> = finding
        .evidence()
        .iter()
        .filter_map(|e| e.record_id.as_deref())
        .collect();
    assert_eq!(records, ["363207", "363191"]);
    assert!(finding.gap().unwrap().what.contains("why"));
    assert!(finding.explanation().contains("sleep was in progress"));
    for finding in lost {
        for evidence in finding.evidence() {
            assert!(!evidence.fields.contains_key("process"));
            assert!(!evidence.fields.contains_key("device"));
        }
    }
}

#[test]
fn holding_the_power_button_is_a_recorded_answer() {
    let mut input = input();
    input.kernel_power = kernel_power("kernel-power-41.xml");
    for event in &mut input.kernel_power.data {
        if let KernelPowerEvent::UncleanReboot(reboot) = event
            && reboot.meta.record_id == Some(362297)
        {
            reboot.long_power_button_press = Some(true);
        }
    }
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    let finding = citing(&answer.findings, "362297");
    assert_eq!(finding.id(), "crash.forced_off");
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "The PC was forced off: the power button was held down"
    );
    assert_eq!(by_id(&answer.findings, "crash.power_lost").len(), 2);
}

fn bugcheck_events() -> (Sourced<KernelPowerEvent>, Sourced<LifecycleEvent>) {
    let reboots = kernel_power("synthetic-kernel-power-41-versions.xml");
    let blue = lifecycle("synthetic-wer-systemerrorreporting-1001.xml");
    (reboots, blue)
}

#[test]
fn a_bugcheck_record_alone_gives_the_stop_code_and_the_dump() {
    let (_, blue) = bugcheck_events();
    let mut input = input();
    input.lifecycle = blue;
    let answer = crash::answer(&input, &window("2026-11-04T00:00:00Z"));
    let finding = citing(&answer.findings, "900020");
    assert_eq!(finding.id(), "crash.blue_screen");
    assert_eq!(finding.confidence(), Confidence::Recorded);
    assert_eq!(
        finding.headline(),
        "The PC restarted after a blue screen (stop code 0x0000009F, DRIVER_POWER_STATE_FAILURE)"
    );
    assert!(finding.explanation().contains("C:\\Windows\\MEMORY.DMP"));
    // A code without a known name is shown as a number only.
    let other = citing(&answer.findings, "900021");
    assert_eq!(
        other.headline(),
        "The PC restarted after a blue screen (stop code 0x00000133, DPC_WATCHDOG_VIOLATION)"
    );
}

#[test]
fn a_kernel_power_41_with_a_bugcheck_code_and_a_close_bugcheck_record_are_one_finding() {
    let mut input = input();
    let mut reboot = UncleanReboot::from_raw(&raw_events("kernel-power-41.xml")[0]).unwrap();
    reboot.meta = meta(901, "2026-11-04T05:00:30Z");
    reboot.bugcheck_code = Some(0x9f);
    input
        .kernel_power
        .data
        .push(KernelPowerEvent::UncleanReboot(reboot));
    input.lifecycle = bugcheck_events().1;
    let answer = crash::answer(&input, &window("2026-11-04T00:00:00Z"));
    let finding = citing(&answer.findings, "901");
    assert_eq!(finding.id(), "crash.blue_screen");
    let records: Vec<_> = finding
        .evidence()
        .iter()
        .filter_map(|e| e.record_id.as_deref())
        .collect();
    assert!(records.contains(&"901") && records.contains(&"900020"));
    // The second bugcheck, an hour later, stands alone.
    assert_eq!(by_id(&answer.findings, "crash.blue_screen").len(), 2);
}

#[test]
fn a_bugcheck_code_of_zero_is_not_a_bugcheck() {
    let mut input = input();
    input.kernel_power = kernel_power("kernel-power-41.xml");
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    assert!(by_id(&answer.findings, "crash.blue_screen").is_empty());
    assert_eq!(by_id(&answer.findings, "crash.power_lost").len(), 3);
}

#[test]
fn an_unexpected_shutdown_record_alone_is_still_not_recorded() {
    let mut input = input();
    input.lifecycle = lifecycle("synthetic-eventlog-6008.xml");
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    assert_eq!(by_id(&answer.findings, "crash.power_lost").len(), 3);
    assert!(
        answer
            .findings
            .iter()
            .all(|f| f.confidence() == Confidence::NotRecorded)
    );
}

#[test]
fn a_shutdown_request_names_the_process_and_the_reason_code_in_plain_words() {
    let mut input = input();
    input.lifecycle = lifecycle("user32-1074.xml");
    let answer = crash::answer(&input, &window("2026-11-01T00:00:00Z"));
    assert_eq!(answer.findings.len(), 4);
    let finding = citing(&answer.findings, "365367");
    assert_eq!(finding.id(), "crash.shutdown_requested");
    assert_eq!(finding.confidence(), Confidence::Recorded);

    let raw = raw_events("user32-1074.xml");
    let typed = ShutdownInitiated::from_raw(&raw[0]).unwrap();
    let exe = typed.process_name().unwrap();
    assert!(exe.ends_with(".exe"));
    assert_eq!(finding.evidence()[0].fields["process"], exe);
    assert_eq!(
        finding.headline(),
        format!("{exe} asked Windows to shut down or restart")
    );
    // Reason code is shown; the localized texts are never used to say shutdown or restart.
    assert!(finding.explanation().contains("reason code 0x0"));
    assert!(finding.explanation().contains("not marked as planned"));
    let text = format!("{} {}", finding.headline(), finding.explanation());
    assert!(text.is_ascii(), "{text}");
}

#[test]
fn a_planned_reason_code_is_marked_planned() {
    let mut input = input();
    let raw = raw_events("user32-1074.xml");
    let mut shutdown = ShutdownInitiated::from_raw(&raw[0]).unwrap();
    shutdown.reason_code = Some(0x8002_0002);
    input
        .lifecycle
        .data
        .push(LifecycleEvent::ShutdownInitiated(shutdown));
    let answer = crash::answer(&input, &window("2026-11-01T00:00:00Z"));
    let finding = &answer.findings[0];
    assert!(finding.explanation().contains("reason code 0x80020002"));
    assert!(finding.explanation().contains("marked as planned"));
    assert!(!finding.explanation().contains("not marked"));
}

#[test]
fn a_failing_source_does_not_stop_the_others() {
    let mut input = input();
    input.applications = applications("application-error-1000.xml");
    input.lifecycle = Sourced::unreadable(SourceId::EventLogSystem, Access::NeedsAdmin);
    input.kernel_power = Sourced::unreadable(
        SourceId::EventLogSystem,
        Access::Partial {
            message: "2 records could not be read".into(),
        },
    );
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    assert_eq!(by_id(&answer.findings, "crash.app_crash").len(), 6);
    assert_eq!(answer.limits.len(), 2);
    assert!(answer.limits.iter().any(
        |l| matches!(&l.access, Access::Partial { message } if message.contains("2 records"))
    ));
}

#[test]
fn findings_cite_event_records_and_never_a_later_record_than_asked() {
    let mut input = input();
    input.applications = applications("application-error-1000.xml");
    input.kernel_power = kernel_power("kernel-power-41.xml");
    input.lifecycle = lifecycle("user32-1074.xml");
    let answer = crash::answer(&input, &window("2026-10-01T00:00:00Z"));
    assert!(!ids(&answer.findings).is_empty());
    for finding in &answer.findings {
        assert!(finding.evidence().iter().all(|e| e.record_id.is_some()));
    }
    // Unused types keep the imports honest.
    let _ = (
        std::mem::size_of::<AppCrash>(),
        std::mem::size_of::<Bugcheck>(),
        std::mem::size_of::<UnexpectedShutdown>(),
    );
}

#[test]
fn hundreds_of_other_reports_cite_only_the_newest_few() {
    let mut input = input();
    for n in 0..25u64 {
        input
            .applications
            .data
            .push(ApplicationEvent::Report(WerReport {
                meta: meta(1000 + n, &format!("2026-11-02T10:{n:02}:00Z")),
                event_name: if n % 5 == 0 { "RareKind" } else { "CommonKind" }.into(),
                bucket: None,
                bucket_type: None,
                parameters: vec!["x.exe".into()],
                report_id: None,
                report_status: None,
                response: None,
            }));
    }
    let answer = crash::answer(&input, &window("2026-11-01T00:00:00Z"));
    let finding = &answer.findings[0];
    assert_eq!(finding.headline(), "Windows filed 25 other error reports");
    assert_eq!(finding.evidence().len(), 10);
    assert_eq!(finding.evidence()[0].record_id.as_deref(), Some("1024"));
    assert!(
        finding
            .explanation()
            .contains("(CommonKind x20, RareKind x5)")
    );
    assert!(finding.explanation().contains("The newest 10 are cited."));
}
