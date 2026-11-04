//! The words a reader judges the product by. A handful of findings are pinned exactly, and every
//! finding built from the fixtures is checked for plain English: no bare "Unknown", no jargon
//! without its gloss.

mod support;

use std::time::Duration;

use pcsleuth_core::{Access, Answer, Finding, SourceId, Sourced};
use pcsleuth_engine::{crash, nosleep, slow, wake};
use pcsleuth_sources::eventlog::{
    ApplicationEvent, KernelPowerEvent, LifecycleEvent, PerfEvent, PowerTroubleshooterWake,
    ProcessorCapped, ResourceExhaustion,
};
use pcsleuth_sources::power::{AcDc, SleepSettings, Timeout, WakeTimerPolicy};
use support::{citing, events, window};

fn wake_answer() -> Answer {
    wake::answer(
        &wake::Input {
            wakes: events(
                "power-troubleshooter-1.xml",
                SourceId::EventLogSystem,
                PowerTroubleshooterWake::from_raw,
            ),
            kernel_power: events(
                "synthetic-kernel-power-modern-standby.xml",
                SourceId::EventLogSystem,
                KernelPowerEvent::from_raw,
            ),
            timers: Sourced::unreadable(SourceId::WakeTimers, Access::NeedsAdmin),
            armed: Sourced::unreadable(SourceId::ArmedDevices, Access::Missing),
            tasks: Sourced::unreadable(SourceId::ScheduledTasks, Access::NeedsAdmin),
        },
        &window("2026-09-01T00:00:00Z"),
    )
}

fn crash_answer() -> Answer {
    let mut lifecycle: Sourced<LifecycleEvent> = events(
        "synthetic-eventlog-6008.xml",
        SourceId::EventLogSystem,
        LifecycleEvent::from_raw,
    );
    for name in [
        "user32-1074.xml",
        "synthetic-wer-systemerrorreporting-1001.xml",
    ] {
        lifecycle
            .data
            .extend(events(name, SourceId::EventLogSystem, LifecycleEvent::from_raw).data);
    }
    crash::answer(
        &crash::Input {
            applications: events(
                "application-error-1000.xml",
                SourceId::EventLogApplication,
                ApplicationEvent::from_raw,
            ),
            lifecycle,
            kernel_power: events(
                "kernel-power-41.xml",
                SourceId::EventLogSystem,
                KernelPowerEvent::from_raw,
            ),
        },
        &window("2026-10-01T00:00:00Z"),
    )
}

fn slow_answer() -> Answer {
    slow::answer(
        &slow::Input {
            perf: events(
                "diagnostics-performance-boot.xml",
                SourceId::EventLogDiagnosticsPerformance,
                PerfEvent::from_raw,
            ),
            applications: events(
                "application-hang-1002.xml",
                SourceId::EventLogApplication,
                ApplicationEvent::from_raw,
            ),
            processor_caps: events(
                "kernel-processor-power-37.xml",
                SourceId::EventLogSystem,
                ProcessorCapped::from_raw,
            ),
            resource: events(
                "synthetic-resource-exhaustion-2004.xml",
                SourceId::EventLogResourceExhaustion,
                ResourceExhaustion::from_raw,
            ),
            srum: Sourced::unreadable(SourceId::Srum, Access::NeedsAdmin),
            recorder: Sourced::unreadable(SourceId::Recorder, Access::Missing),
        },
        &window("2026-10-01T00:00:00Z"),
    )
}

fn nosleep_answer() -> Answer {
    nosleep::answer(
        &nosleep::Input {
            settings: Sourced::ok(
                SourceId::PowerSettings,
                vec![SleepSettings {
                    scheme: "scheme".into(),
                    standby_timeout: AcDc {
                        ac: Some(Timeout::Never),
                        dc: Some(Timeout::After(Duration::from_secs(900))),
                    },
                    hibernate_timeout: AcDc { ac: None, dc: None },
                    allow_wake_timers: AcDc {
                        ac: Some(WakeTimerPolicy::Enable),
                        dc: Some(WakeTimerPolicy::Enable),
                    },
                }],
            ),
            requests: Sourced::unreadable(SourceId::PowerRequests, Access::NeedsAdmin),
            execution_state: Sourced::unreadable(SourceId::PowerState, Access::Missing),
            last_input: Sourced::unreadable(SourceId::PowerState, Access::Missing),
            wakes: Sourced::unreadable(SourceId::EventLogSystem, Access::Missing),
            recorder: Sourced::unreadable(SourceId::Recorder, Access::Missing),
        },
        &window("2026-10-01T00:00:00Z"),
    )
}

#[test]
fn power_button_wake_reads_plainly() {
    let answer = wake_answer();
    let finding = citing(&answer.findings, "360285");
    assert_eq!(
        finding.headline(),
        "Woke from sleep: the power button was pressed"
    );
    assert_eq!(
        finding.explanation(),
        "Windows' wake log (Power-Troubleshooter, event 1) lists the power button as the wake \
         source. The PC had been asleep for 1 h 27 min."
    );
}

#[test]
fn hibernate_wake_with_no_source_says_what_it_does_not_know_and_why() {
    let answer = wake_answer();
    let finding = citing(&answer.findings, "364927");
    assert_eq!(
        finding.headline(),
        "Woke from hibernate: Windows did not record what woke it"
    );
    assert_eq!(
        finding.explanation(),
        "Windows' wake log (Power-Troubleshooter, event 1) lists the wake source as \"unknown\": \
         Windows received no wake source for this wake. Hibernate saves the PC's memory to disk \
         and turns it off. A missing source is often seen after hibernate because the PC was \
         fully off, but it can also have other causes. The PC had been hibernating for 21 min."
    );
    let gap = finding.gap().unwrap();
    assert_eq!(gap.what, "what woke the PC from hibernate");
    assert_eq!(
        gap.would_capture,
        "no software runs while the PC is off, so pcsleuth cannot capture it; waking from sleep \
         instead of hibernate usually gives a named source."
    );
}

#[test]
fn a_lost_power_restart_reads_plainly() {
    let answer = crash_answer();
    let finding = citing(&answer.findings, "362297");
    assert_eq!(
        finding.headline(),
        "The PC lost power or stopped completely, and Windows does not know why"
    );
    assert_eq!(
        finding.explanation(),
        "Windows found that the PC had not shut down cleanly (Kernel-Power event 41, EventLog \
         event 6008) and recorded no blue screen code and no power button hold. Possible reasons \
         include a power cut, a flat battery, a hard reset or a hardware fault; Windows did not \
         record which."
    );
}

#[test]
fn an_application_crash_reads_plainly() {
    let answer = crash_answer();
    let finding = citing(&answer.findings, "170177");
    assert_eq!(finding.headline(), "RedactedApp.exe crashed");
    assert_eq!(
        finding.explanation(),
        "Windows logged an Application Error (event 1000), which is a program crash. The failure \
         was seen in KERNELBASE.dll, which is where Windows saw it, not always where the bug is. \
         Exception code 0xc000041d."
    );
}

#[test]
fn a_sleep_timeout_of_never_reads_plainly() {
    let answer = nosleep_answer();
    let finding = answer
        .findings
        .iter()
        .find(|f| f.id() == "nosleep.timeout_never")
        .unwrap();
    assert_eq!(
        finding.headline(),
        "The sleep timeout is set to Never while plugged in, so Windows will not sleep on its own"
    );
    assert_eq!(
        finding.explanation(),
        "The active power plan says never to put the PC to sleep after it has been idle. The PC \
         can still be put to sleep by hand, and the lid and power button have their own settings."
    );
}

fn all_text(finding: &Finding) -> String {
    let mut text = format!("{} {}", finding.headline(), finding.explanation());
    if let Some(gap) = finding.gap() {
        text.push_str(&format!(" {} {}", gap.what, gap.would_capture));
    }
    if let Some(fix) = finding.fix() {
        text.push_str(&format!(" {}", fix.explanation));
    }
    text
}

/// Terms a reader may not know, and a phrase that explains each, which must be in the same finding.
const JARGON: [(&str, &str); 6] = [
    ("firmware", "built-in software"),
    ("wake timer", "alarm"),
    ("Modern Standby", "low-power idle state"),
    ("SRUM", "usage records"),
    ("bugcheck", "blue screen"),
    ("power request", "asks Windows"),
];

#[test]
fn no_finding_says_unknown_alone_or_uses_jargon_without_its_gloss() {
    let answers = [
        wake_answer(),
        crash_answer(),
        slow_answer(),
        nosleep_answer(),
    ];
    let mut checked = 0;
    for answer in &answers {
        for finding in &answer.findings {
            checked += 1;
            let headline = finding.headline();
            assert!(
                !headline.to_lowercase().contains("unknown"),
                "{}: {headline}",
                finding.id()
            );
            // "unknown" appears only quoted, as the word Windows itself wrote.
            let text = all_text(finding);
            for (at, _) in text.to_lowercase().match_indices("unknown") {
                assert_eq!(
                    text[..at].chars().last(),
                    Some('"'),
                    "{}: bare unknown in {text}",
                    finding.id()
                );
            }
            for (term, gloss) in JARGON {
                if text.contains(term) {
                    assert!(
                        text.contains(gloss),
                        "{}: {term:?} without {gloss:?} in {text}",
                        finding.id()
                    );
                }
            }
            assert!(finding.headline().len() >= 20, "{}", finding.id());
        }
    }
    assert!(checked > 40, "only {checked} findings were checked");
}
