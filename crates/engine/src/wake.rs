//! `wake`: why did the PC wake up?
//!
//! Each wake comes from Power-Troubleshooter event 1, which states the wake source. Windows
//! names the source for a power button, a device and a timer. It does not for a hibernate resume,
//! and then the answer says "not recorded" and keeps the record as its evidence.

use std::time::Duration;

use pcsleuth_core::{
    Answer, Evidence, Finding, FindingError, NotRecorded, Question, SourceId, Sourced,
};
use pcsleuth_sources::eventlog::{
    KernelPowerEvent, ModernStandbyEntered, ModernStandbyExited, PowerState,
    PowerTroubleshooterWake, WakeSourceType,
};
use pcsleuth_sources::power::{ArmedDevice, Reason, Requester, WakeTimer};
use pcsleuth_sources::tasks::{TaskScan, TaskState};

use crate::common::{
    Findings, Limits, Window, between, collapse_sids, duration, exe_name, file_name, finish, fix,
    live, not_recorded_citing, quote_for_shell, stamped,
};

/// What the question reads. Every source is read on its own, so one that fails costs only itself.
pub struct Input {
    pub wakes: Sourced<PowerTroubleshooterWake>,
    pub kernel_power: Sourced<KernelPowerEvent>,
    pub timers: Sourced<WakeTimer>,
    pub armed: Sourced<ArmedDevice>,
    pub tasks: Sourced<TaskScan>,
}

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.wakes);
    limits.note(&input.kernel_power);
    limits.note(&input.timers);
    limits.note(&input.armed);
    limits.note(&input.tasks);

    let mut findings = event_findings(&input.wakes, &input.kernel_power, window);
    live_findings(input, window, &mut findings);
    finish(Question::Wake, window, findings.0, limits)
}

/// Every wake in the window, from the log. No live state, so the timeline can use it.
pub fn event_findings(
    wakes: &Sourced<PowerTroubleshooterWake>,
    kernel_power: &Sourced<KernelPowerEvent>,
    window: &Window,
) -> Findings {
    let exits: Vec<(&ModernStandbyExited, Option<&ModernStandbyEntered>)> = {
        let all = &kernel_power.data;
        all.iter()
            .filter_map(|event| match event {
                KernelPowerEvent::ModernStandbyExited(exit) if window.contains(exit.meta.time) => {
                    Some(exit)
                }
                _ => None,
            })
            .map(|exit| (exit, entered_before(all, exit)))
            .collect()
    };
    let mut used = vec![false; exits.len()];

    let mut out = Findings::default();
    for wake in wakes.data.iter().filter(|w| window.contains(w.meta.time)) {
        // A Modern Standby exit within seconds of a wake record is the same wake: cite both.
        let mut extra = Vec::new();
        for (i, (exit, entered)) in exits.iter().enumerate() {
            if close(wake.meta.time, exit.meta.time) {
                used[i] = true;
                extra.push(stamped(exit.to_evidence(), &exit.meta));
                extra.extend(entered.map(|e| stamped(e.to_evidence(), &e.meta)));
            }
        }
        out.push(wake_finding(wake, extra));
    }
    for (i, (exit, entered)) in exits.iter().enumerate() {
        if !used[i] {
            out.push(standby_finding(exit, *entered));
        }
    }
    out
}

fn close(a: Option<jiff::Timestamp>, b: Option<jiff::Timestamp>) -> bool {
    between(a, b)
        .or_else(|| between(b, a))
        .is_some_and(|gap| gap <= Duration::from_secs(10))
        || a == b
}

/// The Modern Standby entry just before `exit`, if the log has one.
fn entered_before<'a>(
    all: &'a [KernelPowerEvent],
    exit: &ModernStandbyExited,
) -> Option<&'a ModernStandbyEntered> {
    all.iter()
        .filter_map(|event| match event {
            KernelPowerEvent::ModernStandbyEntered(entered) => Some(entered),
            _ => None,
        })
        .filter(|entered| {
            between(entered.meta.time, exit.meta.time)
                .is_some_and(|span| span <= Duration::from_secs(24 * 3600))
        })
        .max_by_key(|entered| entered.meta.time)
}

/// "sleep", "hibernate", or neither when Windows gave a state this code has no name for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Sleep,
    Hibernate,
    Other,
}

impl Kind {
    pub(crate) fn of(wake: &PowerTroubleshooterWake) -> Kind {
        match wake.target_state.or(wake.effective_state) {
            Some(PowerState::Sleep) => Kind::Sleep,
            Some(PowerState::Hibernate) => Kind::Hibernate,
            _ => Kind::Other,
        }
    }

    pub(crate) fn noun(self) -> &'static str {
        match self {
            Kind::Sleep => "sleep",
            Kind::Hibernate => "hibernate",
            Kind::Other => "a low-power state",
        }
    }

    fn woke_from(self) -> &'static str {
        match self {
            Kind::Sleep => "Woke from sleep",
            Kind::Hibernate => "Woke from hibernate",
            Kind::Other => "Woke from a low-power state",
        }
    }
}

fn slept_sentence(wake: &PowerTroubleshooterWake, kind: Kind) -> String {
    match between(wake.sleep_time, wake.wake_time) {
        Some(span) => {
            let state = if kind == Kind::Hibernate {
                "hibernating"
            } else {
                "asleep"
            };
            format!(" The PC had been {state} for {}.", duration(span))
        }
        None => String::new(),
    }
}

fn wake_finding(
    wake: &PowerTroubleshooterWake,
    extra: Vec<Evidence>,
) -> Result<Finding, FindingError> {
    let kind = Kind::of(wake);
    let evidence = || stamped(wake.to_evidence(), &wake.meta);
    let with_extra = |first: Evidence| {
        let mut all = vec![first];
        all.extend(extra.iter().cloned());
        all
    };
    let when = wake.wake_time.or(wake.meta.time);
    let at = |finding: Finding| match when {
        Some(when) => finding.at(when),
        None => finding,
    };
    let slept = slept_sentence(wake, kind);
    let log = "Windows' wake log (Power-Troubleshooter, event 1)";

    if wake.is_doze_timer() {
        return Finding::recorded(
            "wake.sleep_to_hibernate",
            Question::Wake,
            "Windows moved the PC from sleep to hibernate by itself",
            format!(
                "After the PC had slept for a while, Windows saved its memory to disk and powered \
                 it off (hibernate) on its own timer. {log} records this as a doze timer, not as \
                 a wake."
            ),
            with_extra(evidence()),
        )
        .map(|f| match wake.sleep_time.or(when) {
            Some(time) => f.at(time),
            None => f,
        });
    }

    match wake.source {
        WakeSourceType::PowerButton => Finding::recorded(
            "wake.power_button",
            Question::Wake,
            format!("{}: the power button was pressed", kind.woke_from()),
            format!("{log} lists the power button as the wake source.{slept}"),
            with_extra(evidence()),
        )
        .map(at),
        WakeSourceType::Device => {
            device_finding(wake, kind, log, &slept, with_extra(evidence())).map(at)
        }
        _ if wake.timer_owner.is_some() => {
            let owner = wake.timer_owner.clone().unwrap_or_default();
            let mut e = evidence().with_field("timer_owner", owner.as_str());
            if let Some(context) = &wake.timer_context {
                e = e.with_field("timer_context", context.as_str());
            }
            let who = exe_name(&owner).unwrap_or_else(|| owner.clone());
            if let Some(exe) = exe_name(&owner) {
                e = e.with_field("process", exe);
            }
            let context = wake
                .timer_context
                .as_deref()
                .map(|c| format!(" and its context as \"{c}\""))
                .unwrap_or_default();
            Finding::recorded(
                "wake.timer",
                Question::Wake,
                format!("{}: a wake timer set by {who} went off", kind.woke_from()),
                format!(
                    "A wake timer is an alarm that a program sets to wake the PC. {log} gives \
                     this timer's owner as \"{owner}\"{context}.{slept}"
                ),
                with_extra(e),
            )
            .map(at)
        }
        WakeSourceType::Unknown => {
            unknown_finding(wake, kind, log, &slept, with_extra(evidence())).map(at)
        }
        other => Finding::recorded(
            "wake.other_type",
            Question::Wake,
            format!("{} (wake source {other})", kind.woke_from()),
            format!(
                "{log} gives the wake source as {other}. pcsleuth has only seen wake sources \
                 0, 1, 3 and 5 on real hardware, so it will not guess what this one means.{slept}"
            ),
            with_extra(evidence()),
        )
        .and_then(|f| {
            f.with_gap(NotRecorded::new(
                format!("what wake source {other} stands for"),
                "a report of this record from someone who can match it to a cause; Windows \
                 does not publish the list of wake source numbers",
            ))
        })
        .map(at),
    }
}

fn device_finding(
    wake: &PowerTroubleshooterWake,
    kind: Kind,
    log: &str,
    slept: &str,
    evidence: Vec<Evidence>,
) -> Result<Finding, FindingError> {
    let Some(name) = wake.device_name() else {
        return Finding::recorded(
            "wake.device",
            Question::Wake,
            format!(
                "{}: a device woke it, but Windows did not give its name",
                kind.woke_from()
            ),
            format!("{log} lists a device as the wake source without a name.{slept}"),
            evidence,
        )
        .and_then(|f| {
            f.with_gap(NotRecorded::new(
                "which device woke the PC",
                "the list of armed devices from this command shows which devices are allowed to \
                 wake it",
            ))
        });
    };
    let mut evidence = evidence;
    if let Some(first) = evidence.first_mut() {
        first.fields.insert("device".into(), name.to_owned());
    }
    let base = |explanation: String| {
        Finding::recorded(
            "wake.device",
            Question::Wake,
            format!("{}: \"{name}\" woke the PC", kind.woke_from()),
            explanation,
            evidence.clone(),
        )
    };
    match quote_for_shell(name) {
        Some(quoted) => base(format!(
            "{log} lists this device as the wake source. Keyboards, mice and network adapters \
             can wake a PC when they are allowed to.{slept}"
        ))
        .map(|f| {
            f.with_fix(fix(
                format!("powercfg /devicedisablewake {quoted}"),
                "Stops this device from waking the PC. Undo it with powercfg /deviceenablewake \
                 and the same name. pcsleuth does not run this for you.",
                true,
            ))
        }),
        None => base(format!(
            "{log} lists this device as the wake source.{slept} Its name has characters that \
             cannot be put in a command safely, so no fix command is shown. List the devices \
             that are allowed to wake the PC with powercfg /devicequery wake_armed."
        )),
    }
}

fn unknown_finding(
    wake: &PowerTroubleshooterWake,
    kind: Kind,
    log: &str,
    slept: &str,
    evidence: Vec<Evidence>,
) -> Result<Finding, FindingError> {
    let (explanation, gap) = if kind == Kind::Hibernate {
        (
            format!(
                "{log} lists the wake source as \"unknown\": Windows received no wake source for \
                 this wake. Hibernate saves the PC's memory to disk and turns it off. A missing \
                 source is often seen after hibernate because the PC was fully off, but it can \
                 also have other causes.{slept}"
            ),
            NotRecorded::new(
                "what woke the PC from hibernate",
                "no software runs while the PC is off, so pcsleuth cannot capture it; waking from \
                 sleep instead of hibernate usually gives a named source.",
            ),
        )
    } else {
        (
            format!("{log} lists the wake source as \"unknown\" for this wake.{slept}"),
            NotRecorded::new(
                "what woke the PC",
                "Nothing was logged for this wake. Reading the live wake timers \
                 (pcsleuth wake --elevate) and the devices allowed to wake the PC narrows it down \
                 before the next sleep.",
            ),
        )
    };
    let _ = wake;
    not_recorded_citing(
        "wake.unknown_source",
        Question::Wake,
        format!("{}: Windows did not record what woke it", kind.woke_from()),
        explanation,
        gap,
        evidence,
    )
}

fn standby_finding(
    exit: &ModernStandbyExited,
    entered: Option<&ModernStandbyEntered>,
) -> Result<Finding, FindingError> {
    let span = exit.duration_us.map(Duration::from_micros);
    let headline = match span {
        Some(span) => format!("Left Modern Standby after {}", duration(span)),
        None => "Left Modern Standby".to_owned(),
    };
    let deepest = match (exit.drips_residency_us, exit.duration_us) {
        (Some(deepest), Some(total)) if total > 0 => format!(
            " It spent {}% of that time in its deepest low-power state.",
            (deepest.min(total) as f64 / total as f64 * 100.0).floor()
        ),
        _ => String::new(),
    };
    let mut evidence = vec![stamped(exit.to_evidence(), &exit.meta)];
    evidence.extend(entered.map(|e| stamped(e.to_evidence(), &e.meta)));
    let finding = Finding::recorded(
        "wake.modern_standby",
        Question::Wake,
        headline,
        format!(
            "Modern Standby is the low-power idle state some PCs use instead of sleep.{deepest} \
             Windows gave its reason for leaving as {}, and pcsleuth cannot name that code yet.",
            exit.reason
        ),
        evidence,
    )
    .and_then(|f| {
        f.with_gap(NotRecorded::new(
            "what ended Modern Standby",
            "Windows logs only a numeric reason, and nobody has matched those numbers to causes \
             on real Modern Standby hardware yet.",
        ))
    })?;
    Ok(match exit.meta.time {
        Some(time) => finding.at(time),
        None => finding,
    })
}

fn live_findings(input: &Input, window: &Window, out: &mut Findings) {
    timer_findings(&input.timers, Question::Wake, window, out);
    armed_finding(&input.armed, window, out);
    tasks_finding(&input.tasks, window, out);
}

/// One finding per armed wake timer, or one saying there are none. Shared with `now`.
pub(crate) fn timer_findings(
    timers: &Sourced<WakeTimer>,
    question: Question,
    window: &Window,
    out: &mut Findings,
) {
    if !timers.access.is_ok() && timers.data.is_empty() {
        return;
    }
    if timers.data.is_empty() {
        out.push(Finding::recorded(
            format!("{question}.no_timers"),
            question,
            "No wake timers are armed right now",
            "A wake timer is an alarm that a program sets to wake the PC. Windows lists none.",
            [live(SourceId::WakeTimers, window.now).with_field("armed_timers", "0")],
        ));
    }
    for timer in &timers.data {
        out.push(timer_finding(timer, question, window));
    }
}

fn timer_finding(
    timer: &WakeTimer,
    question: Question,
    window: &Window,
) -> Result<Finding, FindingError> {
    let mut evidence = live(SourceId::WakeTimers, window.now);
    let owner = match &timer.owner {
        Requester::Process { image, .. } => {
            let image = image.as_deref().unwrap_or("a program");
            if let Some(exe) = exe_name(image) {
                evidence = evidence.with_field("process", exe);
            }
            file_name(image).to_owned()
        }
        Requester::Service { image, tag, .. } => {
            let image = image.as_deref().unwrap_or("a service host");
            if let Some(exe) = exe_name(image) {
                evidence = evidence.with_field("process", exe);
            }
            format!(
                "a Windows service running inside {} (service tag {tag})",
                file_name(image)
            )
        }
        Requester::Driver {
            description,
            device_path,
        } => {
            let name = description.as_deref().or(device_path.as_deref());
            if let Some(name) = name {
                evidence = evidence.with_field("driver", name);
            }
            format!("the driver {}", name.unwrap_or("(unnamed)"))
        }
        Requester::Unknown(kind) => format!("an owner of type {kind}"),
    };
    if let Some(due) = timer.due {
        evidence = evidence.with_field("due", due.to_string());
    }
    let due = between(Some(window.now), timer.due)
        .map(|span| format!(" It is due in {}.", duration(span)))
        .unwrap_or_default();
    let repeat = if timer.period_ms > 0 {
        format!(
            " It repeats every {}.",
            duration(Duration::from_millis(u64::from(timer.period_ms)))
        )
    } else {
        String::new()
    };
    let reason = match &timer.reason {
        Some(Reason::Text(text)) => format!(" The reason it gave: \"{text}\"."),
        _ => String::new(),
    };
    Finding::recorded(
        format!("{question}.timer_armed"),
        question,
        format!("A wake timer set by {owner} is armed"),
        format!(
            "A wake timer is an alarm that a program sets to wake the PC. Windows lists this one \
             as set by {owner}.{due}{repeat}{reason}"
        ),
        [evidence],
    )
}

fn armed_finding(armed: &Sourced<ArmedDevice>, window: &Window, out: &mut Findings) {
    if !armed.access.is_ok() && armed.data.is_empty() {
        return;
    }
    if armed.data.is_empty() {
        out.push(Finding::recorded(
            "wake.armed_devices",
            Question::Wake,
            "No device is allowed to wake the PC",
            "Windows lists no device that is armed to wake the PC.",
            [live(SourceId::ArmedDevices, window.now).with_field("armed_devices", "0")],
        ));
        return;
    }
    const SHOWN: usize = 30;
    let mut names: Vec<String> = armed
        .data
        .iter()
        .take(SHOWN)
        .map(|d| d.name.clone())
        .collect();
    if armed.data.len() > SHOWN {
        names.push(format!("and {} more", armed.data.len() - SHOWN));
    }
    let count = armed.data.len();
    // "Allowed to wake" is not "woke it", so these carry `armed_device`, never `device`.
    let evidence = armed.data.iter().take(SHOWN).map(|d| {
        live(SourceId::ArmedDevices, window.now).with_field("armed_device", d.name.as_str())
    });
    out.push(Finding::recorded(
        "wake.armed_devices",
        Question::Wake,
        format!(
            "{count} {} allowed to wake the PC",
            if count == 1 {
                "device is"
            } else {
                "devices are"
            }
        ),
        format!(
            "Allowed to wake is not the same as woke it. Armed: {}. To stop one from waking the \
             PC, run powercfg /devicedisablewake \"device name\" as an administrator.",
            names.join("; ")
        ),
        evidence,
    ));
}

fn tasks_finding(tasks: &Sourced<TaskScan>, window: &Window, out: &mut Findings) {
    let Some(scan) = tasks.data.first() else {
        return;
    };
    let waking: Vec<_> = scan
        .wake_tasks
        .iter()
        .filter(|t| t.enabled != Some(false) && t.state != TaskState::Disabled)
        .collect();
    let seen = if scan.elevated {
        "Windows lists"
    } else {
        "Among the tasks this user can see, Windows lists"
    };
    if waking.is_empty() {
        out.push(Finding::recorded(
            "wake.scheduled_tasks",
            Question::Wake,
            "No scheduled task is set to wake the PC",
            format!("{seen} no enabled scheduled task that is allowed to wake the PC."),
            [live(SourceId::ScheduledTasks, window.now).with_field("wake_tasks", "0")],
        ));
        return;
    }
    let lines: Vec<String> = waking
        .iter()
        .take(8)
        .map(|task| match between(Some(window.now), task.next_run) {
            Some(span) => format!(
                "{} (next run in {})",
                collapse_sids(&task.path),
                duration(span)
            ),
            None => collapse_sids(&task.path),
        })
        .collect();
    let evidence = waking.iter().take(8).map(|task| {
        let mut e = live(SourceId::ScheduledTasks, window.now)
            .with_field("task", collapse_sids(&task.path));
        if let Some(next) = task.next_run {
            e = e.with_field("next_run", next.to_string());
        }
        e
    });
    out.push(Finding::recorded(
        "wake.scheduled_tasks",
        Question::Wake,
        format!(
            "{} scheduled {} set to wake the PC",
            waking.len(),
            if waking.len() == 1 {
                "task is"
            } else {
                "tasks are"
            }
        ),
        format!(
            "{seen} these enabled tasks as allowed to wake the PC to run: {}. Being allowed to \
             wake it does not mean one did.",
            lines.join("; ")
        ),
        evidence,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_means_within_ten_seconds_either_way() {
        let at = |text: &str| Some(text.parse::<jiff::Timestamp>().unwrap());
        assert!(close(
            at("2026-11-04T00:00:00Z"),
            at("2026-11-04T00:00:09Z")
        ));
        assert!(close(
            at("2026-11-04T00:00:09Z"),
            at("2026-11-04T00:00:00Z")
        ));
        assert!(!close(
            at("2026-11-04T00:00:00Z"),
            at("2026-11-04T00:00:11Z")
        ));
        assert!(!close(None, at("2026-11-04T00:00:00Z")));
        assert!(close(
            at("2026-11-04T00:00:00Z"),
            at("2026-11-04T00:00:00Z")
        ));
    }
}
