//! `doctor`: which sources can be read, and what each adds.
//!
//! One finding per source. The command to switch on a disabled log is printed with what it
//! costs. Nothing is applied.

use pcsleuth_core::{
    Access, Answer, Evidence, Finding, FindingError, Limit, NotRecorded, Question, SourceId,
};
use pcsleuth_sources::eventlog::channel_for_source;

use crate::common::{Limits, Window, finish, fix};

/// What one source read gave. `log` is the Event Log side of a source that has both, such as the
/// Task Scheduler (its COM scan is `access`, its history log is `log`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub source: SourceId,
    pub access: Access,
    pub log: Option<Access>,
}

pub struct Input {
    pub probes: Vec<Probe>,
}

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    let mut findings = Vec::new();
    for probe in &input.probes {
        for access in std::iter::once(&probe.access).chain(probe.log.as_ref()) {
            if let Some(limit) = Limit::new(probe.source, access.clone())
                && !limits.0.contains(&limit)
            {
                limits.0.push(limit);
            }
        }
        match finding(probe, window) {
            Ok(finding) => findings.push(finding),
            Err(error) => debug_assert!(false, "a finding was refused: {error}"),
        }
    }
    // Source order, not time order: these findings have no dates, so the sort keeps their order.
    finish(Question::Doctor, window, findings, limits)
}

/// The name of a source in plain words, for `doctor` and for the command line.
pub fn label(source: SourceId) -> &'static str {
    match source {
        SourceId::EventLogSystem => "System event log",
        SourceId::EventLogApplication => "Application event log",
        SourceId::EventLogResourceExhaustion => {
            "Memory-warning event log (Resource-Exhaustion-Detector)"
        }
        SourceId::EventLogDiagnosticsPerformance => {
            "Boot and shutdown timing log (Diagnostics-Performance)"
        }
        SourceId::PowerSettings => "Power plan settings",
        SourceId::PowerState => "Power state",
        SourceId::ArmedDevices => "Devices allowed to wake the PC",
        SourceId::PowerRequests => "Live power requests",
        SourceId::WakeTimers => "Live wake timers",
        SourceId::BatteryReport => "Battery report",
        SourceId::Srum => "Per-app usage history (SRUM)",
        SourceId::ScheduledTasks => "Scheduled tasks",
        SourceId::Processes => "Running processes",
        SourceId::Recorder => "pcsleuth recorder",
    }
}

/// What reading the source adds, as it would follow "adds".
fn adds(source: SourceId) -> &'static str {
    match source {
        SourceId::EventLogSystem => {
            "wake and sleep history, unexpected restarts, blue screens and shutdown requests"
        }
        SourceId::EventLogApplication => "program crashes and hangs",
        SourceId::EventLogResourceExhaustion => "Windows' low-memory warnings",
        SourceId::EventLogDiagnosticsPerformance => "what slowed boots and shutdowns",
        SourceId::PowerSettings => "the sleep timeouts",
        SourceId::PowerState => {
            "the keep-awake flags, the power source and the last keyboard or mouse input"
        }
        SourceId::ArmedDevices => "which devices are allowed to wake the PC",
        SourceId::PowerRequests => "who is keeping the PC awake right now",
        SourceId::WakeTimers => "which alarms are set to wake the PC",
        SourceId::BatteryReport => "battery wear and the biggest drains",
        SourceId::Srum => "which apps used energy, CPU and disk",
        SourceId::ScheduledTasks => "which tasks can wake the PC",
        SourceId::Processes => "what is busy right now",
        SourceId::Recorder => "past CPU, disk and power-request detail that Windows does not keep",
    }
}

/// The cost of switching on a log, printed with its command.
const LOG_COST: &str = "Switches the log on. It costs a little disk and a little CPU: Windows \
    keeps the log at a fixed size and overwrites its oldest records. It records only from the \
    moment it is switched on, so it cannot explain what happened before. Needs admin. pcsleuth \
    does not run this for you.";

fn status(access: &Access) -> String {
    if access.is_ok() {
        "can be read".to_owned()
    } else if access.elevation_helps() {
        "needs admin".to_owned()
    } else if matches!(access, Access::LogDisabled) {
        "switched off".to_owned()
    } else if matches!(access, Access::Missing) {
        "missing on this PC".to_owned()
    } else if let Access::Partial { message } = access {
        format!("only partly readable ({message})")
    } else if let Access::Failed { code, .. } = access {
        format!("could not be read (0x{code:08x})")
    } else {
        access.to_string()
    }
}

fn finding(probe: &Probe, window: &Window) -> Result<Finding, FindingError> {
    let source = probe.source;
    let name = label(source);
    let log_off = |access: &Access| matches!(access, Access::LogDisabled);

    // The log to switch on: the source's own channel, or its separate history log.
    let channel = if log_off(&probe.access) || probe.log.as_ref().is_some_and(log_off) {
        channel_for_source(source)
    } else {
        None
    };
    let history = probe.log.as_ref().filter(|log| log_off(log));

    let mut headline = format!("{name}: {}", status(&probe.access));
    if history.is_some() {
        headline = if probe.access.is_ok() {
            format!("{name}: can be read, but its history log is switched off")
        } else {
            format!(
                "{name}: {}, and its history log is switched off",
                status(&probe.access)
            )
        };
    }
    if source == SourceId::Recorder && matches!(probe.access, Access::Missing) {
        headline = format!("{name}: not set up");
    }

    let detail = match &probe.access {
        Access::Failed { message, .. } if !message.trim().is_empty() => {
            format!(" Windows said: {message}.")
        }
        _ => String::new(),
    };
    let explanation = format!("This source adds {}.{detail}", adds(source));
    let evidence = Evidence::new(source)
        .at(window.now)
        .with_field("access", probe.access.to_string());

    let would_capture = if channel.is_some() {
        let elevate = if probe.access.elevation_helps() {
            "run the same command with --elevate for the part that needs admin, and "
        } else {
            ""
        };
        format!("{elevate}switch the log on (see the suggested fix); it records from then on")
    } else if probe.access.elevation_helps() {
        "run the same command with --elevate; Windows asks you for permission".to_owned()
    } else if source == SourceId::Recorder {
        "set up the pcsleuth recorder (opt-in, off by default); until then past CPU, disk and \
         power-request detail is not recorded"
            .to_owned()
    } else if matches!(probe.access, Access::Missing) {
        "nothing to switch on: this PC does not have it".to_owned()
    } else {
        "run the command again; if it keeps failing the reason is shown above".to_owned()
    };

    let built = if probe.access.is_ok() || matches!(probe.access, Access::Partial { .. }) {
        let finding = Finding::recorded(
            format!("doctor.{source}"),
            Question::Doctor,
            headline,
            explanation,
            [evidence],
        )?;
        match &probe.access {
            Access::Partial { message } => finding.with_gap(NotRecorded::new(
                format!("part of {name}: {message}"),
                "run the command again; if it keeps failing, the log may be damaged",
            ))?,
            _ if history.is_some() => finding.with_gap(NotRecorded::new(
                format!("{name} history: the log is switched off"),
                would_capture,
            ))?,
            _ => finding,
        }
    } else {
        Finding::not_recorded(
            format!("doctor.{source}"),
            Question::Doctor,
            headline,
            explanation,
            NotRecorded::new(adds(source), would_capture),
        )?
    };
    Ok(match channel {
        Some(channel) => built.with_fix(fix(
            format!("wevtutil sl {channel} /e:true"),
            LOG_COST,
            true,
        )),
        None => built,
    })
}
