//! `crash`: what was the PC doing when something crashed, froze or restarted?
//!
//! Application Error 1000, Application Hang 1002 and Windows Error Reporting 1001 name the
//! program. Kernel-Power 41, EventLog 6008 and bugcheck 1001 describe a restart that was not
//! clean, and are folded into one finding per restart. Kernel-Power 41 alone says power was
//! lost, never why, so that case is "not recorded". User32 1074 says which program asked for a
//! shutdown or restart, never which of the two (ADR 0002).

use std::collections::BTreeMap;
use std::time::Duration;

use jiff::Timestamp;
use pcsleuth_core::{Answer, Evidence, Finding, FindingError, NotRecorded, Question, Sourced};
use pcsleuth_sources::eventlog::{
    AppCrash, AppHang, ApplicationEvent, Bugcheck, KernelPowerEvent, LifecycleEvent,
    ShutdownInitiated, UncleanReboot, UnexpectedShutdown, WerReport,
};

use crate::common::{Findings, Limits, Window, finish, stamped};

pub struct Input {
    pub applications: Sourced<ApplicationEvent>,
    pub lifecycle: Sourced<LifecycleEvent>,
    pub kernel_power: Sourced<KernelPowerEvent>,
}

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.applications);
    limits.note(&input.lifecycle);
    limits.note(&input.kernel_power);
    let findings = event_findings(
        &input.applications,
        &input.lifecycle,
        &input.kernel_power,
        window,
    );
    finish(Question::Crash, window, findings.0, limits)
}

pub fn event_findings(
    applications: &Sourced<ApplicationEvent>,
    lifecycle: &Sourced<LifecycleEvent>,
    kernel_power: &Sourced<KernelPowerEvent>,
    window: &Window,
) -> Findings {
    let mut out = Findings::default();
    application_findings(applications, window, &mut out);
    restart_findings(lifecycle, kernel_power, window, &mut out);
    shutdown_requests(lifecycle, window, &mut out);
    out
}

/// How close in time two records must be to describe the same crash or restart.
const SAME_CRASH: Duration = Duration::from_secs(120);
const SAME_RESTART: Duration = Duration::from_secs(300);

fn gap(a: Option<Timestamp>, b: Option<Timestamp>) -> Option<Duration> {
    let (a, b) = (a?, b?);
    let span = if a >= b {
        a.duration_since(b)
    } else {
        b.duration_since(a)
    };
    Duration::try_from(span).ok()
}

/// WER bucket names whose first parameter is the program, from the WER documentation of each
/// bucket's parameters. Any other name does not say what its parameters are.
fn is_program_report(event_name: &str) -> bool {
    ["APPCRASH", "BEX", "BEX64", "AppHangB1"]
        .iter()
        .any(|name| event_name.eq_ignore_ascii_case(name))
}

fn application_findings(
    applications: &Sourced<ApplicationEvent>,
    window: &Window,
    out: &mut Findings,
) {
    let in_window = |meta: &pcsleuth_sources::eventlog::Meta| window.contains(meta.time);
    let crashes: Vec<&AppCrash> = applications
        .data
        .iter()
        .filter_map(|e| match e {
            ApplicationEvent::Crash(c) if in_window(&c.meta) => Some(c),
            _ => None,
        })
        .collect();
    let hangs: Vec<&AppHang> = applications
        .data
        .iter()
        .filter_map(|e| match e {
            ApplicationEvent::Hang(h) if in_window(&h.meta) => Some(h),
            _ => None,
        })
        .collect();
    let reports: Vec<&WerReport> = applications
        .data
        .iter()
        .filter_map(|e| match e {
            ApplicationEvent::Report(r) if in_window(&r.meta) => Some(r),
            _ => None,
        })
        .collect();

    // Each program report joins the nearest crash or hang of the same program, once.
    let mut joined: Vec<Vec<&WerReport>> = vec![Vec::new(); crashes.len() + hangs.len()];
    let mut used = vec![false; reports.len()];
    for (i, report) in reports.iter().enumerate() {
        if !is_program_report(&report.event_name) {
            continue;
        }
        let Some(program) = report.parameters.first() else {
            continue;
        };
        let candidates = crashes
            .iter()
            .map(|c| (c.app_name.as_str(), c.meta.time))
            .chain(hangs.iter().map(|h| (h.app_name.as_str(), h.meta.time)))
            .enumerate()
            .filter(|(_, (name, _))| name.eq_ignore_ascii_case(program))
            .filter_map(|(slot, (_, time))| gap(time, report.meta.time).map(|g| (slot, g)))
            .filter(|(_, g)| *g <= SAME_CRASH)
            .min_by_key(|(_, g)| *g);
        if let Some((slot, _)) = candidates {
            joined[slot].push(report);
            used[i] = true;
        }
    }

    for (slot, crash) in crashes.iter().enumerate() {
        let mut evidence = vec![stamped(crash.to_evidence(), &crash.meta)];
        evidence.extend(
            joined[slot]
                .iter()
                .map(|r| stamped(r.to_evidence(), &r.meta)),
        );
        out.push(crash_finding(crash, evidence));
    }
    for (slot, hang) in hangs.iter().enumerate() {
        let mut evidence = vec![hang_evidence(hang)];
        evidence.extend(
            joined[crashes.len() + slot]
                .iter()
                .map(|r| stamped(r.to_evidence(), &r.meta)),
        );
        out.push(hang_finding(
            Question::Crash,
            "crash.app_hang",
            hang,
            evidence,
        ));
    }

    let mut other: Vec<&WerReport> = Vec::new();
    for (i, report) in reports.iter().enumerate() {
        if used[i] {
            continue;
        }
        if is_program_report(&report.event_name) && !report.parameters.is_empty() {
            out.push(program_report(report));
        } else {
            other.push(report);
        }
    }
    if !other.is_empty() {
        out.push(other_reports(&other));
    }
}

fn gloss(code: u32) -> Option<&'static str> {
    Some(match code {
        0xC000_0005 => "an access violation: the program touched memory it was not allowed to",
        0xC000_0409 => "a program safety check failed, such as a stack buffer overrun",
        0xC000_00FD => "a stack overflow",
        0xC000_0374 => "heap corruption",
        0xC000_0094 => "an integer divide by zero",
        0xE043_4352 => "a .NET exception that nothing handled",
        0xE06D_7363 => "a C++ exception that nothing handled",
        0x8000_0003 => "a breakpoint",
        _ => return None,
    })
}

fn crash_finding(crash: &AppCrash, evidence: Vec<Evidence>) -> Result<Finding, FindingError> {
    let mut evidence = evidence;
    if let Some(first) = evidence.first_mut() {
        first
            .fields
            .insert("process".into(), crash.app_name.clone());
    }
    let place = crash
        .module_name
        .as_deref()
        .map(|module| {
            format!(
                " The failure was seen in {module}, which is where Windows saw it, not always \
                 where the bug is."
            )
        })
        .unwrap_or_default();
    let code = crash
        .exception_code
        .map(|code| match gloss(code) {
            Some(what) => format!(" Exception code 0x{code:08x} means {what}."),
            None => format!(" Exception code 0x{code:08x}."),
        })
        .unwrap_or_default();
    let finding = Finding::recorded(
        "crash.app_crash",
        Question::Crash,
        format!("{} crashed", crash.app_name),
        format!(
            "Windows logged an Application Error (event 1000), which is a program crash.{place}{code}"
        ),
        evidence,
    )?;
    Ok(match crash.meta.time {
        Some(time) => finding.at(time),
        None => finding,
    })
}

pub(crate) fn hang_evidence(hang: &AppHang) -> Evidence {
    stamped(hang.to_evidence(), &hang.meta).with_field("process", hang.app_name.clone())
}

/// A hang finding for `question`, shared with `slow`.
pub(crate) fn hang_finding(
    question: Question,
    id: &str,
    hang: &AppHang,
    evidence: Vec<Evidence>,
) -> Result<Finding, FindingError> {
    let kind = hang
        .hang_type
        .as_deref()
        .map(|kind| format!(" Windows' own hang type for it is \"{kind}\"."))
        .unwrap_or_default();
    let finding = Finding::recorded(
        id,
        question,
        format!("{} stopped responding", hang.app_name),
        format!(
            "Windows logged an Application Hang (event 1002): the program stopped answering \
             Windows.{kind}"
        ),
        evidence,
    )?;
    Ok(match hang.meta.time {
        Some(time) => finding.at(time),
        None => finding,
    })
}

fn program_report(report: &WerReport) -> Result<Finding, FindingError> {
    let program = report.parameters.first().cloned().unwrap_or_default();
    let finding = Finding::recorded(
        "crash.wer_report",
        Question::Crash,
        format!("Windows filed a crash report for {program}"),
        format!(
            "Windows Error Reporting kept a report named {} (event 1001). For this kind of \
             report the first detail is the program.",
            report.event_name
        ),
        [stamped(report.to_evidence(), &report.meta).with_field("process", program)],
    )?;
    Ok(match report.meta.time {
        Some(time) => finding.at(time),
        None => finding,
    })
}

/// How many of the other reports are cited as evidence. A busy PC files hundreds of them.
const OTHER_REPORTS_CITED: usize = 10;

fn other_reports(reports: &[&WerReport]) -> Result<Finding, FindingError> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for report in reports {
        *counts.entry(report.event_name.as_str()).or_default() += 1;
    }
    let mut counts: Vec<(&str, usize)> = counts.into_iter().collect();
    counts.sort_by_key(|(name, count)| (std::cmp::Reverse(*count), *name));
    let mut names: Vec<String> = counts
        .iter()
        .take(5)
        .map(|(name, count)| format!("{name} x{count}"))
        .collect();
    if counts.len() > 5 {
        names.push(format!("and {} more types", counts.len() - 5));
    }
    let mut newest: Vec<&&WerReport> = reports.iter().collect();
    newest.sort_by_key(|r| std::cmp::Reverse(r.meta.time));
    let cited = if reports.len() > OTHER_REPORTS_CITED {
        format!(" The newest {OTHER_REPORTS_CITED} are cited.")
    } else {
        String::new()
    };
    let latest = reports.iter().filter_map(|r| r.meta.time).max();
    let finding = Finding::recorded(
        "crash.other_reports",
        Question::Crash,
        format!("Windows filed {} other error reports", reports.len()),
        format!(
            "Windows Error Reporting also kept reports of other types ({}). pcsleuth does not \
             know what each type means, so it does not call them crashes.{cited}",
            names.join(", ")
        ),
        newest
            .iter()
            .take(OTHER_REPORTS_CITED)
            .map(|r| stamped(r.to_evidence(), &r.meta)),
    )?;
    Ok(match latest {
        Some(time) => finding.at(time),
        None => finding,
    })
}

enum Piece<'a> {
    Reboot(&'a UncleanReboot),
    Unexpected(&'a UnexpectedShutdown),
    Bugcheck(&'a Bugcheck),
}

impl Piece<'_> {
    fn time(&self) -> Option<Timestamp> {
        match self {
            Piece::Reboot(e) => e.meta.time,
            Piece::Unexpected(e) => e.meta.time,
            Piece::Bugcheck(e) => e.meta.time,
        }
    }
}

fn bugcheck_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x0A => "IRQL_NOT_LESS_OR_EQUAL",
        0x1A => "MEMORY_MANAGEMENT",
        0x1E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x3B => "SYSTEM_SERVICE_EXCEPTION",
        0x50 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x7A => "KERNEL_DATA_INPAGE_ERROR",
        0x7E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x9F => "DRIVER_POWER_STATE_FAILURE",
        0xD1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0xEF => "CRITICAL_PROCESS_DIED",
        0x124 => "WHEA_UNCORRECTABLE_ERROR",
        0x133 => "DPC_WATCHDOG_VIOLATION",
        0x139 => "KERNEL_SECURITY_CHECK_FAILURE",
        _ => return None,
    })
}

/// One finding per restart that was not clean. The records of one restart arrive within minutes
/// of each other, so they are grouped by time.
fn restart_findings(
    lifecycle: &Sourced<LifecycleEvent>,
    kernel_power: &Sourced<KernelPowerEvent>,
    window: &Window,
    out: &mut Findings,
) {
    let mut pieces: Vec<Piece> = Vec::new();
    for event in &lifecycle.data {
        match event {
            LifecycleEvent::UnexpectedShutdown(e) if window.contains(e.meta.time) => {
                pieces.push(Piece::Unexpected(e));
            }
            LifecycleEvent::Bugcheck(e) if window.contains(e.meta.time) => {
                pieces.push(Piece::Bugcheck(e));
            }
            _ => {}
        }
    }
    for event in &kernel_power.data {
        if let KernelPowerEvent::UncleanReboot(e) = event
            && window.contains(e.meta.time)
        {
            pieces.push(Piece::Reboot(e));
        }
    }
    pieces.sort_by_key(Piece::time);

    let mut group: Vec<&Piece> = Vec::new();
    let mut last: Option<Timestamp> = None;
    for piece in &pieces {
        let separate = match (last, piece.time()) {
            (Some(last), now) => gap(Some(last), now).is_none_or(|g| g > SAME_RESTART),
            _ => false,
        };
        if separate {
            out.push(restart_finding(&group, window));
            group.clear();
        }
        last = piece.time();
        group.push(piece);
    }
    if !group.is_empty() {
        out.push(restart_finding(&group, window));
    }
}

fn restart_finding(group: &[&Piece], window: &Window) -> Result<Finding, FindingError> {
    let reboot = group.iter().find_map(|p| match p {
        Piece::Reboot(e) => Some(*e),
        _ => None,
    });
    let unexpected = group.iter().find_map(|p| match p {
        Piece::Unexpected(e) => Some(*e),
        _ => None,
    });
    let bugcheck = group.iter().find_map(|p| match p {
        Piece::Bugcheck(e) => Some(*e),
        _ => None,
    });
    let mut evidence = Vec::new();
    if let Some(e) = reboot {
        evidence.push(stamped(e.to_evidence(), &e.meta));
    }
    if let Some(e) = unexpected {
        evidence.push(stamped(e.to_evidence(), &e.meta));
    }
    if let Some(e) = bugcheck {
        evidence.push(stamped(e.to_evidence(), &e.meta));
    }
    let earliest = group.iter().filter_map(|p| p.time()).min();
    // When the PC was last known to be running is the best time for "when it stopped".
    let happened = unexpected
        .and_then(|e| e.previous_shutdown)
        .filter(|time| *time >= window.since)
        .or(earliest);
    let at = |finding: Finding| match happened {
        Some(time) => finding.at(time),
        None => finding,
    };

    let code = bugcheck.map(|b| b.code).or_else(|| {
        reboot
            .filter(|r| r.bugcheck_recorded())
            .and_then(|r| r.bugcheck_code)
    });
    if let Some(code) = code {
        let name = bugcheck_name(code)
            .map(|name| format!(", {name}"))
            .unwrap_or_default();
        let dump = bugcheck
            .and_then(|b| b.dump_path.as_deref())
            .map(|path| format!(" Windows saved a memory dump at {path}."))
            .unwrap_or_default();
        return Finding::recorded(
            "crash.blue_screen",
            Question::Crash,
            format!("The PC restarted after a blue screen (stop code 0x{code:08X}{name})"),
            format!(
                "A blue screen is Windows stopping itself after a fatal error, and the stop code \
                 says which kind.{dump} The records here are Windows' own (bugcheck, event 1001, \
                 and Kernel-Power, event 41)."
            ),
            evidence,
        )
        .map(at);
    }
    if reboot.is_some_and(|r| r.long_power_button_press == Some(true)) {
        return Finding::recorded(
            "crash.forced_off",
            Question::Crash,
            "The PC was forced off: the power button was held down",
            "Windows recorded that the power button was held down (Kernel-Power, event 41). \
             That cuts the power without a clean shutdown.",
            evidence,
        )
        .map(at);
    }
    let sleeping = reboot
        .and_then(|r| r.sleep_in_progress)
        .filter(|n| *n > 0)
        .map(|_| " Windows also noted that a sleep was in progress.")
        .unwrap_or_default();
    // Say "recorded no X" only for what the record actually carries and found empty.
    let mut empty = Vec::new();
    if reboot.is_some_and(|r| r.bugcheck_code == Some(0)) {
        empty.push("no blue screen code");
    }
    if reboot.is_some_and(|r| r.long_power_button_press == Some(false)) {
        empty.push("no power button hold");
    }
    let absent = if empty.is_empty() {
        String::new()
    } else {
        format!(" and recorded {}", empty.join(" and "))
    };
    Finding::not_recorded(
        "crash.power_lost",
        Question::Crash,
        "The PC lost power or stopped completely, and Windows does not know why",
        format!(
            "Windows found that the PC had not shut down cleanly (Kernel-Power event 41, EventLog \
             event 6008){absent}. Possible reasons include a power cut, a flat battery, a hard \
             reset or a hardware fault; Windows did not record which.{sleeping}"
        ),
        NotRecorded::new(
            "why the PC lost power",
            "Windows keeps nothing more after the fact. The pcsleuth recorder (opt-in) shows what \
             the PC was doing just before the next time this happens.",
        ),
    )
    .map(|finding| at(finding.with_evidence(evidence)))
}

/// One finding per program that asked for a shutdown or restart, with how many times. A busy PC
/// logs hundreds of these, and they are context, not crashes, so they never get one finding each.
fn shutdown_requests(lifecycle: &Sourced<LifecycleEvent>, window: &Window, out: &mut Findings) {
    let mut by_program: BTreeMap<String, Vec<&ShutdownInitiated>> = BTreeMap::new();
    for event in &lifecycle.data {
        if let LifecycleEvent::ShutdownInitiated(request) = event
            && window.contains(request.meta.time)
        {
            let key = request.process_name().unwrap_or("").to_lowercase();
            by_program.entry(key).or_default().push(request);
        }
    }
    for requests in by_program.values() {
        out.push(shutdown_request(requests));
    }
}

/// The finding for one program's requests. It cites the newest record only.
fn shutdown_request(requests: &[&ShutdownInitiated]) -> Result<Finding, FindingError> {
    let newest = requests
        .iter()
        .max_by_key(|r| r.meta.time)
        .copied()
        .ok_or(FindingError::Blank("shutdown requests"))?;
    let count = requests.len();
    let program = newest.process_name().map(str::to_owned);
    let mut evidence =
        stamped(newest.to_evidence(), &newest.meta).with_field("requests", count.to_string());
    if let Some(program) = &program {
        evidence = evidence.with_field("process", program.clone());
    }

    let planned = |code: u32| {
        if code & 0x8000_0000 != 0 {
            "marked as planned"
        } else {
            "not marked as planned"
        }
    };
    let name = program.as_deref().unwrap_or("A program");
    let (headline, detail) = if count == 1 {
        let reason = newest
            .reason_code
            .map(|code| format!(" Windows gave reason code 0x{code:x} ({}).", planned(code)))
            .unwrap_or_default();
        (
            format!("{name} asked Windows to shut down or restart"),
            format!("Windows logged a shutdown request (User32, event 1074).{reason}"),
        )
    } else {
        let mut codes: BTreeMap<u32, usize> = BTreeMap::new();
        for code in requests.iter().filter_map(|r| r.reason_code) {
            *codes.entry(code).or_default() += 1;
        }
        let mut codes: Vec<(u32, usize)> = codes.into_iter().collect();
        codes.sort_by_key(|(code, n)| (std::cmp::Reverse(*n), *code));
        let seen: Vec<String> = codes
            .iter()
            .take(3)
            .map(|(code, n)| format!("0x{code:x} x{n} ({})", planned(*code)))
            .collect();
        let reasons = if seen.is_empty() {
            String::new()
        } else {
            format!(" Reason codes seen: {}.", seen.join(", "))
        };
        (
            format!("{name} asked Windows to shut down or restart {count} times"),
            format!(
                "Windows logged {count} shutdown requests (User32, event 1074) from this program. \
                 They are context, not crashes. Only the newest record is cited.{reasons}"
            ),
        )
    };
    let finding = Finding::recorded(
        "crash.shutdown_requested",
        Question::Crash,
        headline,
        format!(
            "{detail} The record does not say in a language-independent way whether it was a shut \
             down or a restart."
        ),
        [evidence],
    )?;
    Ok(match newest.meta.time {
        Some(time) => finding.at(time),
        None => finding,
    })
}
