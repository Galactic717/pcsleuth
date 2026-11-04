//! `nosleep`: why will the PC not stay asleep (or go to sleep)?
//!
//! Three kinds of answer. A sleep timeout set to never is recorded in the power plan. A live
//! power request names its owner, but only when elevated. What held the PC awake in the past is
//! not logged anywhere, so that is "not recorded" unless the recorder saw it.

use pcsleuth_core::{
    Answer, Evidence, Finding, NotRecorded, Question, RecorderRow, SourceId, Sourced,
};
use pcsleuth_sources::eventlog::PowerTroubleshooterWake;
use pcsleuth_sources::power::{ExecutionState, LastInput, PowerRequest, SleepSettings, Timeout};

use crate::common::{Findings, Limits, Window, between, duration, finish, fix, live};
use crate::live::{execution_state_finding, request_findings};
use crate::recorded;
use crate::wake::Kind;

pub struct Input {
    pub settings: Sourced<SleepSettings>,
    pub requests: Sourced<PowerRequest>,
    pub execution_state: Sourced<ExecutionState>,
    pub last_input: Sourced<LastInput>,
    pub wakes: Sourced<PowerTroubleshooterWake>,
    pub recorder: Sourced<RecorderRow>,
}

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.settings);
    limits.note(&input.requests);
    limits.note(&input.execution_state);
    limits.note(&input.last_input);
    limits.note(&input.wakes);
    limits.note(&input.recorder);

    let now = window.now;
    let mut out = Findings::default();
    timeout_findings(&input.settings, now, &mut out);
    request_findings(&input.requests, Question::NoSleep, now, &mut out);
    execution_state_finding(&input.execution_state, Question::NoSleep, now, &mut out);
    last_input_finding(&input.last_input, now, &mut out);
    last_sleep_finding(&input.wakes, window, &mut out);

    let rows = recorded::rows_in_window(&input.recorder, window);
    if !recorded::request_findings(&rows, &mut out) {
        past_blockers(&rows, &mut out);
    }
    finish(Question::NoSleep, window, out.0, limits)
}

fn timeout_findings(settings: &Sourced<SleepSettings>, now: jiff::Timestamp, out: &mut Findings) {
    let Some(settings) = settings.data.first() else {
        return;
    };
    let sides = [
        ("ac", "while plugged in", settings.standby_timeout.ac, 30),
        ("dc", "on battery", settings.standby_timeout.dc, 15),
    ];
    let mut shown = Vec::new();
    let mut any_never = false;
    for (suffix, when, timeout, example) in sides {
        let Some(timeout) = timeout else { continue };
        let evidence = |value: String| -> Evidence {
            live(SourceId::PowerSettings, now)
                .with_field("scheme", settings.scheme.as_str())
                .with_field(format!("standby_timeout_{suffix}"), value)
        };
        match timeout {
            Timeout::Never => {
                any_never = true;
                out.push(
                    Finding::recorded(
                        "nosleep.timeout_never",
                        Question::NoSleep,
                        format!(
                            "The sleep timeout is set to Never {when}, so Windows will not sleep on its own"
                        ),
                        "The active power plan says never to put the PC to sleep after it has been \
                         idle. The PC can still be put to sleep by hand, and the lid and power button have their own settings.",
                        [evidence("never".into())],
                    )
                    .map(|f| {
                        f.with_fix(fix(
                            format!("powercfg /change standby-timeout-{suffix} {example}"),
                            format!(
                                "Makes the PC sleep after {example} minutes idle {when}. Change \
                                 {example} to taste. pcsleuth does not run this for you."
                            ),
                            false,
                        ))
                    }),
                );
            }
            Timeout::After(span) => {
                shown.push(format!("{} {when}", duration(span)));
            }
        }
    }
    if !any_never && !shown.is_empty() {
        let evidence =
            live(SourceId::PowerSettings, now).with_field("scheme", settings.scheme.as_str());
        out.push(Finding::recorded(
            "nosleep.timeouts",
            Question::NoSleep,
            format!("Sleep timeouts: {}", shown.join(", ")),
            format!(
                "The active power plan puts the PC to sleep after {} of no input. Windows itself \
                 would let it sleep, so something else keeps it awake if it does not.",
                shown.join(" and after ")
            ),
            [evidence],
        ));
    }
}

fn last_input_finding(input: &Sourced<LastInput>, now: jiff::Timestamp, out: &mut Findings) {
    let Some(last) = input.data.first() else {
        return;
    };
    out.push(Finding::recorded(
        "nosleep.last_input",
        Question::NoSleep,
        format!(
            "The last keyboard or mouse input was {} ago",
            duration(last.idle)
        ),
        "The sleep timeout counts idle time, which is measured from the last input. A program \
         that sends fake input counts as you.",
        [live(SourceId::PowerState, now).with_field("last_input", last.at.to_string())],
    ));
}

fn last_sleep_finding(
    wakes: &Sourced<PowerTroubleshooterWake>,
    window: &Window,
    out: &mut Findings,
) {
    if !wakes.access.is_ok() && wakes.data.is_empty() {
        return;
    }
    let latest = wakes
        .data
        .iter()
        .filter(|w| window.contains(w.meta.time) && !w.is_doze_timer())
        .max_by_key(|w| w.wake_time.or(w.meta.time));
    let Some(wake) = latest else {
        out.push(Finding::recorded(
            "nosleep.last_sleep",
            Question::NoSleep,
            "Windows logged no sleep or wake in this period",
            "Windows' wake log (Power-Troubleshooter) has no wake in the period asked about, so \
             the PC did not sleep in it, or the log was cleared.",
            [live(SourceId::EventLogSystem, window.now).with_field("wake_records", "0")],
        ));
        return;
    };
    let kind = Kind::of(wake);
    let ago = between(wake.wake_time.or(wake.meta.time), Some(window.now))
        .map(|span| format!(" {} ago", duration(span)))
        .unwrap_or_default();
    let before = between(wake.sleep_time, wake.wake_time)
        .map(|span| {
            let state = if kind == Kind::Hibernate {
                "hibernating"
            } else {
                "asleep"
            };
            format!(
                " The PC had been {state} for {} before that.",
                duration(span)
            )
        })
        .unwrap_or_default();
    out.push(Finding::recorded(
        "nosleep.last_sleep",
        Question::NoSleep,
        format!("The PC last woke from {}{ago}", kind.noun()),
        format!(
            "This is from Windows' wake log (Power-Troubleshooter).{before} The log has no later \
             wake, so the PC has not resumed from sleep or hibernate since; it may have been \
             restarted."
        ),
        [crate::common::stamped(wake.to_evidence(), &wake.meta)],
    ));
}

/// What the recorder's samples in the period do and do not show about past power requests. A
/// sample recorded without admin could not see requests at all, so it is never read as "none".
fn past_blockers(rows: &[&RecorderRow], out: &mut Findings) {
    let taken = rows.len();
    let looked = recorded::seeing_requests(rows);
    let plural = |n: usize| if n == 1 { "sample" } else { "samples" };
    let seen = if taken == 0 {
        String::new()
    } else if looked == 0 {
        format!(
            " The recorder took {taken} recorder {} in this period, but it was not running as \
             admin, so it could not see power requests in any of them. That says nothing about \
             what was held.",
            plural(taken)
        )
    } else {
        let blind = if looked < taken {
            format!(
                " The other {} could not see power requests because the recorder was not running \
                 as admin.",
                taken - looked
            )
        } else {
            String::new()
        };
        format!(
            " The recorder looked at power requests in {looked} of {taken} recorder {} in this \
             period and none showed one.{blind} It can miss anything shorter than its interval, \
             so that does not prove none was held.",
            plural(taken)
        )
    };
    let can_see = if taken > 0 && looked < taken {
        "the pcsleuth recorder running as admin (the installed service does), which samples \
         power requests every few seconds, or pcsleuth nosleep --elevate while the problem is \
         happening"
    } else {
        "the pcsleuth recorder (opt-in), which samples power requests every few seconds, or \
         pcsleuth nosleep --elevate while the problem is happening"
    };
    out.push(Finding::not_recorded(
        "nosleep.past_blockers",
        Question::NoSleep,
        "Windows did not record what kept the PC awake in the past",
        format!(
            "A power request is how a program or driver asks Windows to stay awake. Windows shows one \
             only while it is active and keeps no history of them. That is why pcsleuth can name a blocker that is holding right now (admin needed) or \
             one the recorder saw, and nothing earlier.{seen}"
        ),
        NotRecorded::new("which program or driver held the PC awake earlier", can_see),
    ));
}
