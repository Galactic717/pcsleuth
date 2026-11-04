//! The two output forms: JSON for programs, text for people.

use jiff::Timestamp;
use jiff::tz::TimeZone;
use pcsleuth_core::{Access, Answer, Confidence, Evidence, Finding, Fix, Limit, Question};
use pcsleuth_engine::{Resolved, collapse_sids, default_lookback, doctor::label};

/// Longest line the text output writes, indent included.
const WIDTH: usize = 100;

/// Most evidence lines shown for one finding. The JSON holds all of it.
const EVIDENCE_SHOWN: usize = 3;

/// The answer as pretty JSON, plus a newline.
///
/// Pure ASCII: non-ASCII text is written as `\uXXXX` escapes, which parse to the same strings. That
/// keeps the output intact through a cp1251 or cp866 console or a PowerShell pipe that would
/// otherwise mangle UTF-8 (docs/PLAN.md, first live probe).
pub fn json(answer: &Answer) -> serde_json::Result<String> {
    let text = serde_json::to_string_pretty(answer)?;
    let mut out = String::with_capacity(text.len() + 1);
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            // Non-ASCII can only occur inside JSON strings, where \u escapes are valid.
            for unit in c.encode_utf16(&mut [0; 2]) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out.push('\n');
    Ok(out)
}

/// The answer for a person: one block per finding, then what could not be read. Times are in
/// `zone`. `scope` is the window the answer looked at, shown so a default is never a surprise.
///
/// The text this program writes itself is ASCII. Text from Windows is shown as it came, minus
/// control characters and text-direction marks, which a log writer could use to move the cursor,
/// recolor the terminal or reorder what is read. Account SIDs are collapsed.
pub fn human(answer: &Answer, zone: &TimeZone, scope: Option<&Resolved>) -> String {
    let doctor = answer.question == Question::Doctor;
    let mut lines = vec![format!(
        "pcsleuth {} - generated {}",
        answer.question,
        time(answer.generated_at, zone)
    )];
    if let Some(scope) = scope.filter(|_| uses_window(answer.question)) {
        lines.push(scope_line(answer.question, scope, zone));
    }

    if answer.findings.is_empty() {
        lines.push(String::new());
        lines.push("No findings.".into());
    }
    for finding in &answer.findings {
        lines.push(String::new());
        finding_block(&mut lines, finding, zone, doctor);
    }

    // `doctor` is itself the list of what could and could not be read.
    if !answer.limits.is_empty() && !doctor {
        lines.push(String::new());
        lines.push("Could not be read in full:".into());
        lines.extend(answer.limits.iter().map(limit_line));
    }

    lines.push(String::new());
    lines.join("\n")
}

fn uses_window(question: Question) -> bool {
    !matches!(question, Question::Now | Question::Doctor)
}

fn scope_line(question: Question, scope: &Resolved, zone: &TimeZone) -> String {
    let since = if scope.since_is_default {
        let days = default_lookback(question).as_hours() / 24;
        format!("the default, {days} days")
    } else {
        "as you asked".to_owned()
    };
    let limit = if scope.limit_is_default {
        "the default"
    } else {
        "as you asked"
    };
    format!(
        "Looked back to {} ({since}). Showing at most {} dated findings ({limit}), the more \
         serious kinds first and then the newest of each kind; notes with no date are always \
         shown.",
        time(scope.window.since, zone),
        scope.window.limit
    )
}

fn finding_block(lines: &mut Vec<String>, finding: &Finding, zone: &TimeZone, doctor: bool) {
    lines.push(clean(finding.headline()));
    wrap(lines, finding.explanation(), "  ");
    // The note about what the limit left out is pcsleuth's own, so it has no confidence.
    let note = finding.id().ends_with(".left_out");
    if !doctor && !note {
        lines.push(format!(
            "  Confidence: {} ({})",
            finding.confidence(),
            meaning(finding.confidence())
        ));
    }
    if let Some(at) = finding.time() {
        lines.push(format!("  When: {}", time(at, zone)));
    }

    if !finding.evidence().is_empty() && !doctor && !note {
        lines.push("  Evidence:".into());
        for evidence in finding.evidence().iter().take(EVIDENCE_SHOWN) {
            lines.push(format!("    {}", evidence_line(evidence, zone)));
        }
        let hidden = finding.evidence().len().saturating_sub(EVIDENCE_SHOWN);
        if hidden > 0 {
            lines.push(format!(
                "    ... and {hidden} more (all of them are in the --json output)"
            ));
        }
    }
    if let Some(gap) = finding.gap() {
        wrap(lines, &format!("Not recorded: {}", gap.what), "  ");
        wrap(
            lines,
            &format!("What would capture it: {}", gap.would_capture),
            "  ",
        );
    }
    if let Some(fix) = finding.fix() {
        fix_block(lines, fix);
    }
}

fn meaning(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Recorded => "Windows states it directly",
        Confidence::Correlated => "inferred from records near it in time",
        Confidence::Sampled => "seen by the recorder at an interval",
        Confidence::NotRecorded => "Windows did not keep it",
    }
}

fn evidence_line(evidence: &Evidence, zone: &TimeZone) -> String {
    let mut line = clean(label(evidence.source));
    // Which program, device or task this piece of evidence is about, when it names one.
    let named = [
        "process",
        "device",
        "armed_device",
        "driver",
        "service",
        "task",
        "app",
    ]
    .iter()
    .find_map(|field| evidence.fields.get(*field));
    if let Some(name) = named {
        line.push_str(&format!(": {}", clean(name)));
        if let Some(pid) = evidence.fields.get("pid") {
            line.push_str(&format!(" (pid {})", clean(pid)));
        }
    }
    if let Some(id) = &evidence.record_id {
        line.push_str(&format!(", record {}", clean(id)));
    }
    if let Some(at) = evidence.timestamp {
        line.push_str(&format!(", {}", time(at, zone)));
    }
    line
}

/// A fix is a command for the reader to run. It is shown as a suggestion that was not applied, and
/// is withheld if cleaning it would change it, because then it would not be the command meant.
fn fix_block(lines: &mut Vec<String>, fix: &Fix) {
    let admin = if fix.needs_admin { "; needs admin" } else { "" };
    lines.push(format!("  Suggested fix (pcsleuth did not run it{admin}):"));
    if clean(&fix.command) == fix.command {
        lines.push(format!("    {}", fix.command));
    } else {
        lines.push(
            "    (command withheld: it holds control or text-direction characters)".to_owned(),
        );
    }
    wrap(lines, &fix.explanation, "    ");
}

fn limit_line(limit: &Limit) -> String {
    let status = match &limit.access {
        Access::Partial { message } => format!("only partly readable ({})", clean(message)),
        other => clean(&other.to_string()),
    };
    let adds = limit.adds.as_deref().map_or_else(String::new, |adds| {
        format!(" Running with --elevate adds {}.", clean(adds))
    });
    format!("  {}: {status}.{adds}", label(limit.source))
}

fn time(at: Timestamp, zone: &TimeZone) -> String {
    at.to_zoned(zone.clone())
        .strftime("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

/// Text-direction marks and overrides: they change how a line reads without being visible.
fn is_direction(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// `text` safe to print: control characters become spaces, direction marks and overrides are
/// removed, and account SIDs are collapsed.
fn clean(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .filter(|c| !is_direction(*c))
        .map(|c| {
            if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .collect();
    collapse_sids(&cleaned)
}

/// Push `text` as lines of at most `WIDTH` columns, each starting with `indent`.
fn wrap(lines: &mut Vec<String>, text: &str, indent: &str) {
    for paragraph in text.lines() {
        let mut line = String::from(indent);
        for word in clean(paragraph).split_whitespace() {
            let fresh = line.len() == indent.len();
            if !fresh && line.chars().count() + 1 + word.chars().count() > WIDTH {
                lines.push(std::mem::replace(&mut line, String::from(indent)));
            } else if !fresh {
                line.push(' ');
            }
            line.push_str(word);
        }
        if line.len() > indent.len() {
            lines.push(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::{Evidence, Fix, NotRecorded, SourceId, Sourced};
    use pcsleuth_engine::Window;

    use super::*;

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn zone() -> TimeZone {
        TimeZone::fixed(jiff::tz::offset(2))
    }

    fn scope(since_default: bool, limit_default: bool) -> Resolved {
        Resolved {
            window: Window {
                now: ts("2026-11-04T09:00:00Z"),
                since: ts("2026-10-28T09:00:00Z"),
                limit: 20,
            },
            since_is_default: since_default,
            limit_is_default: limit_default,
        }
    }

    fn sample() -> Answer {
        let wake = Finding::recorded(
            "wake.power_button",
            Question::Wake,
            "Woke from sleep: the power button was pressed",
            "Windows recorded it.\nNothing else was needed.",
            [
                Evidence::new(SourceId::EventLogSystem)
                    .with_record_id("360285")
                    .at(ts("2026-10-28T14:30:33Z")),
                Evidence::new(SourceId::EventLogSystem),
            ],
        )
        .unwrap()
        .at(ts("2026-10-28T14:30:33Z"))
        .with_fix(Fix::new("powercfg /requests", "Lists requests.", true));
        let nothing = Finding::not_recorded(
            "nosleep.past",
            Question::NoSleep,
            "Not recorded",
            "x",
            NotRecorded::new("past blockers", "the recorder"),
        )
        .unwrap();
        let limits = vec![
            Sourced::<()>::unreadable(SourceId::WakeTimers, Access::NeedsAdmin)
                .limit()
                .unwrap(),
            Sourced::<()>::unreadable(SourceId::Recorder, Access::Missing)
                .limit()
                .unwrap(),
            Sourced::<()>::unreadable(
                SourceId::EventLogSystem,
                Access::Partial {
                    message: "2 records could not be read".into(),
                },
            )
            .limit()
            .unwrap(),
        ];
        Answer::new(
            Question::Wake,
            ts("2026-11-03T12:00:00Z"),
            vec![wake, nothing],
            limits,
        )
    }

    #[test]
    fn human_output_has_the_window_confidence_evidence_and_limits() {
        let text = human(&sample(), &zone(), Some(&scope(true, false)));
        assert!(text.starts_with("pcsleuth wake - generated 2026-11-03 14:00:00 +02:00\n"));
        assert!(text.contains(
            "Looked back to 2026-10-28 11:00:00 +02:00 (the default, 7 days). Showing at most 20 \
             dated findings (as you asked), the more serious kinds first and then the newest of \
             each kind; notes with no date are always shown.\n"
        ));
        assert!(text.contains(
            "Woke from sleep: the power button was pressed\n  Windows recorded it.\n  Nothing else was needed.\n  Confidence: recorded (Windows states it directly)\n"
        ));
        assert!(
            text.contains("\n    System event log, record 360285, 2026-10-28 16:30:33 +02:00\n")
        );
        assert!(text.contains("\n    System event log\n"));
        assert!(text.contains("  Confidence: not recorded (Windows did not keep it)\n"));
        assert!(
            text.contains("  Not recorded: past blockers\n  What would capture it: the recorder\n")
        );
        assert!(text.contains(
            "\nCould not be read in full:\n  Live wake timers: needs admin. Running with --elevate adds live wake timers.\n  pcsleuth recorder: missing.\n  System event log: only partly readable (2 records could not be read).\n"
        ));
        assert!(text.is_ascii());
    }

    #[test]
    fn a_fix_is_shown_as_suggested_and_not_applied() {
        let text = human(&sample(), &zone(), None);
        assert!(text.contains(
            "  Suggested fix (pcsleuth did not run it; needs admin):\n    powercfg /requests\n    Lists requests.\n"
        ));
        assert!(!text.contains("Fix applied"));
    }

    #[test]
    fn a_fix_that_cleaning_would_change_is_withheld() {
        for command in [
            "powercfg /devicedisablewake \"a\u{202e}b\"",
            "echo \u{1b}[31mred",
            "echo a\u{200f}b",
        ] {
            let finding = Finding::recorded(
                "a",
                Question::Wake,
                "h",
                "x",
                [Evidence::new(SourceId::ArmedDevices)],
            )
            .unwrap()
            .with_fix(Fix::new(command, "Does something.", true));
            let answer = Answer::new(
                Question::Wake,
                ts("2026-11-03T12:00:00Z"),
                vec![finding],
                vec![],
            );
            let text = human(&answer, &zone(), None);
            assert!(text.contains("(command withheld"), "{command:?}");
            assert!(!text.contains("powercfg"), "{command:?}");
            assert!(
                !text.contains('\u{202e}')
                    && !text.contains('\u{1b}')
                    && !text.contains('\u{200f}')
            );
        }
    }

    #[test]
    fn no_findings_is_still_an_answer() {
        let answer = Answer::new(Question::Now, ts("2026-11-03T12:00:00Z"), vec![], vec![]);
        assert!(human(&answer, &zone(), None).contains("No findings."));
    }

    #[test]
    fn terminal_control_characters_from_logs_are_neutralized() {
        let finding = Finding::recorded(
            "a",
            Question::Crash,
            "bad \u{1b}[31mred\u{7}",
            "x",
            [Evidence::new(SourceId::EventLogApplication).with_record_id("1\r\n2")],
        )
        .unwrap();
        let answer = Answer::new(
            Question::Crash,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\r'));
    }

    #[test]
    fn text_direction_marks_and_overrides_are_removed_everywhere() {
        // Every override, isolate and mark, in the headline, the explanation, a gap and a limit.
        let bidi = "\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{200e}\u{200f}\u{061c}";
        let finding = Finding::not_recorded(
            "a",
            Question::Wake,
            format!("head{bidi}line"),
            format!("expl{bidi}anation 28.10.2026 {bidi}14:30"),
            NotRecorded::new(format!("wh{bidi}at"), format!("cap{bidi}ture")),
        )
        .unwrap();
        let answer = Answer::new(
            Question::Wake,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        assert!(text.contains("headline\n  explanation 28.10.2026 14:30\n"));
        assert!(text.contains("Not recorded: what"));
        assert!(text.contains("What would capture it: capture"));
        for c in bidi.chars() {
            assert!(!text.contains(c), "{c:?} survived");
        }
    }

    #[test]
    fn a_user_account_sid_is_collapsed_in_what_a_person_reads() {
        let finding = Finding::recorded(
            "a",
            Question::Wake,
            "Task OneDrive-S-1-5-21-111-222-333-1001 may wake the PC",
            "x",
            [Evidence::new(SourceId::ScheduledTasks)],
        )
        .unwrap();
        let answer = Answer::new(
            Question::Wake,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        assert!(text.contains("Task OneDrive-<user> may wake the PC"));
        assert!(!text.contains("S-1-5-21"));
    }

    #[test]
    fn long_explanations_wrap_and_keep_their_words() {
        let words = "word ".repeat(60);
        let finding = Finding::recorded(
            "a",
            Question::Wake,
            "h",
            words.trim(),
            [Evidence::new(SourceId::ArmedDevices)],
        )
        .unwrap();
        let answer = Answer::new(
            Question::Wake,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        for line in text.lines() {
            assert!(line.chars().count() <= WIDTH, "{line}");
        }
        assert_eq!(text.matches("word").count(), 60);
    }

    #[test]
    fn doctor_lists_each_source_without_confidence_or_a_second_limits_list() {
        let finding = Finding::not_recorded(
            "doctor.wake_timers",
            Question::Doctor,
            "Live wake timers: needs admin",
            "This source adds which alarms are set to wake the PC.",
            NotRecorded::new("what it adds", "run with --elevate"),
        )
        .unwrap();
        let limits = vec![
            Sourced::<()>::unreadable(SourceId::WakeTimers, Access::NeedsAdmin)
                .limit()
                .unwrap(),
        ];
        let answer = Answer::new(
            Question::Doctor,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            limits,
        );
        let text = human(&answer, &zone(), Some(&scope(true, true)));
        assert!(text.contains("Live wake timers: needs admin\n"));
        assert!(!text.contains("Confidence:"));
        assert!(!text.contains("Could not be read in full"));
        assert!(!text.contains("Looked back"));
    }

    #[test]
    fn a_long_evidence_list_is_cut_and_says_how_many_are_left() {
        let evidence: Vec<_> = (0..30)
            .map(|n| Evidence::new(SourceId::EventLogApplication).with_record_id(n.to_string()))
            .collect();
        let finding = Finding::recorded("a", Question::Crash, "h", "x", evidence).unwrap();
        let answer = Answer::new(
            Question::Crash,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        assert_eq!(text.matches("Application event log, record").count(), 3);
        assert!(text.contains("    ... and 27 more (all of them are in the --json output)\n"));
    }

    #[test]
    fn the_left_out_note_has_no_confidence_or_evidence_lines() {
        let note = Finding::recorded(
            "crash.left_out",
            Question::Crash,
            "6 more dated findings are not shown because of the limit of 4",
            "Left out: program crashes (5). To see everything, run again with --limit 10.",
            [Evidence::new(SourceId::EventLogSystem).with_field("left_out", "6")],
        )
        .unwrap();
        let answer = Answer::new(
            Question::Crash,
            ts("2026-11-03T12:00:00Z"),
            vec![note],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        assert!(text.contains("6 more dated findings are not shown because of the limit of 4\n"));
        assert!(text.contains("run again with --limit 10."));
        assert!(!text.contains("Confidence:") && !text.contains("Evidence:"));
    }

    #[test]
    fn evidence_names_the_program_or_device_it_is_about() {
        let finding = Finding::recorded(
            "a",
            Question::Crash,
            "h",
            "x",
            [
                Evidence::new(SourceId::EventLogApplication)
                    .with_record_id("170177")
                    .at(ts("2026-11-01T16:34:36Z"))
                    .with_field("process", "RedactedApp.exe"),
                Evidence::new(SourceId::ArmedDevices)
                    .with_field("armed_device", "USB Input Device"),
            ],
        )
        .unwrap();
        let answer = Answer::new(
            Question::Crash,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );
        let text = human(&answer, &zone(), None);
        assert!(text.contains(
            "\n    Application event log: RedactedApp.exe, record 170177, 2026-11-01 18:34:36 +02:00\n"
        ));
        assert!(text.contains("\n    Devices allowed to wake the PC: USB Input Device\n"));
    }

    #[test]
    fn json_is_ascii_and_means_the_same() {
        let cyrillic = "\u{41f}\u{440}\u{438}\u{432}\u{456}\u{442} \u{1f600}";
        let finding = Finding::recorded(
            "a",
            Question::Wake,
            cyrillic,
            "x",
            [Evidence::new(SourceId::ArmedDevices).with_field("device", cyrillic)],
        )
        .unwrap();
        let answer = Answer::new(
            Question::Wake,
            ts("2026-11-03T12:00:00Z"),
            vec![finding],
            vec![],
        );

        let text = json(&answer).unwrap();
        assert!(text.is_ascii());
        assert!(text.ends_with("}\n"));
        // "Pr" in Cyrillic, then an emoji as a UTF-16 surrogate pair.
        let escape = |unit: u16| format!("\\u{unit:04x}");
        assert!(text.contains(&(escape(0x41f) + &escape(0x440))));
        assert!(text.contains(&(escape(0xd83d) + &escape(0xde00))));
        assert_eq!(serde_json::from_str::<Answer>(&text).unwrap(), answer);
    }
}
