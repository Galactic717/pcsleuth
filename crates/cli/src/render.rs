//! The two output forms: JSON for programs, text for people.

use jiff::Timestamp;
use jiff::tz::TimeZone;
use pcsleuth_core::{Answer, Finding, Limit};

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

/// The answer for a person: one block per finding, then the limits. Times are in `zone`.
///
/// The text this program writes itself is ASCII. Text from Windows is shown as it came, minus
/// control characters, which a log writer could use to move the cursor or recolor the terminal.
pub fn human(answer: &Answer, zone: &TimeZone) -> String {
    let mut lines = vec![format!(
        "pcsleuth {} (generated {})",
        answer.question,
        time(answer.generated_at, zone)
    )];

    if answer.findings.is_empty() {
        lines.push(String::new());
        lines.push("No findings.".into());
    }
    for finding in &answer.findings {
        lines.push(String::new());
        finding_block(&mut lines, finding, zone);
    }

    if !answer.limits.is_empty() {
        lines.push(String::new());
        lines.push("Limits:".into());
        lines.extend(answer.limits.iter().map(limit_line));
    }

    lines.push(String::new());
    lines.join("\n")
}

fn finding_block(lines: &mut Vec<String>, finding: &Finding, zone: &TimeZone) {
    lines.push(clean(finding.headline()));
    for line in finding.explanation().lines() {
        lines.push(format!("  {}", clean(line)));
    }
    lines.push(format!("  Confidence: {}", finding.confidence()));
    if let Some(at) = finding.time() {
        lines.push(format!("  When: {}", time(at, zone)));
    }

    if !finding.evidence().is_empty() {
        lines.push("  Evidence:".into());
        for evidence in finding.evidence() {
            let record_id = evidence
                .record_id
                .as_deref()
                .map_or_else(|| "-".into(), clean);
            let at = evidence
                .timestamp
                .map_or_else(|| "-".into(), |at| time(at, zone));
            lines.push(format!("    {} {} {}", evidence.source, record_id, at));
        }
    }
    if let Some(gap) = finding.gap() {
        lines.push(format!("  Not recorded: {}", clean(&gap.what)));
        lines.push(format!(
            "  What would capture it: {}",
            clean(&gap.would_capture)
        ));
    }
    if let Some(fix) = finding.fix() {
        let admin = if fix.needs_admin {
            " (needs admin)"
        } else {
            ""
        };
        lines.push(format!("  Fix{admin}: {}", clean(&fix.command)));
        lines.push(format!("    {}", clean(&fix.explanation)));
    }
}

fn limit_line(limit: &Limit) -> String {
    let adds = limit.adds.as_deref().map_or_else(String::new, |adds| {
        format!(" Elevation adds {}.", clean(adds))
    });
    format!(
        "  {}: {}.{adds}",
        limit.source,
        clean(&limit.access.to_string())
    )
}

fn time(at: Timestamp, zone: &TimeZone) -> String {
    at.to_zoned(zone.clone())
        .strftime("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::{Access, Evidence, Fix, NotRecorded, Question, SourceId, Sourced};

    use super::*;

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn zone() -> TimeZone {
        TimeZone::fixed(jiff::tz::offset(2))
    }

    fn sample() -> Answer {
        let wake = Finding::recorded(
            "wake.power_button",
            Question::Wake,
            "Woke because the power button was pressed",
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
        ];
        Answer::new(
            Question::Wake,
            ts("2026-11-03T12:00:00Z"),
            vec![wake, nothing],
            limits,
        )
    }

    #[test]
    fn human_output_has_the_triple_confidence_and_limits() {
        let text = human(&sample(), &zone());
        assert!(text.starts_with("pcsleuth wake (generated 2026-11-03 14:00:00 +02:00)\n"));
        assert!(text.contains("Woke because the power button was pressed\n  Windows recorded it.\n  Nothing else was needed.\n  Confidence: recorded\n"));
        assert!(text.contains("\n    event_log_system 360285 2026-10-28 16:30:33 +02:00\n"));
        assert!(text.contains("\n    event_log_system - -\n"));
        assert!(text.contains("  Confidence: not recorded\n"));
        assert!(
            text.contains("  Not recorded: past blockers\n  What would capture it: the recorder\n")
        );
        assert!(text.contains("  Fix (needs admin): powercfg /requests\n"));
        assert!(text.contains("\nLimits:\n  wake_timers: needs admin. Elevation adds live wake timers.\n  recorder: missing.\n"));
        assert!(text.is_ascii());
    }

    #[test]
    fn no_findings_is_still_an_answer() {
        let answer = Answer::new(Question::Now, ts("2026-11-03T12:00:00Z"), vec![], vec![]);
        assert!(human(&answer, &zone()).contains("No findings."));
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
        let text = human(&answer, &zone());
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\r'));
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
