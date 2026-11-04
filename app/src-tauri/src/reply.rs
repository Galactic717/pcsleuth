//! What the page receives: the answer, made safe to show, plus the words and window it needs.
//!
//! Text in an answer comes from event logs and process names, which any local process can write.
//! The page inserts it with `textContent` only. This module is the second line: control characters
//! and text-direction marks are removed or replaced here, the same way the command line does, so
//! the page never has to decide.

use std::collections::BTreeMap;

use pcsleuth_core::{Answer, Question, SourceId};
use pcsleuth_engine::{Options, collapse_sids, doctor::label, resolve};
use serde::Serialize;
use serde_json::{Map, Value};

/// One answer for the page.
#[derive(Debug, Serialize)]
pub struct Reply {
    /// The [`Answer`] as JSON, with every string made safe to show. A fix command that cleaning
    /// would change is replaced by `null` and flagged `withheld`, so what is shown is never a
    /// different command from the one meant.
    pub answer: Value,
    /// Plain words for each source id used in the answer.
    pub labels: BTreeMap<&'static str, &'static str>,
    /// Where the window began, and how many dated findings were allowed. `None` for the questions
    /// that do not look back (`now`, `doctor`).
    pub window: Option<Window>,
    /// Said by the elevated run when it fell back to the unelevated answer. Safe to show.
    pub notice: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Window {
    pub since: String,
    pub limit: usize,
    pub since_is_default: bool,
    pub limit_is_default: bool,
}

impl Reply {
    pub fn new(answer: &Answer, options: &Options, notice: Option<&str>) -> Reply {
        let window = match answer.question {
            Question::Now | Question::Doctor => None,
            question => {
                let resolved = resolve(question, options, answer.generated_at);
                Some(Window {
                    since: resolved.window.since.to_string(),
                    limit: resolved.window.limit,
                    since_is_default: resolved.since_is_default,
                    limit_is_default: resolved.limit_is_default,
                })
            }
        };
        Reply {
            answer: safe_json(answer),
            labels: SourceId::ALL
                .iter()
                .map(|source| (source.as_str(), label(*source)))
                .collect(),
            window,
            notice: notice.map(clean).filter(|text| !text.trim().is_empty()),
        }
    }
}

/// Text-direction marks and overrides: they change how a line reads without being visible.
fn is_direction(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
        || ('\u{202a}'..='\u{202e}').contains(&c)
        || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// `text` safe to show: control characters become spaces, direction marks and overrides are
/// removed, and account SIDs are collapsed. Newlines become spaces too: the page lays text out
/// itself, and a log writer has no say in it.
pub fn clean(text: &str) -> String {
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

/// The answer as JSON with every string cleaned. See [`Reply::answer`].
pub fn safe_json(answer: &Answer) -> Value {
    // A struct of strings, numbers and vectors always converts.
    let mut value = serde_json::to_value(answer).unwrap_or(Value::Null);
    if let Some(findings) = value.get_mut("findings").and_then(Value::as_array_mut) {
        for finding in findings {
            let Some(fix) = finding.get_mut("fix").and_then(Value::as_object_mut) else {
                continue;
            };
            let changed = fix
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| clean(command) != command);
            if changed {
                fix.insert("command".to_owned(), Value::Null);
                fix.insert("withheld".to_owned(), Value::Bool(true));
            }
        }
    }
    clean_strings(&mut value);
    value
}

fn clean_strings(value: &mut Value) {
    match value {
        Value::String(text) => *text = clean(text),
        Value::Array(items) => items.iter_mut().for_each(clean_strings),
        Value::Object(map) => {
            let old = std::mem::take(map);
            *map = old
                .into_iter()
                .map(|(key, mut item)| {
                    clean_strings(&mut item);
                    (clean(&key), item)
                })
                .collect::<Map<String, Value>>();
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::{Evidence, Finding, Fix, NotRecorded, Timestamp};

    use super::*;

    fn finding_with_fix(command: &str) -> Finding {
        Finding::recorded(
            "wake.test",
            Question::Wake,
            "Woke up",
            "Windows recorded it.",
            [Evidence::new(SourceId::EventLogSystem).with_record_id("1")],
        )
        .unwrap()
        .with_fix(Fix::new(command, "Why.", false))
    }

    fn answer(findings: Vec<Finding>) -> Answer {
        Answer::new(Question::Wake, Timestamp::UNIX_EPOCH, findings, vec![])
    }

    #[test]
    fn controls_direction_marks_and_sids_do_not_reach_the_page() {
        assert_eq!(clean("a\u{202e}b\u{200f}c\u{7}d\ne"), "abc d e");
        assert_eq!(clean("task S-1-5-21-1-2-3-1001 ran"), "task <user> ran");
        assert_eq!(clean("plain <b>text</b>"), "plain <b>text</b>");
    }

    #[test]
    fn a_fix_command_that_cleaning_would_change_is_withheld_not_altered() {
        let tricky = answer(vec![finding_with_fix("powercfg /x\u{202e} /y")]);
        let value = safe_json(&tricky);
        let fix = &value["findings"][0]["fix"];
        assert_eq!(fix["command"], Value::Null);
        assert_eq!(fix["withheld"], Value::Bool(true));
    }

    #[test]
    fn a_plain_fix_command_is_passed_through_exactly() {
        let plain = answer(vec![finding_with_fix("powercfg /requests")]);
        let value = safe_json(&plain);
        assert_eq!(value["findings"][0]["fix"]["command"], "powercfg /requests");
        assert!(value["findings"][0]["fix"].get("withheld").is_none());
    }

    #[test]
    fn hostile_markup_is_left_as_text_for_the_page_to_insert_as_text() {
        let hostile = "<img src=x onerror=alert(1)>";
        let finding = Finding::not_recorded(
            "wake.test",
            Question::Wake,
            hostile,
            "x",
            NotRecorded::new("what", "how"),
        )
        .unwrap();
        let value = safe_json(&answer(vec![finding]));
        assert_eq!(value["findings"][0]["headline"], hostile);
    }

    #[test]
    fn the_reply_names_every_source_and_the_window_only_for_questions_that_look_back() {
        let wake = Reply::new(&answer(vec![]), &Options::default(), None);
        assert_eq!(wake.labels.len(), SourceId::ALL.len());
        assert!(wake.window.as_ref().is_some_and(|w| w.since_is_default));

        let doctor = Answer::new(Question::Doctor, Timestamp::UNIX_EPOCH, vec![], vec![]);
        assert!(
            Reply::new(&doctor, &Options::default(), None)
                .window
                .is_none()
        );
    }

    #[test]
    fn a_blank_notice_is_no_notice() {
        let blank = Reply::new(&answer(vec![]), &Options::default(), Some("  \n"));
        assert!(blank.notice.is_none());
    }
}
