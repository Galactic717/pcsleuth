//! The questions pcsleuth answers, and the answer format.

use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::finding::Finding;
use crate::source::Limit;

/// Version of the JSON shape of [`Answer`]. Bump it when the shape changes; the golden test
/// fails first.
pub const SCHEMA_VERSION: u32 = 1;

/// The questions, named as the command line names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Question {
    Wake,
    NoSleep,
    Battery,
    Crash,
    Slow,
    Now,
    Timeline,
    Doctor,
}

impl Question {
    pub const fn as_str(self) -> &'static str {
        match self {
            Question::Wake => "wake",
            Question::NoSleep => "nosleep",
            Question::Battery => "battery",
            Question::Crash => "crash",
            Question::Slow => "slow",
            Question::Now => "now",
            Question::Timeline => "timeline",
            Question::Doctor => "doctor",
        }
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What every command returns, and what `--json` prints.
///
/// Timestamps are RFC 3339 in UTC. An "unknown" answer is still an answer: it holds findings with
/// [`Confidence::NotRecorded`](crate::Confidence::NotRecorded) and the [`Limit`]s that explain it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer {
    pub schema_version: u32,
    pub question: Question,
    pub generated_at: Timestamp,
    pub findings: Vec<Finding>,
    /// Sources that could not be fully read, and what elevation would add.
    pub limits: Vec<Limit>,
}

impl Answer {
    pub fn new(
        question: Question,
        generated_at: Timestamp,
        findings: Vec<Finding>,
        limits: Vec<Limit>,
    ) -> Self {
        Answer {
            schema_version: SCHEMA_VERSION,
            question,
            generated_at,
            findings,
            limits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn question_names_match_json_and_the_command_line() {
        for (question, name) in [
            (Question::Wake, "wake"),
            (Question::NoSleep, "nosleep"),
            (Question::Battery, "battery"),
            (Question::Crash, "crash"),
            (Question::Slow, "slow"),
            (Question::Now, "now"),
            (Question::Timeline, "timeline"),
            (Question::Doctor, "doctor"),
        ] {
            assert_eq!(question.as_str(), name);
            assert_eq!(
                serde_json::to_string(&question).unwrap(),
                format!("\"{name}\"")
            );
        }
    }
}
