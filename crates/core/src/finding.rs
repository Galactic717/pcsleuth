//! Evidence, confidence and findings.
//!
//! A [`Finding`] cannot be built, or deserialized, without the evidence its confidence promises.

use std::collections::BTreeMap;
use std::fmt;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::answer::Question;
use crate::source::SourceId;

/// One record a finding rests on: where it came from, which record, when, and its fields.
///
/// Fields are read by name from structured data. Localized text is carried as opaque values for
/// display and never branched on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: SourceId,
    /// The source's own id for the record, such as an event record id.
    pub record_id: Option<String>,
    pub timestamp: Option<Timestamp>,
    pub fields: BTreeMap<String, String>,
}

impl Evidence {
    pub fn new(source: SourceId) -> Self {
        Evidence {
            source,
            record_id: None,
            timestamp: None,
            fields: BTreeMap::new(),
        }
    }

    pub fn with_record_id(mut self, record_id: impl Into<String>) -> Self {
        self.record_id = Some(record_id.into());
        self
    }

    pub fn at(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(name.into(), value.into());
        self
    }
}

/// How the answer is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Windows states it directly in a record.
    Recorded,
    /// Inferred from evidence that sits near it in time.
    Correlated,
    /// The recorder saw it at a sampling interval, so it may have missed shorter events.
    Sampled,
    /// Windows did not record it. See [`NotRecorded`].
    NotRecorded,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Recorded => "recorded",
            Confidence::Correlated => "correlated",
            Confidence::Sampled => "sampled",
            Confidence::NotRecorded => "not recorded",
        })
    }
}

/// What Windows did not record, and what would capture it next time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotRecorded {
    pub what: String,
    pub would_capture: String,
}

impl NotRecorded {
    pub fn new(what: impl Into<String>, would_capture: impl Into<String>) -> Self {
        NotRecorded {
            what: what.into(),
            would_capture: would_capture.into(),
        }
    }
}

/// A command the user may run to fix the problem.
///
/// There is deliberately no way to apply it: v0.1.0 prints the command and never changes a setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fix {
    pub command: String,
    pub explanation: String,
    pub needs_admin: bool,
}

impl Fix {
    pub fn new(
        command: impl Into<String>,
        explanation: impl Into<String>,
        needs_admin: bool,
    ) -> Self {
        Fix {
            command: command.into(),
            explanation: explanation.into(),
            needs_admin,
        }
    }
}

/// Why a [`Finding`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingError {
    #[error("finding {0} is blank")]
    Blank(&'static str),
    #[error("a {0} finding needs at least one piece of evidence")]
    NoEvidence(Confidence),
    #[error("a not recorded finding must say what was not recorded and what would capture it")]
    MissingNotRecorded,
}

/// One answer to "why did my PC do that", with the evidence behind it.
///
/// Fields are private so the invariants hold: a recorded, correlated or sampled finding has at
/// least one [`Evidence`], and a not recorded finding names what would capture the missing data.
/// Build one with [`Finding::recorded`], [`Finding::correlated`], [`Finding::sampled`] or
/// [`Finding::not_recorded`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FindingWire")]
pub struct Finding {
    id: String,
    question: Question,
    time: Option<Timestamp>,
    headline: String,
    explanation: String,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    not_recorded: Option<NotRecorded>,
    fix: Option<Fix>,
}

/// Unchecked mirror of [`Finding`] that deserialization goes through.
#[derive(Deserialize)]
struct FindingWire {
    id: String,
    question: Question,
    time: Option<Timestamp>,
    headline: String,
    explanation: String,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    not_recorded: Option<NotRecorded>,
    fix: Option<Fix>,
}

impl TryFrom<FindingWire> for Finding {
    type Error = FindingError;

    fn try_from(wire: FindingWire) -> Result<Self, FindingError> {
        let finding = Finding {
            id: wire.id,
            question: wire.question,
            time: wire.time,
            headline: wire.headline,
            explanation: wire.explanation,
            confidence: wire.confidence,
            evidence: wire.evidence,
            not_recorded: wire.not_recorded,
            fix: wire.fix,
        };
        finding.validate()?;
        Ok(finding)
    }
}

impl Finding {
    /// Windows states the answer directly in `evidence`.
    pub fn recorded(
        id: impl Into<String>,
        question: Question,
        headline: impl Into<String>,
        explanation: impl Into<String>,
        evidence: impl IntoIterator<Item = Evidence>,
    ) -> Result<Self, FindingError> {
        Self::evidenced(
            Confidence::Recorded,
            id,
            question,
            headline,
            explanation,
            evidence,
        )
    }

    /// The answer is inferred from `evidence` that sits near it in time.
    pub fn correlated(
        id: impl Into<String>,
        question: Question,
        headline: impl Into<String>,
        explanation: impl Into<String>,
        evidence: impl IntoIterator<Item = Evidence>,
    ) -> Result<Self, FindingError> {
        Self::evidenced(
            Confidence::Correlated,
            id,
            question,
            headline,
            explanation,
            evidence,
        )
    }

    /// The recorder saw the answer at an interval.
    pub fn sampled(
        id: impl Into<String>,
        question: Question,
        headline: impl Into<String>,
        explanation: impl Into<String>,
        evidence: impl IntoIterator<Item = Evidence>,
    ) -> Result<Self, FindingError> {
        Self::evidenced(
            Confidence::Sampled,
            id,
            question,
            headline,
            explanation,
            evidence,
        )
    }

    /// Windows did not record the answer. `gap` says what is missing and what would capture it.
    pub fn not_recorded(
        id: impl Into<String>,
        question: Question,
        headline: impl Into<String>,
        explanation: impl Into<String>,
        gap: NotRecorded,
    ) -> Result<Self, FindingError> {
        Self::build(
            Confidence::NotRecorded,
            id.into(),
            question,
            headline.into(),
            explanation.into(),
            Vec::new(),
            Some(gap),
        )
    }

    fn evidenced(
        confidence: Confidence,
        id: impl Into<String>,
        question: Question,
        headline: impl Into<String>,
        explanation: impl Into<String>,
        evidence: impl IntoIterator<Item = Evidence>,
    ) -> Result<Self, FindingError> {
        Self::build(
            confidence,
            id.into(),
            question,
            headline.into(),
            explanation.into(),
            evidence.into_iter().collect(),
            None,
        )
    }

    fn build(
        confidence: Confidence,
        id: String,
        question: Question,
        headline: String,
        explanation: String,
        evidence: Vec<Evidence>,
        not_recorded: Option<NotRecorded>,
    ) -> Result<Self, FindingError> {
        let finding = Finding {
            id,
            question,
            time: None,
            headline,
            explanation,
            confidence,
            evidence,
            not_recorded,
            fix: None,
        };
        finding.validate()?;
        Ok(finding)
    }

    fn validate(&self) -> Result<(), FindingError> {
        if is_blank(&self.id) {
            return Err(FindingError::Blank("id"));
        }
        if is_blank(&self.headline) {
            return Err(FindingError::Blank("headline"));
        }
        match self.confidence {
            Confidence::Recorded | Confidence::Correlated | Confidence::Sampled => {
                if self.evidence.is_empty() {
                    return Err(FindingError::NoEvidence(self.confidence));
                }
            }
            Confidence::NotRecorded => {
                if self.not_recorded.is_none() {
                    return Err(FindingError::MissingNotRecorded);
                }
            }
        }
        if let Some(gap) = &self.not_recorded {
            if is_blank(&gap.what) {
                return Err(FindingError::Blank("not_recorded.what"));
            }
            if is_blank(&gap.would_capture) {
                return Err(FindingError::Blank("not_recorded.would_capture"));
            }
        }
        Ok(())
    }

    /// When the thing happened. Findings without a time sort last in a timeline.
    pub fn at(mut self, time: Timestamp) -> Self {
        self.time = Some(time);
        self
    }

    /// Attach a command the user may run. It is only ever printed.
    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }

    /// Note what Windows did not record about an otherwise evidenced finding, for example a
    /// hibernate resume whose wake source the firmware does not report.
    pub fn with_gap(mut self, gap: NotRecorded) -> Result<Self, FindingError> {
        self.not_recorded = Some(gap);
        self.validate()?;
        Ok(self)
    }

    /// Cite more records. This is how a `not recorded` finding keeps the record that shows the
    /// gap, such as a wake whose log entry lists no source: the confidence stays `NotRecorded` and
    /// the gap note stays required. Evidence added here never names a cause for a scorer, because
    /// a not recorded finding is not confident.
    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Stable id such as `wake.power_button`. Tests and the app key on it.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn question(&self) -> Question {
        self.question
    }

    pub fn time(&self) -> Option<Timestamp> {
        self.time
    }

    pub fn headline(&self) -> &str {
        &self.headline
    }

    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    pub fn confidence(&self) -> Confidence {
        self.confidence
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    pub fn gap(&self) -> Option<&NotRecorded> {
        self.not_recorded.as_ref()
    }

    pub fn fix(&self) -> Option<&Fix> {
        self.fix.as_ref()
    }
}

fn is_blank(text: &str) -> bool {
    text.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Evidence {
        Evidence::new(SourceId::EventLogSystem).with_record_id("1")
    }

    fn gap() -> NotRecorded {
        NotRecorded::new(
            "the wake source",
            "the recorder, or a firmware that reports it",
        )
    }

    #[test]
    fn evidenced_findings_need_evidence() {
        let none = || Vec::<Evidence>::new();
        for without in [
            Finding::recorded("a", Question::Wake, "h", "x", none()),
            Finding::correlated("a", Question::Wake, "h", "x", none()),
            Finding::sampled("a", Question::Wake, "h", "x", none()),
        ] {
            assert!(matches!(without, Err(FindingError::NoEvidence(_))));
        }
        for with in [
            Finding::recorded("a", Question::Wake, "h", "x", [evidence()]),
            Finding::correlated("a", Question::Wake, "h", "x", [evidence()]),
            Finding::sampled("a", Question::Wake, "h", "x", [evidence()]),
        ] {
            assert!(with.is_ok());
        }
    }

    #[test]
    fn no_evidence_error_names_the_confidence() {
        let err = Finding::sampled("a", Question::Slow, "h", "x", []).unwrap_err();
        assert_eq!(err, FindingError::NoEvidence(Confidence::Sampled));
        assert_eq!(
            err.to_string(),
            "a sampled finding needs at least one piece of evidence"
        );
    }

    #[test]
    fn not_recorded_must_say_what_would_capture_it() {
        let ok = Finding::not_recorded("n", Question::NoSleep, "h", "x", gap()).unwrap();
        assert_eq!(ok.confidence(), Confidence::NotRecorded);
        assert!(ok.evidence().is_empty());

        let no_capture = NotRecorded::new("the blocker", "  ");
        assert_eq!(
            Finding::not_recorded("n", Question::NoSleep, "h", "x", no_capture),
            Err(FindingError::Blank("not_recorded.would_capture"))
        );
        let no_what = NotRecorded::new("", "the recorder");
        assert_eq!(
            Finding::not_recorded("n", Question::NoSleep, "h", "x", no_what),
            Err(FindingError::Blank("not_recorded.what"))
        );
    }

    #[test]
    fn id_and_headline_cannot_be_blank() {
        assert_eq!(
            Finding::recorded(" ", Question::Wake, "h", "x", [evidence()]),
            Err(FindingError::Blank("id"))
        );
        assert_eq!(
            Finding::recorded("a", Question::Wake, "", "x", [evidence()]),
            Err(FindingError::Blank("headline"))
        );
    }

    #[test]
    fn evidenced_finding_may_carry_a_gap_but_not_a_blank_one() {
        let finding = Finding::recorded("a", Question::Wake, "h", "x", [evidence()]).unwrap();
        let with_gap = finding.clone().with_gap(gap()).unwrap();
        assert_eq!(with_gap.confidence(), Confidence::Recorded);
        assert_eq!(with_gap.gap(), Some(&gap()));
        assert_eq!(
            finding.with_gap(NotRecorded::new("x", "")),
            Err(FindingError::Blank("not_recorded.would_capture"))
        );
    }

    #[test]
    fn a_not_recorded_finding_can_cite_the_record_that_shows_the_gap() {
        let plain = Finding::not_recorded("n", Question::Wake, "h", "x", gap()).unwrap();
        assert!(plain.evidence().is_empty());

        let cited = plain.with_evidence([evidence()]);
        // Still not recorded, still carrying its gap note, now with the record.
        assert_eq!(cited.confidence(), Confidence::NotRecorded);
        assert_eq!(cited.gap(), Some(&gap()));
        assert_eq!(cited.evidence(), [evidence()]);

        // It survives the JSON round trip, and the checks on the wire form still pass.
        let json = serde_json::to_value(&cited).unwrap();
        assert_eq!(serde_json::from_value::<Finding>(json).unwrap(), cited);
    }

    #[test]
    fn citing_more_records_never_removes_what_a_confidence_requires() {
        let recorded = Finding::recorded("a", Question::Wake, "h", "x", [evidence()])
            .unwrap()
            .with_evidence([evidence().with_record_id("2")]);
        assert_eq!(recorded.evidence().len(), 2);
        assert_eq!(recorded.confidence(), Confidence::Recorded);
        // Dropping the gap note from a not recorded finding on the wire is still refused.
        let mut json = serde_json::to_value(
            Finding::not_recorded("n", Question::Wake, "h", "x", gap())
                .unwrap()
                .with_evidence([evidence()]),
        )
        .unwrap();
        json["not_recorded"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<Finding>(json).is_err());
    }

    #[test]
    fn deserializing_cannot_bypass_the_invariants() {
        let finding = Finding::recorded("a", Question::Wake, "h", "x", [evidence()]).unwrap();
        let mut json = serde_json::to_value(&finding).unwrap();
        assert_eq!(
            serde_json::from_value::<Finding>(json.clone()).unwrap(),
            finding
        );

        json["evidence"] = serde_json::json!([]);
        let err = serde_json::from_value::<Finding>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("needs at least one piece of evidence")
        );
    }

    #[test]
    fn builders_set_time_and_fix() {
        let time: Timestamp = "2026-10-28T14:30:33Z".parse().unwrap();
        let finding = Finding::recorded("a", Question::Wake, "h", "x", [evidence()])
            .unwrap()
            .at(time)
            .with_fix(Fix::new(
                "powercfg /devicequery wake_armed",
                "lists armed devices",
                false,
            ));
        assert_eq!(finding.time(), Some(time));
        assert_eq!(finding.fix().map(|f| f.needs_admin), Some(false));
    }
}
