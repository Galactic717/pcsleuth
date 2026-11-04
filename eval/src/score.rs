//! The scorer: a pure function from (expected cause, observability, answer) to an outcome.
//!
//! No clock, no OS, no I/O. The attribution contract the engine follows: a finding names a cause
//! by putting the exe name in `Evidence.fields["process"]` or a device name in
//! `Evidence.fields["device"]`. Prose is never read.

use std::collections::BTreeSet;

use pcsleuth_core::{Answer, Confidence, Evidence, SourceId, Timestamp};
use serde::Serialize;

/// Evidence field that carries the exe name of a process.
pub const PROCESS_FIELD: &str = "process";
/// Evidence field that carries the name of a device.
pub const DEVICE_FIELD: &str = "device";

/// What a finding blames. Names are normalized on construction, so `C:\Apps\Chrome.EXE`,
/// `chrome.exe` and `chrome` are one cause.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum Cause {
    Process(String),
    Device(String),
}

impl Cause {
    pub fn process(name: &str) -> Cause {
        let base = name.rsplit(['\\', '/']).next().unwrap_or(name).trim();
        let lower = base.to_lowercase();
        Cause::Process(lower.strip_suffix(".exe").unwrap_or(&lower).to_owned())
    }

    pub fn device(name: &str) -> Cause {
        Cause::Device(name.trim().to_lowercase())
    }

    pub fn name(&self) -> &str {
        match self {
            Cause::Process(name) | Cause::Device(name) => name,
        }
    }
}

/// What the scenario knows to be true.
#[derive(Debug, Clone)]
pub struct Expect {
    pub cause: Cause,
    /// Record ids of the events the injection produced, when it produced any. If non-empty, a
    /// finding only counts when its evidence cites one of them.
    pub record_ids: Vec<String>,
    /// When the injection started. Without record ids, evidence older than this does not count.
    pub since: Option<Timestamp>,
}

/// Whether Windows recorded the cause in a place the tool can read under the current privileges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observable {
    Yes,
    /// Not recorded. The honest answer is not-recorded, or a named limit: an answer that lists
    /// `limit` among its limits also counts.
    No {
        reason: String,
        limit: Option<SourceId>,
    },
    /// Not known until run on real hardware. Scored if the tool names a cause, otherwise neutral.
    Unverified(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The right cause, tied to the right record.
    TruePositive,
    /// Not observable, and the answer says so.
    Honest,
    /// Observable, and the answer did not name it.
    Miss,
    /// Not observable, and the answer neither named a cause nor admitted a gap.
    Silent,
    /// A confident finding names the wrong cause, or the right one on the wrong record.
    FalseAttribution,
    /// Could not be judged: observability is not known and nothing was named.
    Unverified,
}

impl Outcome {
    /// The name used in the results file and the table.
    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::TruePositive => "true_positive",
            Outcome::Honest => "honest",
            Outcome::Miss => "miss",
            Outcome::Silent => "silent",
            Outcome::FalseAttribution => "false_attribution",
            Outcome::Unverified => "unverified",
        }
    }

    /// A confident wrong answer must rank below an unknown one, so it is the only negative.
    pub const fn points(self) -> i32 {
        match self {
            Outcome::TruePositive | Outcome::Honest => 1,
            Outcome::Miss | Outcome::Silent | Outcome::Unverified => 0,
            Outcome::FalseAttribution => -1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scored {
    pub outcome: Outcome,
    pub detail: String,
    /// Every other cause a confident finding named, for the table and the JSON.
    pub named: Vec<String>,
    /// How many confident attributions were not the expected one. Reported, not scored.
    pub extras: usize,
    /// True when every finding is a `*.not_implemented` placeholder, so any "honest" outcome is
    /// by accident: the engine said nothing real.
    pub placeholder: bool,
}

/// Judge one answer. `None` means the tool produced no usable answer (it failed or printed
/// something that is not an `Answer`); that scores like an empty answer, never better.
///
/// Rules, in order:
/// 1. Only confident findings (anything but `NotRecorded`) can name a cause.
/// 2. The expected cause counts only when its evidence is tied to the injection: it cites one of
///    `record_ids` when those are known, else it is not older than `since`. A record from an
///    earlier run of the same exe is a wrong answer, not a lucky one.
/// 3. Any confident naming of a different cause, or of the right one on the wrong record, with
///    no valid match anywhere in the answer, is a false attribution.
/// 4. With nothing named, the result depends on whether the cause was observable.
pub fn score(expect: &Expect, observable: &Observable, answer: Option<&Answer>) -> Scored {
    let Some(answer) = answer else {
        return unnamed(
            observable,
            None,
            false,
            "the tool produced no usable answer",
        );
    };
    let placeholder = !answer.findings.is_empty()
        && answer
            .findings
            .iter()
            .all(|f| f.id().ends_with(".not_implemented"));

    let mut matched = false;
    let mut unanchored = Vec::new();
    let mut other = BTreeSet::new();
    for finding in &answer.findings {
        if finding.confidence() == Confidence::NotRecorded {
            continue;
        }
        for evidence in finding.evidence() {
            for cause in causes(evidence) {
                if cause != expect.cause {
                    other.insert(cause);
                } else if anchored(evidence, expect) {
                    matched = true;
                } else {
                    unanchored.push(describe(evidence));
                }
            }
        }
    }

    let named: Vec<String> = other.iter().map(|c| c.name().to_owned()).collect();
    let extras = named.len() + unanchored.len();
    let expected = expect.cause.name();
    let (outcome, detail) = if matched {
        (Outcome::TruePositive, format!("named {expected}"))
    } else if !unanchored.is_empty() || !named.is_empty() {
        let mut parts = Vec::new();
        if !unanchored.is_empty() {
            parts.push(format!(
                "named {expected} on {}, not the injected {}",
                unanchored.join(", "),
                injected(expect)
            ));
        }
        if !named.is_empty() {
            parts.push(format!("named {} instead of {expected}", named.join(", ")));
        }
        (Outcome::FalseAttribution, parts.join("; "))
    } else {
        return unnamed(observable, Some(answer), placeholder, "no cause named");
    };
    Scored {
        outcome,
        detail,
        named,
        extras,
        placeholder,
    }
}

/// The answer named no cause at all.
fn unnamed(
    observable: &Observable,
    answer: Option<&Answer>,
    placeholder: bool,
    why: &str,
) -> Scored {
    let (outcome, detail) = match observable {
        Observable::Yes => (Outcome::Miss, format!("observable, but {why}")),
        Observable::No { limit, .. } => match answer {
            Some(answer) if admits_gap(answer, *limit) => (
                Outcome::Honest,
                "not observable, and the answer says so".to_owned(),
            ),
            _ => (
                Outcome::Silent,
                format!("not observable, but the answer did not admit a gap ({why})"),
            ),
        },
        Observable::Unverified(_) => (Outcome::Unverified, format!("not judged: {why}")),
    };
    Scored {
        outcome,
        detail,
        named: Vec::new(),
        extras: 0,
        placeholder,
    }
}

/// A finding admits a gap when it is a `NotRecorded` finding, carries a gap note, or the answer
/// lists the limit that explains the scenario.
fn admits_gap(answer: &Answer, limit: Option<SourceId>) -> bool {
    answer
        .findings
        .iter()
        .any(|f| f.confidence() == Confidence::NotRecorded || f.gap().is_some())
        || limit.is_some_and(|source| answer.limits.iter().any(|l| l.source == source))
}

fn causes(evidence: &Evidence) -> impl Iterator<Item = Cause> + '_ {
    let field = |name: &str| {
        evidence
            .fields
            .get(name)
            .map(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
    };
    field(PROCESS_FIELD)
        .map(Cause::process)
        .into_iter()
        .chain(field(DEVICE_FIELD).map(Cause::device))
}

/// Is this evidence tied to the injection rather than to some older record?
fn anchored(evidence: &Evidence, expect: &Expect) -> bool {
    if !expect.record_ids.is_empty() {
        return evidence
            .record_id
            .as_ref()
            .is_some_and(|id| expect.record_ids.contains(id));
    }
    match (evidence.timestamp, expect.since) {
        (Some(time), Some(since)) => time >= since,
        _ => true,
    }
}

fn describe(evidence: &Evidence) -> String {
    match (&evidence.record_id, evidence.timestamp) {
        (Some(id), _) => format!("record {id}"),
        (None, Some(time)) => format!("a record from {time}"),
        (None, None) => "an unanchored record".to_owned(),
    }
}

fn injected(expect: &Expect) -> String {
    match (expect.record_ids.is_empty(), expect.since) {
        (false, _) => format!("record(s) {}", expect.record_ids.join(", ")),
        (true, Some(since)) => format!("events after {since}"),
        (true, None) => "events".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::{Access, Finding, Limit, NotRecorded, Question};

    use super::*;

    fn ev(source: SourceId, field: &str, value: &str) -> Evidence {
        Evidence::new(source).with_field(field, value)
    }

    fn crash_ev(process: &str, record: &str) -> Evidence {
        ev(SourceId::EventLogApplication, PROCESS_FIELD, process).with_record_id(record)
    }

    fn recorded(id: &str, evidence: Vec<Evidence>) -> Finding {
        Finding::recorded(id, Question::Crash, "h", "x", evidence).unwrap()
    }

    fn unknown(id: &str) -> Finding {
        let gap = NotRecorded::new("the cause", "the recorder");
        Finding::not_recorded(id, Question::Crash, "h", "x", gap).unwrap()
    }

    fn answer(findings: Vec<Finding>, limits: Vec<Limit>) -> Answer {
        Answer::new(Question::Crash, Timestamp::UNIX_EPOCH, findings, limits)
    }

    fn expect(record_ids: &[&str]) -> Expect {
        Expect {
            cause: Cause::process("pcsleuth-fault-crash.exe"),
            record_ids: record_ids.iter().map(|id| id.to_string()).collect(),
            since: None,
        }
    }

    fn outcome(expect: &Expect, observable: &Observable, answer: &Answer) -> Outcome {
        score(expect, observable, Some(answer)).outcome
    }

    fn not_observable() -> Observable {
        Observable::No {
            reason: "not logged".into(),
            limit: None,
        }
    }

    #[test]
    fn right_process_on_the_right_record_is_a_true_positive() {
        let a = answer(
            vec![recorded(
                "crash.app_error",
                vec![crash_ev("pcsleuth-fault-crash.exe", "42")],
            )],
            vec![],
        );
        let scored = score(&expect(&["42"]), &Observable::Yes, Some(&a));
        assert_eq!(scored.outcome, Outcome::TruePositive);
        assert_eq!(scored.extras, 0);
    }

    #[test]
    fn names_are_compared_without_case_directory_or_exe_suffix() {
        for spelled in [
            "PCSLEUTH-FAULT-CRASH.EXE",
            "pcsleuth-fault-crash",
            r"C:\Users\someone\target\debug\pcsleuth-fault-crash.exe",
            "/tmp/pcsleuth-fault-crash.exe",
            "  pcsleuth-fault-crash.exe ",
        ] {
            let a = answer(vec![recorded("r", vec![crash_ev(spelled, "1")])], vec![]);
            assert_eq!(
                outcome(&expect(&["1"]), &Observable::Yes, &a),
                Outcome::TruePositive,
                "{spelled}"
            );
        }
    }

    #[test]
    fn a_confident_wrong_process_is_a_false_attribution() {
        let a = answer(
            vec![recorded("r", vec![crash_ev("chrome.exe", "42")])],
            vec![],
        );
        let scored = score(&expect(&["42"]), &Observable::Yes, Some(&a));
        assert_eq!(scored.outcome, Outcome::FalseAttribution);
        assert_eq!(scored.named, vec!["chrome".to_string()]);
    }

    #[test]
    fn a_confident_wrong_answer_ranks_below_unknown_in_every_case() {
        let wrong = answer(
            vec![recorded("r", vec![crash_ev("chrome.exe", "42")])],
            vec![],
        );
        let unknown_answer = answer(vec![unknown("n")], vec![]);
        for observable in [Observable::Yes, not_observable()] {
            let wrong = outcome(&expect(&["42"]), &observable, &wrong);
            let unknown = outcome(&expect(&["42"]), &observable, &unknown_answer);
            assert!(
                wrong.points() < unknown.points(),
                "{observable:?}: {wrong:?} should rank below {unknown:?}"
            );
        }
        assert!(Outcome::FalseAttribution.points() < Outcome::Miss.points());
        assert!(Outcome::FalseAttribution.points() < Outcome::Honest.points());
        assert!(Outcome::FalseAttribution.points() < Outcome::Silent.points());
    }

    #[test]
    fn the_right_process_on_an_older_record_never_matches() {
        // The same exe crashed in an earlier run. Naming it is not naming this crash.
        let stale = answer(
            vec![recorded(
                "r",
                vec![crash_ev("pcsleuth-fault-crash.exe", "7")],
            )],
            vec![],
        );
        let scored = score(&expect(&["42"]), &Observable::Yes, Some(&stale));
        assert_eq!(scored.outcome, Outcome::FalseAttribution);
        assert!(scored.detail.contains("7"), "{}", scored.detail);
    }

    #[test]
    fn the_right_process_without_a_record_id_does_not_match_when_ids_are_known() {
        let a = answer(
            vec![recorded(
                "r",
                vec![ev(
                    SourceId::EventLogApplication,
                    PROCESS_FIELD,
                    "pcsleuth-fault-crash.exe",
                )],
            )],
            vec![],
        );
        assert_eq!(
            outcome(&expect(&["42"]), &Observable::Yes, &a),
            Outcome::FalseAttribution
        );
    }

    #[test]
    fn the_new_record_wins_over_a_stale_one_in_the_same_answer() {
        let a = answer(
            vec![
                recorded("old", vec![crash_ev("pcsleuth-fault-crash.exe", "7")]),
                recorded("new", vec![crash_ev("pcsleuth-fault-crash.exe", "42")]),
            ],
            vec![],
        );
        let scored = score(&expect(&["42"]), &Observable::Yes, Some(&a));
        assert_eq!(scored.outcome, Outcome::TruePositive);
        assert_eq!(scored.extras, 1);
    }

    #[test]
    fn without_record_ids_evidence_older_than_the_injection_never_matches() {
        let started: Timestamp = "2026-11-03T12:00:00Z".parse().unwrap();
        let expect = Expect {
            cause: Cause::process("pcsleuth-fault-cpu"),
            record_ids: vec![],
            since: Some(started),
        };
        let at = |time: &str| {
            let evidence = ev(SourceId::Processes, PROCESS_FIELD, "pcsleuth-fault-cpu.exe")
                .at(time.parse().unwrap());
            answer(vec![recorded("r", vec![evidence])], vec![])
        };
        assert_eq!(
            outcome(&expect, &Observable::Yes, &at("2026-11-03T11:59:59Z")),
            Outcome::FalseAttribution
        );
        assert_eq!(
            outcome(&expect, &Observable::Yes, &at("2026-11-03T12:00:01Z")),
            Outcome::TruePositive
        );
    }

    #[test]
    fn correlated_and_sampled_findings_count_as_confident() {
        for build in [Finding::correlated, Finding::sampled] {
            let finding =
                build("r", Question::Slow, "h", "x", [crash_ev("chrome.exe", "1")]).unwrap();
            let a = answer(vec![finding], vec![]);
            assert_eq!(
                outcome(&expect(&[]), &Observable::Yes, &a),
                Outcome::FalseAttribution
            );
        }
    }

    #[test]
    fn devices_are_matched_by_name() {
        let expect = Expect {
            cause: Cause::device("Realtek PCIe GbE Family Controller"),
            record_ids: vec![],
            since: None,
        };
        let right = answer(
            vec![recorded(
                "wake.device",
                vec![ev(
                    SourceId::EventLogSystem,
                    DEVICE_FIELD,
                    "realtek pcie gbe family controller",
                )],
            )],
            vec![],
        );
        let wrong = answer(
            vec![recorded(
                "wake.device",
                vec![ev(SourceId::EventLogSystem, DEVICE_FIELD, "Some Mouse")],
            )],
            vec![],
        );
        assert_eq!(
            outcome(&expect, &Observable::Yes, &right),
            Outcome::TruePositive
        );
        assert_eq!(
            outcome(&expect, &Observable::Yes, &wrong),
            Outcome::FalseAttribution
        );
        // A process with the same name is not the device.
        let process = answer(
            vec![recorded(
                "r",
                vec![crash_ev("Realtek PCIe GbE Family Controller", "1")],
            )],
            vec![],
        );
        assert_eq!(
            outcome(&expect, &Observable::Yes, &process),
            Outcome::FalseAttribution
        );
    }

    #[test]
    fn not_recorded_when_observable_is_a_miss() {
        let a = answer(vec![unknown("n")], vec![]);
        assert_eq!(
            outcome(&expect(&["42"]), &Observable::Yes, &a),
            Outcome::Miss
        );
        let empty = answer(vec![], vec![]);
        assert_eq!(
            outcome(&expect(&["42"]), &Observable::Yes, &empty),
            Outcome::Miss
        );
        assert_eq!(
            score(&expect(&["42"]), &Observable::Yes, None).outcome,
            Outcome::Miss
        );
    }

    #[test]
    fn a_confident_finding_that_names_nothing_is_a_miss_when_observable() {
        let a = answer(
            vec![recorded(
                "r",
                vec![Evidence::new(SourceId::EventLogSystem).with_record_id("1")],
            )],
            vec![],
        );
        assert_eq!(
            outcome(&expect(&["42"]), &Observable::Yes, &a),
            Outcome::Miss
        );
    }

    #[test]
    fn not_recorded_when_not_observable_is_honest() {
        let a = answer(vec![unknown("n")], vec![]);
        assert_eq!(
            outcome(&expect(&[]), &not_observable(), &a),
            Outcome::Honest
        );
    }

    #[test]
    fn silence_about_an_unobservable_cause_is_not_honest() {
        let empty = answer(vec![], vec![]);
        assert_eq!(
            outcome(&expect(&[]), &not_observable(), &empty),
            Outcome::Silent
        );
        assert_eq!(
            score(&expect(&[]), &not_observable(), None).outcome,
            Outcome::Silent
        );
        // Confident, but names nothing and admits no gap.
        let vague = answer(
            vec![recorded(
                "r",
                vec![Evidence::new(SourceId::Processes).with_record_id("1")],
            )],
            vec![],
        );
        assert_eq!(
            outcome(&expect(&[]), &not_observable(), &vague),
            Outcome::Silent
        );
    }

    #[test]
    fn a_confident_finding_that_admits_a_gap_is_honest() {
        let finding = recorded(
            "wake.hibernate",
            vec![Evidence::new(SourceId::EventLogSystem).with_record_id("1")],
        )
        .with_gap(NotRecorded::new("the wake source", "nothing; firmware"))
        .unwrap();
        let a = answer(vec![finding], vec![]);
        assert_eq!(
            outcome(&expect(&[]), &not_observable(), &a),
            Outcome::Honest
        );
    }

    #[test]
    fn naming_the_limit_is_honest_but_only_the_relevant_limit() {
        let observable = Observable::No {
            reason: "needs admin".into(),
            limit: Some(SourceId::PowerRequests),
        };
        let limit = |source| Limit::new(source, Access::NeedsAdmin).unwrap();
        let relevant = answer(vec![], vec![limit(SourceId::PowerRequests)]);
        let unrelated = answer(vec![], vec![limit(SourceId::Srum)]);
        assert_eq!(
            outcome(&expect(&[]), &observable, &relevant),
            Outcome::Honest
        );
        assert_eq!(
            outcome(&expect(&[]), &observable, &unrelated),
            Outcome::Silent
        );
    }

    #[test]
    fn naming_the_process_when_not_observable_is_still_judged_by_the_name() {
        let right = answer(
            vec![recorded(
                "r",
                vec![crash_ev("pcsleuth-fault-crash.exe", "1")],
            )],
            vec![],
        );
        let wrong = answer(
            vec![recorded("r", vec![crash_ev("chrome.exe", "1")])],
            vec![],
        );
        assert_eq!(
            outcome(&expect(&[]), &not_observable(), &right),
            Outcome::TruePositive
        );
        assert_eq!(
            outcome(&expect(&[]), &not_observable(), &wrong),
            Outcome::FalseAttribution
        );
    }

    #[test]
    fn unverified_is_neutral_unless_a_cause_is_named() {
        let unverified = Observable::Unverified("not known".into());
        let unknown_answer = answer(vec![unknown("n")], vec![]);
        assert_eq!(
            outcome(&expect(&[]), &unverified, &unknown_answer),
            Outcome::Unverified
        );
        let wrong = answer(
            vec![recorded("r", vec![crash_ev("chrome.exe", "1")])],
            vec![],
        );
        assert_eq!(
            outcome(&expect(&[]), &unverified, &wrong),
            Outcome::FalseAttribution
        );
    }

    #[test]
    fn outcome_names_match_the_json_names() {
        for outcome in [
            Outcome::TruePositive,
            Outcome::Honest,
            Outcome::Miss,
            Outcome::Silent,
            Outcome::FalseAttribution,
            Outcome::Unverified,
        ] {
            assert_eq!(
                serde_json::to_string(&outcome).unwrap(),
                format!("\"{}\"", outcome.as_str())
            );
        }
    }

    #[test]
    fn placeholder_answers_are_flagged() {
        let stub = answer(vec![unknown("crash.not_implemented")], vec![]);
        let scored = score(&expect(&[]), &not_observable(), Some(&stub));
        assert_eq!(scored.outcome, Outcome::Honest);
        assert!(scored.placeholder);

        let real = answer(vec![unknown("crash.nothing_recorded")], vec![]);
        assert!(!score(&expect(&[]), &not_observable(), Some(&real)).placeholder);
        assert!(!score(&expect(&[]), &not_observable(), None).placeholder);
        let empty = answer(vec![], vec![]);
        assert!(!score(&expect(&[]), &not_observable(), Some(&empty)).placeholder);
    }

    #[test]
    fn extras_count_other_causes_without_changing_a_true_positive() {
        let a = answer(
            vec![
                recorded("a", vec![crash_ev("pcsleuth-fault-crash.exe", "42")]),
                recorded("b", vec![crash_ev("chrome.exe", "43")]),
                recorded("c", vec![crash_ev("Teams.exe", "44")]),
            ],
            vec![],
        );
        let scored = score(&expect(&["42"]), &Observable::Yes, Some(&a));
        assert_eq!(scored.outcome, Outcome::TruePositive);
        assert_eq!(scored.extras, 2);
        assert_eq!(
            scored.named,
            vec!["chrome".to_string(), "teams".to_string()]
        );
    }

    #[test]
    fn blank_names_are_not_attributions() {
        let a = answer(
            vec![recorded(
                "r",
                vec![
                    ev(SourceId::Processes, PROCESS_FIELD, "  "),
                    ev(SourceId::Processes, DEVICE_FIELD, ""),
                ],
            )],
            vec![],
        );
        assert_eq!(outcome(&expect(&[]), &Observable::Yes, &a), Outcome::Miss);
    }

    #[test]
    fn a_not_recorded_finding_cannot_name_anything() {
        // Findings enforce it: not_recorded carries no evidence, so there is nothing to read.
        let finding = unknown("n");
        assert!(finding.evidence().is_empty());
        assert_eq!(finding.confidence(), Confidence::NotRecorded);
    }
}
