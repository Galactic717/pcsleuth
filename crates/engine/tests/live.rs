//! Live smoke tests: they read this machine's real logs and settings, so they assert shapes, never
//! contents. They need no admin and change nothing; they pass with or without elevation.
#![cfg(windows)]

use pcsleuth_core::{Confidence, Question, SourceId};
use pcsleuth_engine::{Options, battery, crash, doctor, nosleep, now, slow, timeline, wake};

fn options() -> Options {
    Options::default()
}

#[test]
fn every_question_answers_and_each_finding_is_well_formed() {
    let answers = [
        (Question::Wake, wake(&options())),
        (Question::NoSleep, nosleep(&options())),
        (Question::Crash, crash(&options())),
        (Question::Slow, slow(&options())),
        (Question::Now, now(&options())),
        (Question::Timeline, timeline(&options())),
    ];
    for (question, answer) in answers {
        assert_eq!(answer.question, question);
        let dated: Vec<_> = answer.findings.iter().filter_map(|f| f.time()).collect();
        assert!(dated.windows(2).all(|w| w[0] <= w[1]), "{question}");
        for finding in &answer.findings {
            // Evidence-backed findings cite something; the others say what is missing.
            match finding.confidence() {
                Confidence::NotRecorded => assert!(finding.gap().is_some()),
                _ => assert!(!finding.evidence().is_empty()),
            }
            if question != Question::Timeline {
                assert!(
                    finding.id().starts_with(question.as_str()),
                    "{question}: {}",
                    finding.id()
                );
            }
        }
    }
}

#[test]
fn doctor_reports_each_source_once_and_never_applies_anything() {
    let answer = doctor(&options());
    assert_eq!(answer.findings.len(), SourceId::ALL.len());
    for (finding, source) in answer.findings.iter().zip(SourceId::ALL) {
        assert_eq!(finding.id(), format!("doctor.{source}"));
        // A fix is a printed command; nothing else in the contract can carry one out.
        if let Some(fix) = finding.fix() {
            assert!(!fix.command.is_empty());
        }
    }
}

#[test]
fn battery_answers_on_a_laptop_or_says_there_is_none() {
    let answer = battery(&options());
    assert_eq!(answer.question, Question::Battery);
    assert!(!answer.findings.is_empty());
}

#[test]
fn a_window_in_the_future_finds_no_dated_event() {
    let mut options = options();
    options.since = Some(jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24));
    let answer = timeline(&options);
    assert!(answer.findings.iter().all(|f| f.time().is_none()));
}
