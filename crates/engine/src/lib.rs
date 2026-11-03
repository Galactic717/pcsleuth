//! One function per question, each returning an [`Answer`].
//!
//! Stubs for now: every question returns one honest "not recorded" finding saying it is not
//! implemented yet. The engine package replaces the bodies; the signatures are what the command
//! line and the app call.
#![forbid(unsafe_code)]

use jiff::Timestamp;
use pcsleuth_core::{Answer, Finding, NotRecorded, Question};

/// What the caller asked for. Fields may be added; build it with `Options::default()` and set fields.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// Only use evidence at or after this time.
    pub since: Option<Timestamp>,
    /// Return at most this many findings, keeping the most recent.
    pub limit: Option<usize>,
}

pub fn wake(options: &Options) -> Answer {
    not_implemented(Question::Wake, options)
}

pub fn nosleep(options: &Options) -> Answer {
    not_implemented(Question::NoSleep, options)
}

pub fn battery(options: &Options) -> Answer {
    not_implemented(Question::Battery, options)
}

pub fn crash(options: &Options) -> Answer {
    not_implemented(Question::Crash, options)
}

pub fn slow(options: &Options) -> Answer {
    not_implemented(Question::Slow, options)
}

pub fn now(options: &Options) -> Answer {
    not_implemented(Question::Now, options)
}

pub fn timeline(options: &Options) -> Answer {
    not_implemented(Question::Timeline, options)
}

pub fn doctor(options: &Options) -> Answer {
    not_implemented(Question::Doctor, options)
}

fn not_implemented(question: Question, _options: &Options) -> Answer {
    let finding = Finding::not_recorded(
        format!("{question}.not_implemented"),
        question,
        format!("The {question} question is not implemented yet"),
        "This build of pcsleuth has the answer format and the command line, but does not read \
         any logs for this question yet.",
        NotRecorded::new(
            format!("the answer to the {question} question"),
            "a release whose engine reads the sources listed for this question in docs/PLAN.md",
        ),
    )
    .expect("the stub text is fixed and not blank");
    Answer::new(question, Timestamp::now(), vec![finding], Vec::new())
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::Confidence;

    use super::*;

    #[test]
    fn every_question_says_it_is_not_implemented() {
        let options = Options::default();
        type Ask = fn(&Options) -> Answer;
        let questions: [(Question, Ask); 8] = [
            (Question::Wake, wake),
            (Question::NoSleep, nosleep),
            (Question::Battery, battery),
            (Question::Crash, crash),
            (Question::Slow, slow),
            (Question::Now, now),
            (Question::Timeline, timeline),
            (Question::Doctor, doctor),
        ];
        for (question, ask) in questions {
            let answer = ask(&options);
            assert_eq!(answer.question, question);
            assert_eq!(answer.findings.len(), 1);
            let finding = &answer.findings[0];
            assert_eq!(finding.confidence(), Confidence::NotRecorded);
            assert_eq!(finding.id(), format!("{question}.not_implemented"));
        }
    }
}
