//! One function per question, each returning an [`Answer`].
//!
//! Each question is split in two. A pure function turns what the sources returned into findings
//! (the modules [`wake`], [`nosleep`], [`battery`], [`crash`], [`slow`], [`now`], [`timeline`] and
//! [`doctor`]) and is tested over `fixtures/`. A thin step in `gather` reads the sources and hands
//! them over. The functions at the crate root are the two joined, and are what the command line
//! and the app call.
//!
//! The rule that shapes every finding: never state a cause Windows did not state. `Recorded`
//! only when a record says it, `Correlated` only with a cited nearby record and the word
//! "likely", `Sampled` only from the recorder with its interval, and `not recorded` with what
//! would capture it otherwise.
#![forbid(unsafe_code)]

pub mod battery;
pub mod common;
pub mod crash;
pub mod doctor;
mod gather;
pub mod live;
pub mod nosleep;
pub mod now;
pub mod recorded;
pub mod slow;
pub mod timeline;
pub mod wake;

pub use common::{Window, collapse_sids};

use jiff::{SignedDuration, Timestamp};
use pcsleuth_core::{Answer, Question};

/// What the caller asked for. Fields may be added; build it with `Options::default()` and set fields.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// Only use evidence at or after this time. Defaults to [`default_lookback`] before now.
    pub since: Option<Timestamp>,
    /// Show at most this many dated findings, keeping the most recent. Defaults to
    /// [`default_limit`]. Findings with no date (live state, "not recorded" notes) are always shown.
    pub limit: Option<usize>,
}

/// The window an answer used, and whether it came from the caller or from a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    pub window: Window,
    pub since_is_default: bool,
    pub limit_is_default: bool,
}

/// How far back a question looks when `--since` is not given.
pub fn default_lookback(question: Question) -> SignedDuration {
    match question {
        // Crashes are rare enough that a week often shows none.
        Question::Crash => SignedDuration::from_hours(30 * 24),
        _ => SignedDuration::from_hours(7 * 24),
    }
}

/// How many dated findings a question shows when `--limit` is not given.
pub fn default_limit(question: Question) -> usize {
    match question {
        Question::Timeline => 50,
        _ => 20,
    }
}

/// The window for `question` at `now`, with defaults filled in.
pub fn resolve(question: Question, options: &Options, now: Timestamp) -> Resolved {
    let default_since = now
        .checked_sub(default_lookback(question))
        .unwrap_or(Timestamp::UNIX_EPOCH);
    Resolved {
        window: Window {
            now,
            since: options.since.unwrap_or(default_since),
            limit: options.limit.unwrap_or_else(|| default_limit(question)),
        },
        since_is_default: options.since.is_none(),
        limit_is_default: options.limit.is_none(),
    }
}

fn window(question: Question, options: &Options) -> Window {
    resolve(question, options, Timestamp::now()).window
}

pub fn wake(options: &Options) -> Answer {
    let w = window(Question::Wake, options);
    wake::answer(&gather::wake_input(&w), &w)
}

pub fn nosleep(options: &Options) -> Answer {
    let w = window(Question::NoSleep, options);
    nosleep::answer(&gather::nosleep_input(&w), &w)
}

pub fn battery(options: &Options) -> Answer {
    let w = window(Question::Battery, options);
    battery::answer(&gather::battery_input(&w), &w)
}

pub fn crash(options: &Options) -> Answer {
    let w = window(Question::Crash, options);
    crash::answer(&gather::crash_input(&w), &w)
}

pub fn slow(options: &Options) -> Answer {
    let w = window(Question::Slow, options);
    slow::answer(&gather::slow_input(&w), &w)
}

pub fn now(options: &Options) -> Answer {
    let w = window(Question::Now, options);
    now::answer(&gather::now_input(), &w)
}

pub fn timeline(options: &Options) -> Answer {
    let w = window(Question::Timeline, options);
    timeline::answer(&gather::timeline_input(&w), &w)
}

pub fn doctor(options: &Options) -> Answer {
    let w = window(Question::Doctor, options);
    doctor::answer(&gather::doctor_input(&w), &w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn defaults_are_a_week_back_and_twenty_findings() {
        let now = at("2026-11-04T09:00:00Z");
        let resolved = resolve(Question::Wake, &Options::default(), now);
        assert_eq!(resolved.window.since, at("2026-10-28T09:00:00Z"));
        assert_eq!(resolved.window.limit, 20);
        assert!(resolved.since_is_default && resolved.limit_is_default);
    }

    #[test]
    fn crashes_look_back_a_month_and_the_timeline_shows_more() {
        let now = at("2026-11-04T09:00:00Z");
        let crash = resolve(Question::Crash, &Options::default(), now);
        assert_eq!(crash.window.since, at("2026-10-05T09:00:00Z"));
        let timeline = resolve(Question::Timeline, &Options::default(), now);
        assert_eq!(timeline.window.limit, 50);
    }

    #[test]
    fn what_the_caller_asked_for_wins_and_is_not_marked_default() {
        let options = Options {
            since: Some(at("2026-11-01T00:00:00Z")),
            limit: Some(3),
        };
        let resolved = resolve(Question::Slow, &options, at("2026-11-04T09:00:00Z"));
        assert_eq!(resolved.window.since, at("2026-11-01T00:00:00Z"));
        assert_eq!(resolved.window.limit, 3);
        assert!(!resolved.since_is_default && !resolved.limit_is_default);
    }
}
