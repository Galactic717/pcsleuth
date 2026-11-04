//! One row per scenario, the summary over them, the printed table and the results file.

use std::fmt::Write as _;

use pcsleuth_core::Question;
use serde::Serialize;

use crate::host::Env;
use crate::score::{Observable, Outcome, Scored};

/// Bump when the shape of the results file changes.
pub const RESULTS_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub name: &'static str,
    pub question: Question,
    /// `yes`, `no` or `unverified`.
    pub observable: &'static str,
    /// Why it is not observable, or not known.
    pub why: Option<String>,
    /// `scored`, or `not_run` with the reason in `detail`. Never a pass.
    pub status: &'static str,
    pub outcome: Option<Outcome>,
    pub detail: String,
    /// Other causes a confident finding named.
    pub named: Vec<String>,
    pub extras: usize,
    /// Every finding was a `*.not_implemented` placeholder.
    pub placeholder: bool,
    /// Event record ids the injection produced, when it produced any.
    pub injected_record_ids: Vec<String>,
}

fn observable_label(observable: &Observable) -> (&'static str, Option<String>) {
    match observable {
        Observable::Yes => ("yes", None),
        Observable::No { reason, .. } => ("no", Some(reason.clone())),
        Observable::Unverified(why) => ("unverified", Some(why.clone())),
    }
}

/// One line for `list`: `yes`, `no: why` or `unverified: why`.
pub fn observable_text(observable: &Observable) -> String {
    match observable_label(observable) {
        (label, Some(why)) => format!("{label}: {why}"),
        (label, None) => label.to_owned(),
    }
}

impl Row {
    pub fn scored(
        name: &'static str,
        question: Question,
        observable: &Observable,
        scored: Scored,
        injected_record_ids: Vec<String>,
    ) -> Row {
        let (label, why) = observable_label(observable);
        Row {
            name,
            question,
            observable: label,
            why,
            status: "scored",
            outcome: Some(scored.outcome),
            detail: scored.detail,
            named: scored.named,
            extras: scored.extras,
            placeholder: scored.placeholder,
            injected_record_ids,
        }
    }

    pub fn not_run(
        name: &'static str,
        question: Question,
        observable: &Observable,
        reason: String,
    ) -> Row {
        let (label, why) = observable_label(observable);
        Row {
            name,
            question,
            observable: label,
            why,
            status: "not_run",
            outcome: None,
            detail: reason,
            named: Vec::new(),
            extras: 0,
            placeholder: false,
            injected_record_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub true_positive: usize,
    pub honest: usize,
    pub miss: usize,
    pub silent: usize,
    pub false_attribution: usize,
    pub unverified: usize,
    pub not_run: usize,
    /// Scored rows whose cause was observable, and how many of them were found.
    pub observable_scored: usize,
    pub observable_found: usize,
    /// Scored rows whose cause was not observable, and how many said so.
    pub unobservable_scored: usize,
    pub unobservable_honest: usize,
    /// Honest outcomes that came from `*.not_implemented` placeholder answers.
    pub honest_by_placeholder: usize,
    pub points: i32,
    /// Scored rows that could earn a point; unverified and not-run rows are left out.
    pub possible: usize,
}

impl Summary {
    pub fn of(rows: &[Row]) -> Summary {
        let mut s = Summary::default();
        for row in rows {
            let Some(outcome) = row.outcome else {
                s.not_run += 1;
                continue;
            };
            match outcome {
                Outcome::TruePositive => s.true_positive += 1,
                Outcome::Honest => s.honest += 1,
                Outcome::Miss => s.miss += 1,
                Outcome::Silent => s.silent += 1,
                Outcome::FalseAttribution => s.false_attribution += 1,
                Outcome::Unverified => s.unverified += 1,
            }
            match row.observable {
                "yes" => {
                    s.observable_scored += 1;
                    s.observable_found += usize::from(outcome == Outcome::TruePositive);
                }
                "no" => {
                    s.unobservable_scored += 1;
                    s.unobservable_honest += usize::from(outcome == Outcome::Honest);
                }
                _ => {}
            }
            let by_placeholder = outcome == Outcome::Honest && row.placeholder;
            s.honest_by_placeholder += usize::from(by_placeholder);
            // A stub that says "not implemented" to every question is not being honest about a
            // limit, so it earns no point for it. It still counts as `honest` above, visibly.
            if !by_placeholder {
                s.points += outcome.points();
            }
            s.possible += usize::from(outcome != Outcome::Unverified);
        }
        s
    }
}

/// The table printed after a run, and the lines under it.
pub fn table(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<28} {:<8} {:<11} {:<17} detail",
        "scenario", "question", "observable", "result"
    );
    for row in rows {
        let result = row.outcome.map_or("not_run", Outcome::as_str);
        let detail: String = row.detail.chars().take(78).collect();
        let _ = writeln!(
            out,
            "{:<28} {:<8} {:<11} {:<17} {}",
            row.name,
            row.question.as_str(),
            row.observable,
            result,
            detail
        );
    }
    let s = Summary::of(rows);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "found      {}/{} scenarios whose cause Windows recorded and the tool could read",
        s.observable_found, s.observable_scored
    );
    let _ = writeln!(
        out,
        "honest     {}/{} scenarios whose cause was not observable ({} by placeholder answers)",
        s.unobservable_honest, s.unobservable_scored, s.honest_by_placeholder
    );
    let _ = writeln!(out, "false attributions  {}", s.false_attribution);
    let _ = writeln!(
        out,
        "not run    {} (a scenario that did not run is never a pass)",
        s.not_run
    );
    let _ = writeln!(
        out,
        "net points {} of {} possible (placeholder answers earn no honesty points)",
        s.points, s.possible
    );
    out
}

#[derive(Serialize)]
pub struct Results<'a> {
    pub schema: u32,
    pub env: &'a Env,
    pub summary: &'a Summary,
    pub scenarios: &'a [Row],
}

/// The file name for a run: sortable, and says where it ran.
pub fn file_name(env: &Env) -> String {
    format!("run-{}-{}.json", env.date.strftime("%Y%m%dT%H%M%SZ"), env.tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::Scored;

    fn scored(outcome: Outcome, placeholder: bool) -> Scored {
        Scored {
            outcome,
            detail: "d".into(),
            named: vec![],
            extras: 0,
            placeholder,
        }
    }

    fn rows() -> Vec<Row> {
        let no = Observable::No {
            reason: "not logged".into(),
            limit: None,
        };
        vec![
            Row::scored("a", Question::Crash, &Observable::Yes, scored(Outcome::TruePositive, false), vec!["1".into()]),
            Row::scored("b", Question::Now, &Observable::Yes, scored(Outcome::Miss, true), vec![]),
            Row::scored("c", Question::Slow, &no, scored(Outcome::Honest, true), vec![]),
            Row::scored("d", Question::Slow, &no, scored(Outcome::Silent, false), vec![]),
            Row::scored("e", Question::Wake, &Observable::Yes, scored(Outcome::FalseAttribution, false), vec![]),
            Row::scored("f", Question::Wake, &Observable::Unverified("w".into()), scored(Outcome::Unverified, false), vec![]),
            Row::not_run("g", Question::Wake, &Observable::Yes, "needs --sleep".into()),
        ]
    }

    #[test]
    fn summary_counts_every_outcome_and_never_counts_not_run_as_a_pass() {
        let s = Summary::of(&rows());
        assert_eq!(
            (s.true_positive, s.honest, s.miss, s.silent, s.false_attribution),
            (1, 1, 1, 1, 1)
        );
        assert_eq!((s.unverified, s.not_run), (1, 1));
        assert_eq!((s.observable_scored, s.observable_found), (3, 1));
        assert_eq!((s.unobservable_scored, s.unobservable_honest), (2, 1));
        assert_eq!(s.honest_by_placeholder, 1);
        // +1 true positive, -1 false attribution. The honest outcome came from a placeholder
        // answer, so it adds nothing; the others add nothing either.
        assert_eq!(s.points, 0);
        // Scored rows except the unverified one: the not-run row is not possible either.
        assert_eq!(s.possible, 5);
    }

    #[test]
    fn a_run_where_nothing_ran_scores_nothing() {
        let rows = vec![Row::not_run("g", Question::Wake, &Observable::Yes, "x".into())];
        let s = Summary::of(&rows);
        assert_eq!((s.points, s.possible, s.not_run), (0, 0, 1));
        assert_eq!(Summary::of(&[]), Summary::default());
    }

    #[test]
    fn the_table_lists_every_row_and_says_not_run_is_not_a_pass() {
        let text = table(&rows());
        for name in ["a", "b", "c", "d", "e", "f", "g"] {
            assert!(text.lines().any(|l| l.starts_with(&format!("{name} "))), "{name}");
        }
        assert!(text.contains("not_run"));
        assert!(text.contains("never a pass"));
        assert!(text.contains("net points 0 of 5 possible"));
    }

    #[test]
    fn real_honesty_earns_a_point_and_placeholder_honesty_does_not() {
        let no = Observable::No {
            reason: "x".into(),
            limit: None,
        };
        let row = |placeholder| {
            Row::scored("c", Question::Slow, &no, scored(Outcome::Honest, placeholder), vec![])
        };
        assert_eq!(Summary::of(&[row(false)]).points, 1);
        assert_eq!(Summary::of(&[row(true)]).points, 0);
        assert_eq!(Summary::of(&[row(true)]).honest, 1);
    }

    #[test]
    fn the_results_file_name_carries_the_tag_and_a_sortable_date() {
        let env = Env {
            tag: "laptop",
            elevated: false,
            os_build: "10.0.1".into(),
            git_commit: "abc".into(),
            git_dirty: false,
            date: "2026-11-03T13:05:09Z".parse().unwrap(),
        };
        assert_eq!(file_name(&env), "run-20261103T130509Z-laptop.json");
    }

    #[test]
    fn the_results_json_has_the_environment_and_no_machine_names() {
        let env = Env {
            tag: "ci",
            elevated: true,
            os_build: "10.0.26300".into(),
            git_commit: "abc123".into(),
            git_dirty: false,
            date: "2026-11-03T13:05:09Z".parse().unwrap(),
        };
        let rows = rows();
        let summary = Summary::of(&rows);
        let json = serde_json::to_value(Results {
            schema: RESULTS_SCHEMA,
            env: &env,
            summary: &summary,
            scenarios: &rows,
        })
        .unwrap();
        assert_eq!(json["env"]["tag"], "ci");
        assert_eq!(json["env"]["elevated"], true);
        assert_eq!(json["env"]["os_build"], "10.0.26300");
        assert_eq!(json["env"]["git_commit"], "abc123");
        assert_eq!(json["env"]["date"], "2026-11-03T13:05:09Z");
        assert_eq!(json["scenarios"][0]["outcome"], "true_positive");
        assert_eq!(json["scenarios"][6]["status"], "not_run");
        assert!(json["scenarios"][6]["outcome"].is_null());
        let keys: Vec<_> = json["env"].as_object().unwrap().keys().cloned().collect();
        assert!(!keys.iter().any(|k| k.contains("host") || k.contains("user") || k.contains("name")));
    }
}
