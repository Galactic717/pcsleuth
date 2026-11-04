//! Shared pieces: the question window, limit collection, finding assembly and wording helpers.

use std::fmt::Display;
use std::time::Duration;

use jiff::Timestamp;
use pcsleuth_core::{
    Answer, Evidence, Finding, FindingError, Fix, Limit, NotRecorded, Question, SourceId, Sourced,
    merge_timeline,
};
use pcsleuth_sources::eventlog::Meta;

/// The span a question looks at, and how many dated findings it shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub now: Timestamp,
    /// Records older than this are never used, whatever they say.
    pub since: Timestamp,
    /// At most this many dated findings are kept, the most recent. Live state and "not recorded"
    /// notes have no date and are always kept.
    pub limit: usize,
}

impl Window {
    /// True for a record made at or after `since`. A record with no time is left out, because
    /// nothing proves it falls inside the window.
    pub fn contains(&self, time: Option<Timestamp>) -> bool {
        time.is_some_and(|time| time >= self.since)
    }
}

/// Findings built so far. A finding that fails core's checks is dropped, and trips a debug
/// assertion so the tests see it.
#[derive(Default)]
pub struct Findings(pub Vec<Finding>);

impl Findings {
    pub fn push<E: Display>(&mut self, built: Result<Finding, E>) {
        match built {
            Ok(finding) => self.0.push(finding),
            Err(error) => debug_assert!(false, "a finding was refused: {error}"),
        }
    }
}

/// The limits of every source read for one answer, once each.
#[derive(Default)]
pub struct Limits(pub Vec<Limit>);

impl Limits {
    pub fn note<T>(&mut self, read: &Sourced<T>) {
        if let Some(limit) = read.limit()
            && !self.0.contains(&limit)
        {
            self.0.push(limit);
        }
    }
}

/// How serious a kind of finding is (0 first) and what to call the kind in plural.
///
/// Rank 0 is trouble with the machine itself, rank 1 is trouble with a named program, a boot or
/// the battery, and every wake. Rank 2 is background noise that a busy PC makes by the hundred:
/// shutdown requests, other error reports, firmware slowdowns. The limit keeps rank 0 before
/// rank 1 before rank 2, and shares each rank between its kinds, so one noisy kind cannot fill it.
pub fn kind_of(id: &str) -> (u8, &'static str) {
    match id {
        "crash.power_lost" | "crash.blue_screen" | "crash.forced_off" => {
            (0, "restarts without a clean shutdown")
        }
        "slow.low_memory" => (0, "low-memory warnings"),
        "crash.app_crash" => (1, "program crashes"),
        "crash.app_hang" | "slow.app_hang" => (1, "program hangs"),
        "crash.wer_report" => (1, "crash reports"),
        "slow.boot" | "slow.shutdown" | "slow.boot_culprit" | "slow.shutdown_culprit" => {
            (1, "slow boots and shutdowns")
        }
        "slow.recorder_cpu" | "slow.recorder_io" => (1, "busy programs seen by the recorder"),
        "nosleep.recorder_request" => (1, "power requests seen by the recorder"),
        "battery.drain" | "battery.drain_apps" => (1, "battery drains"),
        "wake.sleep_to_hibernate" => (2, "automatic sleep-to-hibernate switches"),
        "crash.other_reports" => (2, "other error reports"),
        "crash.shutdown_requested" => (2, "shutdown requests"),
        "slow.cpu_capped" => (2, "firmware slowdowns"),
        _ if id.starts_with("wake.") => (1, "wakes"),
        _ => (1, "other findings"),
    }
}

/// Keep `window.limit` dated findings: the more serious ranks first, each rank shared between its
/// kinds (newest first within a kind). Undated findings are always kept. When some are left out,
/// a note says how many of which kind and how to see them. Sorted oldest first.
pub fn finish(
    question: Question,
    window: &Window,
    findings: Vec<Finding>,
    limits: Limits,
) -> Answer {
    let (dated, undated): (Vec<Finding>, Vec<Finding>) =
        findings.into_iter().partition(|f| f.time().is_some());
    let chosen = choose(&dated, window.limit);
    let mut slots: Vec<Option<Finding>> = dated.into_iter().map(Some).collect();
    let mut kept: Vec<Finding> = undated;
    kept.extend(chosen.iter().filter_map(|&i| slots[i].take()));
    let left_out: Vec<Finding> = slots.into_iter().flatten().collect();

    let note = left_out_note(question, window, chosen.len(), &left_out);
    let mut merged = merge_timeline(kept);
    merged.extend(note);
    Answer::new(question, window.now, merged, limits.0)
}

/// Indices of the dated findings to keep, in the order they were chosen.
fn choose(dated: &[Finding], limit: usize) -> Vec<usize> {
    let kinds: Vec<(u8, &'static str)> = dated.iter().map(|f| kind_of(f.id())).collect();
    let mut ranks: Vec<u8> = kinds.iter().map(|(rank, _)| *rank).collect();
    ranks.sort_unstable();
    ranks.dedup();

    let mut order = Vec::new();
    for rank in ranks {
        // Each kind of this rank, newest first, and the kinds with the newest finding first.
        let mut by_kind: Vec<(&str, Vec<usize>)> = Vec::new();
        for (i, (_, label)) in kinds.iter().enumerate().filter(|(_, (r, _))| *r == rank) {
            match by_kind.iter_mut().find(|(known, _)| known == label) {
                Some((_, indices)) => indices.push(i),
                None => by_kind.push((label, vec![i])),
            }
        }
        for (_, indices) in &mut by_kind {
            indices.sort_by_key(|&i| std::cmp::Reverse(dated[i].time()));
        }
        by_kind.sort_by_key(|(_, indices)| std::cmp::Reverse(dated[indices[0]].time()));
        for turn in 0.. {
            let before = order.len();
            order.extend(
                by_kind
                    .iter()
                    .filter_map(|(_, indices)| indices.get(turn).copied()),
            );
            if order.len() == before {
                break;
            }
        }
    }
    order.truncate(limit);
    order
}

/// An undated note naming what the limit left out and how to see it, or `None` if nothing was.
fn left_out_note(
    question: Question,
    window: &Window,
    shown: usize,
    left_out: &[Finding],
) -> Option<Finding> {
    if left_out.is_empty() {
        return None;
    }
    let mut counts: Vec<((u8, &str), usize)> = Vec::new();
    for finding in left_out {
        let kind = kind_of(finding.id());
        match counts.iter_mut().find(|(known, _)| *known == kind) {
            Some((_, n)) => *n += 1,
            None => counts.push((kind, 1)),
        }
    }
    counts.sort_by_key(|((rank, label), n)| (*rank, std::cmp::Reverse(*n), *label));
    let list: Vec<String> = counts
        .iter()
        .map(|((_, label), n)| format!("{label} ({n})"))
        .collect();
    let n = left_out.len();
    let source = left_out
        .iter()
        .find_map(|f| f.evidence().first().map(|e| e.source))
        .unwrap_or(SourceId::EventLogSystem);
    let note = Finding::recorded(
        format!("{question}.left_out"),
        question,
        format!(
            "{n} more dated {} not shown because of the limit of {}",
            if n == 1 { "finding is" } else { "findings are" },
            window.limit
        ),
        format!(
            "Left out: {}. The limit keeps the more serious kinds first and, within a kind, the              newest findings. To see everything, run again with --limit {}, or look at a shorter              period with --since.",
            list.join(", "),
            shown + n
        ),
        [Evidence::new(source)
            .at(window.now)
            .with_field("shown", shown.to_string())
            .with_field("left_out", n.to_string())
            .with_field("limit", window.limit.to_string())],
    );
    match note {
        Ok(note) => Some(note),
        Err(error) => {
            debug_assert!(false, "the left-out note was refused: {error}");
            None
        }
    }
}

/// A finding that is `not recorded` and still cites the record that shows the gap.
///
/// Core has no constructor for this shape: `Finding::not_recorded` takes no evidence, and the
/// other constructors set another confidence. Its validating deserializer accepts it, so the
/// finding is built through that and gets the same checks as any other.
pub fn not_recorded_citing(
    id: &str,
    question: Question,
    headline: String,
    explanation: String,
    gap: NotRecorded,
    evidence: Vec<Evidence>,
) -> Result<Finding, FindingError> {
    // Core's own constructor runs the checks first, so a refusal carries core's reason.
    Finding::not_recorded(id, question, &headline, &explanation, gap.clone())?;
    serde_json::from_value(serde_json::json!({
        "id": id,
        "question": question,
        "time": null,
        "headline": headline,
        "explanation": explanation,
        "confidence": "not_recorded",
        "evidence": evidence,
        "not_recorded": gap,
        "fix": null,
    }))
    // Unreachable once the checks above passed: every part serializes.
    .map_err(|_| FindingError::Blank("not recorded finding"))
}

/// `base` with the record id and time of `meta` filled in when the source left them out.
pub fn stamped(mut base: Evidence, meta: &Meta) -> Evidence {
    if base.record_id.is_none() {
        base.record_id = meta.record_id.map(|id| id.to_string());
    }
    if base.timestamp.is_none() {
        base.timestamp = meta.time;
    }
    base
}

/// Evidence from a live read made at `now`.
pub fn live(source: SourceId, now: Timestamp) -> Evidence {
    Evidence::new(source).at(now)
}

/// A fix whose command is printed, never run.
pub fn fix(command: impl Into<String>, explanation: impl Into<String>, needs_admin: bool) -> Fix {
    Fix::new(command, explanation, needs_admin)
}

/// `1 h 27 min`, `45 min`, `20 s`, `3 days`. Seconds are cut off once the span passes an hour.
pub fn duration(span: Duration) -> String {
    let seconds = span.as_secs();
    let (hours, minutes) = (seconds / 3600, seconds % 3600 / 60);
    match (hours, minutes) {
        (48.., _) => format!("{} days", hours / 24),
        (0, 0) => format!("{seconds} s"),
        (0, minutes) => format!("{minutes} min"),
        (hours, 0) => format!("{hours} h"),
        (hours, minutes) => format!("{hours} h {minutes} min"),
    }
}

/// Milliseconds as seconds with one decimal: `68.2 s`.
pub fn seconds_ms(ms: u64) -> String {
    format!("{:.1} s", ms as f64 / 1000.0)
}

/// The span from `earlier` to `later`, `None` when they are out of order or either is missing.
pub fn between(earlier: Option<Timestamp>, later: Option<Timestamp>) -> Option<Duration> {
    Duration::try_from(later?.duration_since(earlier?))
        .ok()
        .filter(|span| !span.is_zero())
}

/// `1.4 GB`, `220 MB`, `12 KB`, `300 B`.
pub fn bytes(count: u64) -> String {
    const UNITS: [(&str, f64); 3] = [("GB", 1_073_741_824.0), ("MB", 1_048_576.0), ("KB", 1024.0)];
    for (name, size) in UNITS {
        if count as f64 >= size {
            let value = count as f64 / size;
            return if value >= 100.0 {
                format!("{value:.0} {name}")
            } else {
                format!("{value:.1} {name}")
            };
        }
    }
    format!("{count} B")
}

/// The last part of a path, after `\` or `/`.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// The program name in `path` when it names an `.exe`, such as `chrome.exe`. Anything else, such
/// as a task path or a driver, is not a process and gives `None`.
pub fn exe_name(path: &str) -> Option<String> {
    let name = file_name(path.trim());
    let is_exe = name.len() > 4 && name.is_char_boundary(name.len() - 4) && {
        name[name.len() - 4..].eq_ignore_ascii_case(".exe")
    };
    is_exe.then(|| name.to_owned())
}

/// `text` with each user account SID (`S-1-5-21-...`, `S-1-12-1-...`) replaced by `<user>`.
///
/// A SID identifies a person, and Windows appends one to the name of some scheduled tasks. It adds
/// nothing a reader needs, so it is collapsed in what pcsleuth shows and in evidence built from
/// such names. Well-known SIDs such as Local System are not people and stay as they are.
pub fn collapse_sids(text: &str) -> String {
    const PREFIXES: [&str; 2] = ["S-1-5-21-", "S-1-12-1-"];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut previous: Option<char> = None;
    while let Some(c) = rest.chars().next() {
        let prefix = PREFIXES.iter().find(|p| rest.starts_with(**p));
        if let (Some(prefix), false) = (prefix, previous.is_some_and(char::is_alphanumeric)) {
            // Digits and hyphens follow the prefix; a hyphen right at the end is not part of it.
            let body = &rest[prefix.len()..];
            let body = &body[..body
                .find(|c: char| !(c.is_ascii_digit() || c == '-'))
                .unwrap_or(body.len())];
            let body = body.trim_end_matches('-');
            if body.starts_with(|c: char| c.is_ascii_digit()) {
                out.push_str("<user>");
                rest = &rest[prefix.len() + body.len()..];
                previous = Some('>');
                continue;
            }
        }
        out.push(c);
        previous = Some(c);
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// `name` in double quotes for a `powercfg` command line, or `None` when it has a character that
/// a shell could treat as more than text: a quote, `%`, `$`, a backtick, or a control or
/// direction character. Printing the command anyway would not be the command the user thinks.
pub fn quote_for_shell(name: &str) -> Option<String> {
    let risky = |c: char| {
        c.is_control()
            || matches!(c, '"' | '%' | '$' | '`')
            || matches!(
                c,
                '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{2028}' | '\u{2029}'
            )
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
    };
    (!name.trim().is_empty() && !name.contains(risky)).then(|| format!("\"{name}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_like_a_person_says_them() {
        let secs = Duration::from_secs;
        assert_eq!(duration(secs(20)), "20 s");
        assert_eq!(duration(secs(45 * 60 + 30)), "45 min");
        assert_eq!(duration(secs(3600)), "1 h");
        assert_eq!(duration(secs(5256)), "1 h 27 min");
        assert_eq!(duration(secs(3 * 86_400 + 5)), "3 days");
        assert_eq!(duration(secs(47 * 3600)), "47 h");
    }

    #[test]
    fn byte_sizes() {
        assert_eq!(bytes(300), "300 B");
        assert_eq!(bytes(12 * 1024), "12.0 KB");
        assert_eq!(bytes(220 * 1_048_576), "220 MB");
        assert_eq!(bytes(1_503_238_554), "1.4 GB");
    }

    #[test]
    fn only_exe_paths_are_processes() {
        assert_eq!(
            exe_name(r"\Device\HarddiskVolume3\Tools\Pcsleuth-Fault.EXE"),
            Some("Pcsleuth-Fault.EXE".into())
        );
        assert_eq!(exe_name("chrome.exe"), Some("chrome.exe".into()));
        assert_eq!(exe_name(r"Windows\UpdateOrchestrator\Reboot"), None);
        assert_eq!(exe_name(".exe"), None);
        assert_eq!(exe_name(""), None);
        assert_eq!(exe_name("\u{43f}\u{44f}\u{442}\u{44c}"), None);
    }

    #[test]
    fn user_sids_are_collapsed_and_nothing_else_is() {
        assert_eq!(
            collapse_sids(r"\OneDrive\Reporting Task-S-1-5-21-111-222-333-1001"),
            r"\OneDrive\Reporting Task-<user>"
        );
        assert_eq!(
            collapse_sids("X-S-1-12-1-111-222-333-444 (done)"),
            "X-<user> (done)"
        );
        assert_eq!(
            collapse_sids("a S-1-5-21-1-2-3 and S-1-5-21-4-5-6."),
            "a <user> and <user>."
        );
        // Not people, not SIDs, or not a whole word.
        assert_eq!(collapse_sids("S-1-5-18 runs it"), "S-1-5-18 runs it");
        assert_eq!(collapse_sids("AS-1-5-21-5"), "AS-1-5-21-5");
        assert_eq!(collapse_sids("S-1-5-21-"), "S-1-5-21-");
        assert_eq!(collapse_sids("S-1-5-21-1-2-"), "<user>-");
        assert_eq!(collapse_sids(""), "");
        assert_eq!(
            collapse_sids("\u{43f}\u{44f}\u{442}\u{44c}"),
            "\u{43f}\u{44f}\u{442}\u{44c}"
        );
    }

    #[test]
    fn a_name_is_quoted_only_when_that_is_safe() {
        assert_eq!(
            quote_for_shell("Intel(R) USB 3.10 (Microsoft)"),
            Some("\"Intel(R) USB 3.10 (Microsoft)\"".into())
        );
        for bad in [
            "a\"b",
            "50%",
            "$env:x",
            "a`b",
            "a\nb",
            "a\u{202e}b",
            "a\u{200e}b",
            "  ",
            "",
        ] {
            assert_eq!(quote_for_shell(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_limit_keeps_the_newest_dated_findings_and_all_undated_ones() {
        let at = |text: &str| text.parse::<Timestamp>().unwrap();
        let dated = |id: &str, time: &str| {
            Finding::not_recorded(id, Question::Wake, "h", "x", NotRecorded::new("w", "c"))
                .unwrap()
                .at(at(time))
        };
        let undated =
            Finding::not_recorded("u", Question::Wake, "h", "x", NotRecorded::new("w", "c"))
                .unwrap();
        let window = Window {
            now: at("2026-11-04T00:00:00Z"),
            since: at("2026-11-01T00:00:00Z"),
            limit: 2,
        };
        let answer = finish(
            Question::Wake,
            &window,
            vec![
                dated("c", "2026-11-03T00:00:00Z"),
                undated,
                dated("a", "2026-11-01T00:00:00Z"),
                dated("b", "2026-11-02T00:00:00Z"),
            ],
            Limits::default(),
        );
        let ids: Vec<_> = answer.findings.iter().map(Finding::id).collect();
        assert_eq!(ids, ["b", "c", "u", "wake.left_out"]);
        let note = answer.findings.last().unwrap();
        assert_eq!(
            note.headline(),
            "1 more dated finding is not shown because of the limit of 2"
        );
        assert!(note.explanation().contains("other findings (1)"));
        assert!(note.explanation().contains("--limit 3"));
        assert!(note.time().is_none());
    }

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn dated(id: &str, time: &str) -> Finding {
        Finding::not_recorded(id, Question::Crash, "h", "x", NotRecorded::new("w", "c"))
            .unwrap()
            .at(at(time))
    }

    fn window(limit: usize) -> Window {
        Window {
            now: at("2026-11-05T00:00:00Z"),
            since: at("2026-10-01T00:00:00Z"),
            limit,
        }
    }

    #[test]
    fn serious_kinds_are_kept_before_noisy_ones_whatever_their_age() {
        let mut findings = vec![
            dated("crash.power_lost", "2026-10-02T00:00:00Z"),
            dated("crash.power_lost", "2026-10-03T00:00:00Z"),
        ];
        // A flood of newer, less serious findings.
        for day in 10..30 {
            findings.push(dated(
                "crash.shutdown_requested",
                &format!("2026-10-{day}T00:00:00Z"),
            ));
            findings.push(dated(
                "crash.app_crash",
                &format!("2026-10-{day}T01:00:00Z"),
            ));
        }
        let answer = finish(Question::Crash, &window(5), findings, Limits::default());
        let ids: Vec<_> = answer.findings.iter().map(Finding::id).collect();
        // Both restarts, then the newest crashes, and no shutdown request at all.
        assert_eq!(ids.iter().filter(|i| **i == "crash.power_lost").count(), 2);
        assert_eq!(ids.iter().filter(|i| **i == "crash.app_crash").count(), 3);
        assert!(!ids.contains(&"crash.shutdown_requested"));
        let note = answer.findings.last().unwrap();
        assert_eq!(note.id(), "crash.left_out");
        assert!(
            note.explanation()
                .contains("program crashes (17), shutdown requests (20)")
        );
        assert!(note.explanation().contains("--limit 42"));
    }

    #[test]
    fn kinds_of_one_rank_share_the_limit_so_one_noisy_kind_cannot_fill_it() {
        let mut findings = Vec::new();
        for day in 10..20 {
            findings.push(dated(
                "slow.cpu_capped",
                &format!("2026-10-{day}T00:00:00Z"),
            ));
            findings.push(dated("slow.app_hang", &format!("2026-10-{day}T00:00:00Z")));
            findings.push(dated(
                "slow.boot_culprit",
                &format!("2026-10-{day}T00:00:00Z"),
            ));
        }
        let answer = finish(Question::Slow, &window(4), findings, Limits::default());
        let ids: Vec<_> = answer
            .findings
            .iter()
            .filter(|f| f.time().is_some())
            .map(Finding::id)
            .collect();
        // Rank 1 holds the hangs and the boot culprits: two of each. The firmware slowdowns
        // (rank 2) wait for what is left, which is nothing.
        assert_eq!(ids.iter().filter(|i| **i == "slow.app_hang").count(), 2);
        assert_eq!(ids.iter().filter(|i| **i == "slow.boot_culprit").count(), 2);
        assert!(!ids.contains(&"slow.cpu_capped"));
    }

    #[test]
    fn nothing_left_out_means_no_note() {
        let answer = finish(
            Question::Crash,
            &window(5),
            vec![dated("crash.app_crash", "2026-10-02T00:00:00Z")],
            Limits::default(),
        );
        assert_eq!(answer.findings.len(), 1);
    }

    #[test]
    fn a_record_without_a_time_is_outside_every_window() {
        let window = Window {
            now: "2026-11-04T00:00:00Z".parse().unwrap(),
            since: "2026-11-01T00:00:00Z".parse().unwrap(),
            limit: 1,
        };
        assert!(!window.contains(None));
        assert!(window.contains(Some("2026-11-01T00:00:00Z".parse().unwrap())));
        assert!(!window.contains(Some("2026-10-31T23:59:59Z".parse().unwrap())));
    }

    #[test]
    fn a_not_recorded_finding_can_cite_its_record() {
        let finding = not_recorded_citing(
            "x.y",
            Question::Crash,
            "headline".into(),
            "text".into(),
            NotRecorded::new("what", "capture"),
            vec![Evidence::new(SourceId::EventLogSystem).with_record_id("7")],
        )
        .unwrap();
        assert_eq!(finding.confidence(), pcsleuth_core::Confidence::NotRecorded);
        assert_eq!(finding.evidence()[0].record_id.as_deref(), Some("7"));
        // The same checks as any other finding: a blank headline is refused.
        assert_eq!(
            not_recorded_citing(
                "x.y",
                Question::Crash,
                " ".into(),
                "text".into(),
                NotRecorded::new("what", "capture"),
                vec![],
            ),
            Err(FindingError::Blank("headline"))
        );
    }
}
