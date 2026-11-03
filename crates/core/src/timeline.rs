//! Merging findings into a timeline.

use crate::finding::Finding;

/// Merge findings from any number of questions into one timeline, oldest first.
///
/// The sort is stable, so findings with equal times keep the order they were given in. Findings
/// without a time go last, also in the order given.
pub fn merge_timeline(findings: impl IntoIterator<Item = Finding>) -> Vec<Finding> {
    let mut merged: Vec<Finding> = findings.into_iter().collect();
    merged.sort_by_key(|finding| (finding.time().is_none(), finding.time()));
    merged
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;
    use crate::answer::Question;
    use crate::finding::NotRecorded;

    fn finding(id: &str, time: Option<&str>) -> Finding {
        let finding =
            Finding::not_recorded(id, Question::Timeline, "h", "x", NotRecorded::new("w", "c"))
                .unwrap();
        match time {
            Some(time) => finding.at(time.parse::<Timestamp>().unwrap()),
            None => finding,
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(Finding::id).collect()
    }

    #[test]
    fn sorts_oldest_first_keeps_ties_in_given_order_and_puts_untimed_last() {
        let merged = merge_timeline([
            finding("ten_a", Some("2026-11-03T10:00:00Z")),
            finding("untimed_1", None),
            finding("nine", Some("2026-11-03T09:00:00Z")),
            finding("ten_b", Some("2026-11-03T10:00:00Z")),
            finding("untimed_2", None),
            finding("eleven", Some("2026-11-03T11:00:00Z")),
        ]);
        assert_eq!(
            ids(&merged),
            ["nine", "ten_a", "ten_b", "eleven", "untimed_1", "untimed_2"]
        );
    }

    #[test]
    fn empty_in_empty_out() {
        assert!(merge_timeline([]).is_empty());
    }
}
