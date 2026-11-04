//! Bounded reads over a stream of records, and what to say about them. Pure: the cursor over a
//! real channel is in `native.rs`, the tests here feed vectors.
//!
//! A read is `Ok` only when nothing is missing. Everything that makes the data incomplete is
//! `Partial` with the reason: records that could not be rendered, parsed or converted, a read that
//! failed part way, the limit being reached while more records exist, and not knowing whether the
//! log is switched on. `Failed` is for a read that got nothing.

use jiff::Timestamp;
use pcsleuth_core::{Access, SourceId, Sourced};

use super::raw::RawEvent;

/// One thing a cursor over a channel yielded.
pub(crate) enum Step {
    /// A record, or `None` when it could not be rendered or parsed.
    Event(Option<RawEvent>),
    /// The read failed. The cursor yields nothing after this.
    Failed(Access),
}

/// What reading one channel produced, before it becomes an access result.
pub(crate) struct Collected<T> {
    pub data: Vec<T>,
    /// Records skipped because they could not be rendered, parsed or converted.
    pub unreadable: usize,
    /// A record exists after the `limit` converted ones. It is looked at, never returned.
    pub more: bool,
    /// The cursor failed before the end of the channel or the limit.
    pub failure: Option<Access>,
}

/// Take up to `limit` records that `convert` accepts. The limit counts converted records, so a
/// record that cannot be converted (garbage, or an event someone else wrote under a provider's
/// name) never pushes a real one out. One more record is looked at after the limit to see whether
/// the channel holds more; it does not change `data`.
pub(crate) fn collect<T>(
    steps: impl Iterator<Item = Step>,
    limit: usize,
    mut convert: impl FnMut(RawEvent) -> Option<T>,
) -> Collected<T> {
    let mut out = Collected {
        data: Vec::new(),
        unreadable: 0,
        more: false,
        failure: None,
    };
    for step in steps {
        match step {
            // Past the limit a failure cannot lose anything that was asked for.
            Step::Failed(access) => {
                if out.data.len() < limit {
                    out.failure = Some(access);
                }
                break;
            }
            Step::Event(_) if out.data.len() >= limit => {
                out.more = true;
                break;
            }
            Step::Event(raw) => match raw.and_then(&mut convert) {
                Some(item) => out.data.push(item),
                None => out.unreadable += 1,
            },
        }
    }
    out
}

/// One channel's records and how complete the read was, apart from the limit.
pub(crate) struct ChannelRead<T> {
    /// Failure, unreadable records and whether the log is on. The limit is added in [`merge`].
    pub access: Access,
    pub data: Vec<T>,
    pub more: bool,
}

/// Turn what [`collect`] saw into a [`ChannelRead`]. `enabled` asks whether the log is switched on;
/// it is not called when the read failed.
pub(crate) fn finish_channel<T>(
    channel: &str,
    collected: Collected<T>,
    enabled: impl FnOnce() -> Result<bool, Access>,
) -> ChannelRead<T> {
    let Collected {
        data,
        unreadable,
        more,
        failure,
    } = collected;
    let mut access = match failure {
        Some(failure) if data.is_empty() => failure,
        Some(failure) => partial(format!(
            "{channel}: read {}, then failed: {failure}",
            records(data.len())
        )),
        // A disabled channel can still hold old records, so they stay in `data`.
        None => match enabled() {
            Ok(true) => Access::Ok,
            Ok(false) => Access::LogDisabled,
            Err(why) => partial(format!(
                "{channel}: could not tell whether the log is enabled: {why}"
            )),
        },
    };
    if unreadable > 0 {
        let message = format!("{channel}: {} could not be read", records(unreadable));
        access = worst(access, partial(message));
    }
    ChannelRead { access, data, more }
}

/// Join channels into one result, newest first (when there are several, by `TimeCreated`), at
/// most `limit` long. The worst access among the channels decides, and reaching the limit with
/// more records left is a `Partial` that says how many were read.
pub(crate) fn merge<T>(
    source: SourceId,
    parts: Vec<ChannelRead<(Option<Timestamp>, T)>>,
    limit: usize,
) -> Sourced<T> {
    let several = parts.len() > 1;
    let mut access = Access::Ok;
    let mut more = false;
    let mut all = Vec::new();
    for part in parts {
        access = worst(access, part.access);
        more |= part.more;
        all.extend(part.data);
    }
    if several {
        all.sort_by_key(|(time, _)| std::cmp::Reverse(*time));
    }
    if all.len() > limit {
        more = true;
        all.truncate(limit);
    }
    if more {
        access = worst(access, partial(limit_message(limit)));
    }
    Sourced {
        source,
        access,
        data: all.into_iter().map(|(_, item)| item).collect(),
    }
}

/// What a `Partial` says when the limit was reached and the channel has more.
pub(crate) fn limit_message(limit: usize) -> String {
    format!(
        "limit reached: read the newest {} and more exist",
        records(limit)
    )
}

fn partial(message: String) -> Access {
    Access::Partial { message }
}

fn records(count: usize) -> String {
    match count {
        1 => "1 record".to_owned(),
        n => format!("{n} records"),
    }
}

/// How much a state says is wrong, for picking one of several.
fn severity(access: &Access) -> u8 {
    match access {
        Access::Ok => 0,
        Access::LogDisabled => 1,
        Access::Missing => 2,
        Access::Partial { .. } => 3,
        Access::NeedsAdmin => 4,
        Access::Failed { .. } => 5,
    }
}

/// The worse of two states: `Failed` over `NeedsAdmin` over `Partial` over `Missing` over
/// `LogDisabled` over `Ok`. On a tie the first wins, except that two `Partial` join their messages
/// so neither reason is lost.
pub(crate) fn worst(first: Access, second: Access) -> Access {
    match (first, second) {
        (Access::Partial { message: a }, Access::Partial { message: b }) => Access::Partial {
            message: format!("{a}; {b}"),
        },
        (first, second) if severity(&second) > severity(&first) => second,
        (first, _) => first,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record that converts: it has a record id. `bad()` has none and does not.
    fn good(id: u64) -> Step {
        Step::Event(Some(RawEvent {
            record_id: Some(id),
            ..RawEvent::default()
        }))
    }

    fn bad() -> Step {
        Step::Event(Some(RawEvent::default()))
    }

    fn id_of(raw: RawEvent) -> Option<u64> {
        raw.record_id
    }

    fn failed() -> Access {
        Access::Failed {
            code: 1722,
            message: "rpc".into(),
        }
    }

    fn partial_text(access: &Access) -> &str {
        match access {
            Access::Partial { message } => message,
            other => panic!("expected Partial, got {other}"),
        }
    }

    #[test]
    fn looking_past_the_limit_flags_more_without_changing_what_is_returned() {
        let ids = |limit| {
            let steps = (1..=5).map(good);
            collect(steps, limit, id_of)
        };
        let capped = ids(3);
        assert_eq!(capped.data, [1, 2, 3]);
        assert!(capped.more);
        // Exactly as many records as the limit: nothing more, same data prefix.
        let exact = ids(5);
        assert_eq!(exact.data, [1, 2, 3, 4, 5]);
        assert!(!exact.more);
        assert!(!ids(6).more);
        assert_eq!(ids(6).data, exact.data);
        let none = ids(0);
        assert!(none.data.is_empty() && none.more);
    }

    #[test]
    fn records_that_do_not_convert_are_counted_and_never_use_up_the_limit() {
        // A hundred forged records ahead of three real ones, then more real ones.
        let steps = (0..100)
            .map(|_| bad())
            .chain([good(7), good(6), good(5), good(4)]);
        let read = collect(steps, 3, id_of);
        assert_eq!(read.data, [7, 6, 5]);
        assert_eq!(read.unreadable, 100);
        assert!(read.more);
        // A record that could not even be rendered counts the same way.
        let read = collect([Step::Event(None), good(1)].into_iter(), 5, id_of);
        assert_eq!((read.data, read.unreadable, read.more), (vec![1], 1, false));
    }

    #[test]
    fn a_failure_keeps_the_records_read_before_it_and_is_ignored_after_the_limit() {
        let read = collect(
            [good(2), good(1), Step::Failed(failed())].into_iter(),
            10,
            id_of,
        );
        assert_eq!(read.data, [2, 1]);
        assert_eq!(read.failure, Some(failed()));
        // The limit was already met, so the failure lost nothing that was asked for.
        let read = collect(
            [good(2), good(1), Step::Failed(failed())].into_iter(),
            2,
            id_of,
        );
        assert_eq!((read.data.len(), read.failure, read.more), (2, None, false));
    }

    fn collected(data: Vec<u64>, unreadable: usize, failure: Option<Access>) -> Collected<u64> {
        Collected {
            data,
            unreadable,
            more: false,
            failure,
        }
    }

    #[test]
    fn a_channel_is_ok_only_when_nothing_is_missing() {
        let ok = || Ok(true);
        assert_eq!(
            finish_channel("System", collected(vec![1], 0, None), ok).access,
            Access::Ok
        );
        assert_eq!(
            finish_channel("System", collected(vec![], 0, None), || Ok(false)).access,
            Access::LogDisabled
        );
        // Unreadable records make it Partial, and Partial outranks a disabled log.
        let read = finish_channel("System", collected(vec![1], 2, None), || Ok(false));
        assert_eq!(read.data, [1]);
        assert_eq!(
            partial_text(&read.access),
            "System: 2 records could not be read"
        );
        // Not knowing whether the log is on is said, not assumed.
        let read = finish_channel("System", collected(vec![1], 0, None), || {
            Err(Access::NeedsAdmin)
        });
        assert!(partial_text(&read.access).contains("could not tell whether the log is enabled"));
        assert_eq!(read.data, [1]);
    }

    #[test]
    fn a_failed_read_is_failed_only_when_it_got_nothing() {
        let never =
            || -> Result<bool, Access> { panic!("the log state is not asked after a failure") };
        let none = finish_channel("System", collected(vec![], 0, Some(failed())), never);
        assert_eq!(none.access, failed());
        let denied = finish_channel(
            "Security",
            collected(vec![], 0, Some(Access::NeedsAdmin)),
            never,
        );
        assert_eq!(denied.access, Access::NeedsAdmin);
        let some = finish_channel("System", collected(vec![3, 2], 0, Some(failed())), never);
        assert_eq!(some.data, [3, 2]);
        assert!(partial_text(&some.access).starts_with("System: read 2 records, then failed: "));
        let one = finish_channel("System", collected(vec![3], 0, Some(failed())), never);
        assert!(partial_text(&one.access).starts_with("System: read 1 record, then failed"));
    }

    #[test]
    fn the_worst_state_wins_and_partial_reasons_are_kept() {
        let partial = |m: &str| Access::Partial { message: m.into() };
        let order = [
            Access::Ok,
            Access::LogDisabled,
            Access::Missing,
            partial("x"),
            Access::NeedsAdmin,
            failed(),
        ];
        for (i, lower) in order.iter().enumerate() {
            for higher in &order[i + 1..] {
                assert_eq!(&worst(lower.clone(), higher.clone()), higher);
                assert_eq!(&worst(higher.clone(), lower.clone()), higher);
            }
        }
        assert_eq!(worst(partial("a"), partial("b")), partial("a; b"));
        assert_eq!(worst(Access::Ok, Access::Ok), Access::Ok);
    }

    fn part(
        access: Access,
        items: &[(&str, u64)],
        more: bool,
    ) -> ChannelRead<(Option<Timestamp>, u64)> {
        ChannelRead {
            access,
            data: items
                .iter()
                .map(|(time, id)| (Some(time.parse().unwrap()), *id))
                .collect(),
            more,
        }
    }

    #[test]
    fn a_disabled_channel_does_not_hide_a_failed_one() {
        let merged = merge(
            SourceId::EventLogResourceExhaustion,
            vec![
                part(Access::LogDisabled, &[], false),
                part(failed(), &[], false),
            ],
            10,
        );
        assert_eq!(merged.access, failed());
        let other_way = merge(
            SourceId::EventLogResourceExhaustion,
            vec![
                part(failed(), &[], false),
                part(Access::LogDisabled, &[], false),
            ],
            10,
        );
        assert_eq!(other_way.access, failed());
    }

    #[test]
    fn channels_merge_newest_first_and_truncation_is_reported() {
        let merged = merge(
            SourceId::EventLogResourceExhaustion,
            vec![
                part(
                    Access::Ok,
                    &[("2026-11-03T10:00:00Z", 1), ("2026-11-01T10:00:00Z", 2)],
                    false,
                ),
                part(
                    Access::Ok,
                    &[("2026-11-04T10:00:00Z", 3), ("2026-11-02T10:00:00Z", 4)],
                    false,
                ),
            ],
            3,
        );
        assert_eq!(merged.data, [3, 1, 4]);
        assert_eq!(
            merged.access,
            Access::Partial {
                message: limit_message(3)
            }
        );
        // Under the limit and nothing more: complete.
        let all = merge(
            SourceId::EventLogSystem,
            vec![part(Access::Ok, &[("2026-11-03T10:00:00Z", 1)], false)],
            3,
        );
        assert_eq!((all.data, all.access), (vec![1], Access::Ok));
        // One channel says there is more.
        let more = merge(
            SourceId::EventLogSystem,
            vec![part(Access::Ok, &[("2026-11-03T10:00:00Z", 1)], true)],
            1,
        );
        assert_eq!(
            more.access,
            Access::Partial {
                message: limit_message(1)
            }
        );
        assert_eq!(
            limit_message(1),
            "limit reached: read the newest 1 record and more exist"
        );
    }

    #[test]
    fn every_reason_a_read_is_incomplete_is_in_one_message() {
        let read = finish_channel("System", collected(vec![1], 4, None), || Ok(true));
        let merged = merge(
            SourceId::EventLogSystem,
            vec![ChannelRead {
                access: read.access,
                data: vec![(None, 1u64)],
                more: true,
            }],
            1,
        );
        let message = partial_text(&merged.access);
        assert!(message.contains("4 records could not be read"), "{message}");
        assert!(message.contains("more exist"), "{message}");
    }
}
