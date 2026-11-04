//! The Windows Event Log reader: `EvtQuery` (newest first), `EvtNext`, `EvtRender` as XML.
//!
//! This is the only place in the event log code that uses `unsafe`. Handles are closed by
//! [`Owned`]. Nothing here panics on what the OS returns: every failure becomes an [`Access`].
//!
//! What a read returns is decided in `collect.rs`, which is pure: `Ok` only when nothing is
//! missing, `Partial` (with the reason) when records were unreadable, the read failed part way,
//! the limit was reached with more left, or the log's state is unknown, and `Failed` only when
//! nothing was read.

use std::collections::VecDeque;
use std::mem::size_of;

use jiff::Timestamp;
use pcsleuth_core::{Access, SourceId, Sourced};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS};
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_VARIANT, EvtChannelConfigEnabled, EvtGetChannelConfigProperty, EvtNext,
    EvtOpenChannelConfig, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, EvtVarTypeBoolean,
};
use windows::core::{Error, HSTRING, Owned};

use super::apps::ApplicationEvent;
use super::collect::{ChannelRead, Step, collect, finish_channel, merge};
use super::common::FromRawError;
use super::lifecycle::LifecycleEvent;
use super::perf::PerfEvent;
use super::power::{KernelPowerEvent, PowerTroubleshooterWake, ProcessorCapped};
use super::query::{Family, access_from_code, source_for_channel, win32_code};
use super::raw::{RawEvent, parse_event};
use super::resource::ResourceExhaustion;
use super::sched::TaskEvent;

/// Events fetched per `EvtNext` call, at most.
const BATCH: usize = 32;
/// How long one `EvtNext` may wait, in milliseconds. Local reads return at once.
const NEXT_TIMEOUT_MS: u32 = 5_000;

fn access_from_error(error: &Error) -> Access {
    access_from_code(win32_code(error.code().0), &error.message())
}

/// One event as `EvtRenderEventXml` XML.
fn render_xml(event: EVT_HANDLE) -> Result<String, Error> {
    let mut used = 0u32;
    let mut count = 0u32;
    // SAFETY: a null buffer of size 0 only asks for the size needed; both out pointers are valid.
    let first = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used,
            &mut count,
        )
    };
    match first {
        Ok(()) => {}
        Err(e) if win32_code(e.code().0) == ERROR_INSUFFICIENT_BUFFER.0 => {}
        Err(e) => return Err(e),
    }
    let mut buffer = vec![0u16; (used as usize).div_ceil(2)];
    // SAFETY: `buffer` is writable for `used` bytes and both out pointers are valid.
    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            used,
            Some(buffer.as_mut_ptr().cast()),
            &mut used,
            &mut count,
        )?;
    }
    let written = (used as usize / 2).min(buffer.len());
    let text = &buffer[..written];
    Ok(String::from_utf16_lossy(
        text.strip_suffix(&[0]).unwrap_or(text),
    ))
}

/// Whether the channel is switched on, from its configuration. `Err` when that cannot be told:
/// the configuration cannot be read, or `Enabled` is not a Boolean.
fn channel_enabled(channel: &str) -> Result<bool, Access> {
    // SAFETY: the channel path is a valid string for the call; `None` selects the local machine.
    let config = unsafe { EvtOpenChannelConfig(None, &HSTRING::from(channel), 0) }
        .map_err(|e| access_from_error(&e))?;
    // SAFETY: the handle is new and owned by nobody else.
    let config = unsafe { Owned::new(config) };
    let mut value = EVT_VARIANT::default();
    let mut used = 0u32;
    // SAFETY: the buffer is one EVT_VARIANT and its size is passed; a Boolean needs no more room.
    unsafe {
        EvtGetChannelConfigProperty(
            *config,
            EvtChannelConfigEnabled,
            0,
            size_of::<EVT_VARIANT>() as u32,
            Some(&mut value),
            &mut used,
        )
    }
    .map_err(|e| access_from_error(&e))?;
    // SAFETY: the union is read as a Boolean only after `Type` says it is one.
    enabled_from_variant(value.Type, || {
        unsafe { value.Anonymous.BooleanVal }.as_bool()
    })
}

/// `Enabled` is documented as a Boolean. Anything else is not "enabled": it is an answer this
/// reader does not understand, and it says so.
fn enabled_from_variant(variant_type: u32, boolean: impl FnOnce() -> bool) -> Result<bool, Access> {
    if variant_type == EvtVarTypeBoolean.0 as u32 {
        return Ok(boolean());
    }
    Err(Access::Failed {
        code: 0,
        message: format!("the Enabled property has variant type {variant_type}, not Boolean"),
    })
}

/// A query over one channel, yielding its records newest first.
struct Cursor {
    results: Owned<EVT_HANDLE>,
    /// Event handles fetched and not yet rendered. Dropping one closes it.
    pending: VecDeque<Owned<EVT_HANDLE>>,
    /// How many handles to ask `EvtNext` for at a time, at most [`BATCH`].
    batch: usize,
    failure: Option<Access>,
    done: bool,
}

impl Cursor {
    fn fetch(&mut self) {
        let mut handles = [0isize; BATCH];
        let want = self.batch.min(BATCH);
        let mut returned = 0u32;
        // SAFETY: `handles[..want]` is writable, `returned` is a valid out pointer, and `results` is open.
        let status = unsafe {
            EvtNext(
                *self.results,
                &mut handles[..want],
                NEXT_TIMEOUT_MS,
                0,
                &mut returned,
            )
        };
        let returned = (returned as usize).min(want);
        for &raw_handle in &handles[..returned] {
            // SAFETY: EvtNext returned this handle to us; `Owned` closes it.
            self.pending
                .push_back(unsafe { Owned::new(EVT_HANDLE(raw_handle)) });
        }
        match status {
            Ok(()) if returned > 0 => {}
            // No handles and no error would loop forever; treat it as the end.
            Ok(()) => self.done = true,
            Err(e) if win32_code(e.code().0) == ERROR_NO_MORE_ITEMS.0 => self.done = true,
            Err(e) => {
                self.failure = Some(access_from_error(&e));
                self.done = true;
            }
        }
    }
}

impl Iterator for Cursor {
    type Item = Step;

    fn next(&mut self) -> Option<Step> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                // A record that cannot be rendered or parsed is counted by `collect`, not fatal.
                let raw = render_xml(*event)
                    .ok()
                    .and_then(|xml| parse_event(&xml).ok());
                return Some(Step::Event(raw));
            }
            // Handles that arrived with an error are delivered before it.
            if let Some(access) = self.failure.take() {
                return Some(Step::Failed(access));
            }
            if self.done {
                return None;
            }
            self.fetch();
        }
    }
}

/// Read one channel, newest first, until `limit` records were accepted by `convert` or the channel
/// ends. The result says everything about completeness except the limit, which `merge` adds.
fn read_channel<T>(
    channel: &str,
    xpath: &str,
    limit: usize,
    convert: impl FnMut(RawEvent) -> Option<T>,
) -> ChannelRead<T> {
    let xpath = if xpath.trim().is_empty() { "*" } else { xpath };
    let flags = EvtQueryChannelPath.0 | EvtQueryReverseDirection.0;
    // SAFETY: both strings are valid for the call; `None` selects the local machine.
    let results =
        match unsafe { EvtQuery(None, &HSTRING::from(channel), &HSTRING::from(xpath), flags) } {
            // SAFETY: the handle is new and owned by nobody else.
            Ok(handle) => unsafe { Owned::new(handle) },
            Err(e) => {
                return ChannelRead {
                    access: access_from_error(&e),
                    data: Vec::new(),
                    more: false,
                };
            }
        };
    let cursor = Cursor {
        results,
        pending: VecDeque::new(),
        // One more than the limit, so the look past it needs no second call.
        batch: limit.saturating_add(1).clamp(1, BATCH),
        failure: None,
        done: false,
    };
    finish_channel(channel, collect(cursor, limit, convert), || {
        channel_enabled(channel)
    })
}

/// Read each of `channels` and merge them, newest first, at most `limit` records in all.
fn read_channels<T>(
    source: SourceId,
    channels: &[&str],
    xpath: &str,
    limit: usize,
    mut convert: impl FnMut(RawEvent) -> Option<(Option<Timestamp>, T)>,
) -> Sourced<T> {
    let parts = channels
        .iter()
        .map(|channel| read_channel(channel, xpath, limit, &mut convert))
        .collect();
    merge(source, parts, limit)
}

/// Read raw events from one of the channels this crate knows (see [`source_for_channel`]),
/// newest first, at most `limit`. `xpath` may be empty for "everything".
///
/// The result is `Ok` only when nothing is missing. Records that could not be rendered or parsed,
/// a read that failed part way, and `limit` being reached while more records exist are each an
/// [`Access::Partial`] that says so, with the records that were read kept in `data`. Looking for
/// more past the limit never changes `data`.
///
/// A channel this crate does not know is reported as [`Access::Missing`] under the System source,
/// because the contract has no source to file it under.
pub fn query(channel: &str, xpath: &str, limit: usize) -> Sourced<RawEvent> {
    match source_for_channel(channel) {
        Some(source) => read_channels(source, &[channel], xpath, limit, |raw| {
            Some((raw.time_created, raw))
        }),
        None => Sourced::unreadable(SourceId::EventLogSystem, Access::Missing),
    }
}

/// Whether a channel can be read: `Missing` when it is not registered, `LogDisabled` when it is
/// switched off, `NeedsAdmin` when Windows denies the read, `Ok` otherwise. For `doctor`.
pub fn channel_status(channel: &str) -> Access {
    // One record shows the channel can be read; whether more exist does not matter here.
    read_channel(channel, "*", 1, Some).access
}

/// Every channel of a family, merged, as the typed event. The limit is on typed events: a record
/// that fails `convert` is counted as unreadable and does not use up the limit, so it cannot push a
/// real record out. Unreadable records make the result `Partial`.
fn typed<T>(
    family: Family,
    since: Option<Timestamp>,
    limit: usize,
    convert: fn(&RawEvent) -> Result<T, FromRawError>,
) -> Sourced<T> {
    read_channels(
        family.source(),
        family.channels(),
        &family.xpath(since),
        limit,
        |raw| {
            let time = raw.time_created;
            convert(&raw).ok().map(|item| (time, item))
        },
    )
}

/// Power-Troubleshooter 1 wake records, newest first.
pub fn wakes(since: Option<Timestamp>, limit: usize) -> Sourced<PowerTroubleshooterWake> {
    typed(
        Family::Wakes,
        since,
        limit,
        PowerTroubleshooterWake::from_raw,
    )
}

/// Kernel-Power 41, 42, 105, 107, 172, 506 and 507, newest first.
pub fn kernel_power(since: Option<Timestamp>, limit: usize) -> Sourced<KernelPowerEvent> {
    typed(
        Family::KernelPower,
        since,
        limit,
        KernelPowerEvent::from_raw,
    )
}

/// Kernel-Processor-Power 37 records, newest first.
pub fn processor_caps(since: Option<Timestamp>, limit: usize) -> Sourced<ProcessorCapped> {
    typed(
        Family::ProcessorPower,
        since,
        limit,
        ProcessorCapped::from_raw,
    )
}

/// EventLog 6005, 6006, 6008, 6009, User32 1074 and bugcheck 1001, newest first.
pub fn lifecycle_events(since: Option<Timestamp>, limit: usize) -> Sourced<LifecycleEvent> {
    typed(Family::Lifecycle, since, limit, LifecycleEvent::from_raw)
}

/// Application Error 1000, Application Hang 1002 and Windows Error Reporting 1001, newest first.
///
/// Providers in the Application log can be forged by any local process, so a record shows what was
/// logged, not that the program crashed.
pub fn application_events(since: Option<Timestamp>, limit: usize) -> Sourced<ApplicationEvent> {
    typed(
        Family::Applications,
        since,
        limit,
        ApplicationEvent::from_raw,
    )
}

/// Resource-Exhaustion-Detector 2004, from the Operational and System channels, newest first.
pub fn resource_exhaustion(since: Option<Timestamp>, limit: usize) -> Sourced<ResourceExhaustion> {
    typed(
        Family::ResourceExhaustion,
        since,
        limit,
        ResourceExhaustion::from_raw,
    )
}

/// Diagnostics-Performance boot and shutdown records. `NeedsAdmin` without elevation.
pub fn diagnostics_performance(since: Option<Timestamp>, limit: usize) -> Sourced<PerfEvent> {
    typed(Family::Performance, since, limit, PerfEvent::from_raw)
}

/// Task Scheduler Operational records. The channel is off by default (`LogDisabled`).
pub fn task_events(since: Option<Timestamp>, limit: usize) -> Sourced<TaskEvent> {
    typed(Family::Tasks, since, limit, TaskEvent::from_raw)
}

/// Live smoke tests: they read this machine's real logs, so they assert shapes and access
/// results, never counts or contents. They pass with or without elevation.
#[cfg(test)]
mod tests {
    use jiff::SignedDuration;

    use super::*;
    use crate::eventlog::collect::limit_message;
    use crate::eventlog::query::{DIAGNOSTICS_PERFORMANCE, SYSTEM, TASK_SCHEDULER};

    fn readable_or_gated(access: &Access) -> bool {
        matches!(
            access,
            Access::Ok | Access::NeedsAdmin | Access::LogDisabled | Access::Partial { .. }
        )
    }

    /// The read is complete, or incomplete only because it stopped at `limit` with more left.
    #[track_caller]
    fn complete_or_limited<T>(read: &Sourced<T>, limit: usize) {
        if read.access != Access::Ok {
            assert_eq!(
                read.access,
                Access::Partial {
                    message: limit_message(limit)
                }
            );
            assert_eq!(read.data.len(), limit);
        }
    }

    #[test]
    fn system_log_reads_newest_first() {
        let read = query(SYSTEM, "*", 40);
        complete_or_limited(&read, 40);
        assert_eq!(read.source, SourceId::EventLogSystem);
        assert!(!read.data.is_empty() && read.data.len() <= 40);
        assert!(
            read.data
                .iter()
                .all(|e| e.channel.as_deref() == Some("System"))
        );
        assert!(
            read.data
                .iter()
                .all(|e| e.provider.is_some() && e.record_id.is_some())
        );
        assert!(
            read.data
                .windows(2)
                .all(|w| w[0].time_created >= w[1].time_created)
        );
        assert!(
            read.data
                .windows(2)
                .all(|w| w[0].record_id > w[1].record_id)
        );
    }

    #[test]
    fn hitting_the_limit_is_partial_and_zero_reads_nothing() {
        // The System log of a machine that has run holds far more than three records.
        let three = query(SYSTEM, "", 3);
        assert_eq!(three.data.len(), 3);
        assert_eq!(
            three.access,
            Access::Partial {
                message: limit_message(3)
            }
        );
        let none = query(SYSTEM, "*", 0);
        assert!(none.data.is_empty());
        assert_eq!(
            none.access,
            Access::Partial {
                message: limit_message(0)
            }
        );
    }

    #[test]
    fn a_limit_above_what_exists_is_a_complete_read() {
        let hour_ago = Timestamp::now() - SignedDuration::from_hours(1);
        let recent = query(SYSTEM, &Family::Lifecycle.xpath(Some(hour_ago)), 1_000);
        assert_eq!(recent.access, Access::Ok);
        assert!(recent.data.len() < 1_000);
    }

    #[test]
    fn finds_and_types_power_or_event_log_records() {
        let wakes = wakes(None, 20);
        let life = lifecycle_events(None, 20);
        complete_or_limited(&wakes, 20);
        complete_or_limited(&life, 20);
        assert!(
            !wakes.data.is_empty() || !life.data.is_empty(),
            "a machine that has booted has logged a wake or an Event Log start"
        );
        for w in &wakes.data {
            assert!(w.to_evidence().record_id.is_some());
        }
        for e in &life.data {
            assert!(e.to_evidence().timestamp.is_some());
        }
    }

    #[test]
    fn records_that_do_not_convert_are_reported_and_do_not_use_up_the_limit() {
        let raw = query(SYSTEM, &Family::Lifecycle.xpath(None), 1);
        assert!(!raw.data.is_empty(), "every booted machine logs 6005");
        let rejected = typed::<()>(Family::Lifecycle, None, 3, |_| {
            Err(FromRawError::MissingField("x"))
        });
        assert!(rejected.data.is_empty());
        match &rejected.access {
            Access::Partial { message } => {
                assert!(message.contains("could not be read"), "{message}");
                assert!(!message.contains("limit reached"), "{message}");
            }
            other => panic!("expected Partial, got {other}"),
        }
    }

    #[test]
    fn every_system_family_reads_without_failing() {
        complete_or_limited(&kernel_power(None, 10), 10);
        complete_or_limited(&processor_caps(None, 10), 10);
        complete_or_limited(&application_events(None, 10), 10);
        assert!(readable_or_gated(&resource_exhaustion(None, 10).access));
    }

    #[test]
    fn diagnostics_performance_is_gated_or_readable() {
        let perf = diagnostics_performance(None, 5);
        assert!(readable_or_gated(&perf.access), "{:?}", perf.access);
        assert_eq!(perf.source, SourceId::EventLogDiagnosticsPerformance);
        if perf.access.elevation_helps() {
            assert!(perf.data.is_empty());
            assert!(perf.limit().unwrap().adds.is_some());
        }
        let status = channel_status(DIAGNOSTICS_PERFORMANCE);
        assert!(readable_or_gated(&status), "{status:?}");
    }

    #[test]
    fn unregistered_channel_is_missing() {
        assert_eq!(
            channel_status("Pcsleuth-Does-Not-Exist/Operational"),
            Access::Missing
        );
        assert_eq!(
            read_channel("Pcsleuth-Does-Not-Exist/Operational", "*", 1, Some).access,
            Access::Missing
        );
        assert_eq!(query("Not-A-Known-Channel", "*", 1).access, Access::Missing);
    }

    #[test]
    fn denied_channel_maps_to_needs_admin_not_a_failure() {
        // The Security log needs an elevated token. This asserts the mapping on whichever side the
        // test runs: unelevated gives NeedsAdmin, elevated gives Ok.
        let read = read_channel("Security", "*", 1, Some);
        assert!(
            matches!(read.access, Access::NeedsAdmin | Access::Ok),
            "{:?}",
            read.access
        );
        let status = channel_status("Security");
        assert!(
            matches!(status, Access::NeedsAdmin | Access::Ok),
            "{status:?}"
        );
    }

    #[test]
    fn a_channel_setting_that_is_not_a_boolean_is_not_assumed_enabled() {
        let boolean = EvtVarTypeBoolean.0 as u32;
        assert_eq!(enabled_from_variant(boolean, || true), Ok(true));
        assert_eq!(enabled_from_variant(boolean, || false), Ok(false));
        let other = enabled_from_variant(boolean + 1, || unreachable!("not read"));
        assert!(matches!(other, Err(Access::Failed { .. })), "{other:?}");
        // The real channels answer with a Boolean.
        assert_eq!(channel_enabled(SYSTEM), Ok(true));
    }

    #[test]
    fn since_is_understood_by_the_event_log() {
        let since = Timestamp::now() - SignedDuration::from_hours(24 * 30);
        let recent = query(SYSTEM, &Family::Lifecycle.xpath(Some(since)), 50);
        assert!(
            matches!(recent.access, Access::Ok | Access::Partial { .. }),
            "the since predicate was rejected: {:?}",
            recent.access
        );
        complete_or_limited(&recent, 50);
        assert!(recent.data.iter().all(|e| e.time_created >= Some(since)));
        let future = Timestamp::now() + SignedDuration::from_hours(24);
        let none = wakes(Some(future), 5);
        assert_eq!((none.access, none.data.len()), (Access::Ok, 0));
    }

    #[test]
    fn task_scheduler_status_is_reported_either_way() {
        // Off by default (LogDisabled here), on after someone enables history.
        let status = channel_status(TASK_SCHEDULER);
        assert!(readable_or_gated(&status), "{status:?}");
        let events = task_events(None, 5);
        assert!(readable_or_gated(&events.access), "{:?}", events.access);
    }
}
