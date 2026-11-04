//! Event log channels read through `EvtQuery` and `EvtRender`, and the parsers over event XML.
//!
//! Three layers, each usable on its own:
//!
//! 1. [`parse_event`] turns one `EvtRender` XML string into a [`RawEvent`]. Pure, tolerant, and
//!    never reads `RenderingInfo` or `Message` (ADR 0002).
//! 2. Typed events such as [`PowerTroubleshooterWake`] or [`AppCrash`], each with a fallible
//!    `from_raw(&RawEvent)` and a `to_evidence()`. Numeric codes get names only where the name was
//!    proven; everything else displays as `type N`.
//! 3. On Windows, `query`, `channel_status` and one reader per event family, such as
//!    `wakes`, returning [`pcsleuth_core::Sourced`] so an unreadable channel is data.
//!
//! Evidence built by `to_evidence()` is stamped with the record's `TimeCreated`. Times from inside
//! the event (a wake time, a boot start) are fields, so the typed struct is the place to read the
//! moment something happened.
//!
//! Fixtures live in `fixtures/eventlog/`, one event per line. Files named `synthetic-*` were
//! built from provider manifests for events this laptop has never logged and are not real
//! validation.

#[forbid(unsafe_code)]
mod apps;
// Off Windows nothing reads a channel, so only the tests use the bounded-read logic.
#[cfg_attr(not(windows), allow(dead_code))]
#[forbid(unsafe_code)]
mod collect;
#[forbid(unsafe_code)]
mod common;
#[forbid(unsafe_code)]
mod lifecycle;
#[cfg(windows)]
mod native;
#[forbid(unsafe_code)]
mod perf;
#[forbid(unsafe_code)]
mod power;
#[forbid(unsafe_code)]
mod query;
#[forbid(unsafe_code)]
mod raw;
#[forbid(unsafe_code)]
mod resource;
#[forbid(unsafe_code)]
mod sched;
#[cfg(test)]
mod testutil;

pub use apps::{AppCrash, AppHang, ApplicationEvent, WerReport};
pub use common::{Coded, FromRawError, Meta, collapse_profile_path};
pub use lifecycle::{
    Bugcheck, EventLogService, LifecycleEvent, OsVersionAtBoot, ServiceState, ShutdownInitiated,
    UnexpectedShutdown,
};
#[cfg(windows)]
pub use native::{
    application_events, channel_status, diagnostics_performance, kernel_power, lifecycle_events,
    processor_caps, query, resource_exhaustion, task_events, wakes,
};
pub use perf::{BootSummary, CulpritKind, PerfCulprit, PerfEvent, PerfPhase, ShutdownSummary};
pub use power::{
    KernelPowerEvent, ModernStandbyEntered, ModernStandbyExited, ModernStandbyReason,
    PowerSourceChanged, PowerState, PowerTroubleshooterWake, ProcessorCapped, SleepEntered,
    SleepReason, SleepResumed, StandbyConnectivity, StandbyConnectivityReason,
    StandbyConnectivityState, UncleanReboot, WakeSourceType,
};
pub use query::{
    APPLICATION, DIAGNOSTICS_PERFORMANCE, Family, RESOURCE_EXHAUSTION, SYSTEM, TASK_SCHEDULER,
    access_from_code, channel_for_source, source_for_channel, win32_code, xpath_time,
};
pub use raw::{Datum, ParseError, RawEvent, parse_event};
pub use resource::{ExhaustingProcess, ResourceExhaustion};
pub use sched::{TaskEvent, TaskEventKind};
