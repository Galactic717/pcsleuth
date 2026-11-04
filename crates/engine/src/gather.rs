//! The thin step that reads the sources. Everything an answer says comes from the pure functions
//! in the question modules; this only calls the readers and hands over what they returned.
//!
//! Each reader is called on its own and wrapped so that a reader that panics becomes a failed
//! read of that one source. A failing source never stops the others.
//!
//! Off Windows nothing can be read, so every source is reported missing.
#![cfg_attr(not(windows), allow(unused_variables, dead_code))]

use pcsleuth_core::{Access, SourceId, Sourced};
use pcsleuth_sources::battery::BatteryReport;
use pcsleuth_sources::eventlog::{
    ApplicationEvent, KernelPowerEvent, LifecycleEvent, PerfEvent, PowerTroubleshooterWake,
    ProcessorCapped, ResourceExhaustion,
};
use pcsleuth_sources::power::{
    ArmedDevice, ExecutionState, LastInput, PowerRequest, PowerSource, SleepSettings, WakeTimer,
};
use pcsleuth_sources::processes::ProcessSample;
use pcsleuth_sources::srum::AppUsage;
use pcsleuth_sources::tasks::TaskScan;

use crate::common::Window;
use crate::{battery, crash, doctor, nosleep, now, slow, timeline, wake};

/// The most records one event log read returns. A week is far below it.
const EVENT_LIMIT: usize = 2000;

/// Run a reader, turning a panic into a failed read of its source.
#[cfg(windows)]
fn guard<T>(source: SourceId, read: impl FnOnce() -> Sourced<T>) -> Sourced<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(read)).unwrap_or_else(|_| {
        Sourced::unreadable(
            source,
            Access::Failed {
                code: 0,
                message: "the reader stopped unexpectedly".into(),
            },
        )
    })
}

#[cfg(not(windows))]
fn unavailable<T>(source: SourceId) -> Sourced<T> {
    Sourced::unreadable(source, Access::Missing)
}

macro_rules! read {
    ($source:expr, $windows:expr) => {{
        #[cfg(windows)]
        {
            guard($source, || $windows)
        }
        #[cfg(not(windows))]
        {
            unavailable($source)
        }
    }};
}

fn wakes(w: &Window) -> Sourced<PowerTroubleshooterWake> {
    read!(
        SourceId::EventLogSystem,
        pcsleuth_sources::eventlog::wakes(Some(w.since), EVENT_LIMIT)
    )
}

fn kernel_power(w: &Window) -> Sourced<KernelPowerEvent> {
    read!(
        SourceId::EventLogSystem,
        pcsleuth_sources::eventlog::kernel_power(Some(w.since), EVENT_LIMIT)
    )
}

fn lifecycle(w: &Window) -> Sourced<LifecycleEvent> {
    read!(
        SourceId::EventLogSystem,
        pcsleuth_sources::eventlog::lifecycle_events(Some(w.since), EVENT_LIMIT)
    )
}

fn applications(w: &Window) -> Sourced<ApplicationEvent> {
    read!(
        SourceId::EventLogApplication,
        pcsleuth_sources::eventlog::application_events(Some(w.since), EVENT_LIMIT)
    )
}

fn processor_caps(w: &Window) -> Sourced<ProcessorCapped> {
    read!(
        SourceId::EventLogSystem,
        pcsleuth_sources::eventlog::processor_caps(Some(w.since), EVENT_LIMIT)
    )
}

fn resource(w: &Window) -> Sourced<ResourceExhaustion> {
    read!(
        SourceId::EventLogResourceExhaustion,
        pcsleuth_sources::eventlog::resource_exhaustion(Some(w.since), EVENT_LIMIT)
    )
}

fn perf(w: &Window) -> Sourced<PerfEvent> {
    read!(
        SourceId::EventLogDiagnosticsPerformance,
        pcsleuth_sources::eventlog::diagnostics_performance(Some(w.since), EVENT_LIMIT)
    )
}

fn sleep_settings() -> Sourced<SleepSettings> {
    read!(
        SourceId::PowerSettings,
        pcsleuth_sources::power::sleep_settings()
    )
}

fn execution_state() -> Sourced<ExecutionState> {
    read!(
        SourceId::PowerState,
        pcsleuth_sources::power::execution_state()
    )
}

fn last_input() -> Sourced<LastInput> {
    read!(SourceId::PowerState, pcsleuth_sources::power::last_input())
}

fn power_source() -> Sourced<PowerSource> {
    read!(
        SourceId::PowerState,
        pcsleuth_sources::power::power_source()
    )
}

fn armed_devices() -> Sourced<ArmedDevice> {
    read!(
        SourceId::ArmedDevices,
        pcsleuth_sources::power::armed_devices()
    )
}

fn power_requests() -> Sourced<PowerRequest> {
    read!(
        SourceId::PowerRequests,
        pcsleuth_sources::power::power_requests()
    )
}

fn wake_timers() -> Sourced<WakeTimer> {
    read!(SourceId::WakeTimers, pcsleuth_sources::power::wake_timers())
}

fn wake_tasks() -> Sourced<TaskScan> {
    read!(
        SourceId::ScheduledTasks,
        pcsleuth_sources::tasks::wake_tasks()
    )
}

fn battery_report() -> Sourced<BatteryReport> {
    read!(
        SourceId::BatteryReport,
        pcsleuth_sources::battery::read_battery_report()
    )
}

fn process_sample() -> Sourced<ProcessSample> {
    read!(SourceId::Processes, pcsleuth_sources::processes::sample())
}

/// Per-app usage from SRUM. Only an elevated run can copy the database, and `snapshot_copy`
/// says so without trying when this one is not, so an unelevated run costs nothing.
fn srum(w: &Window) -> Sourced<AppUsage> {
    read!(SourceId::Srum, {
        match pcsleuth_sources::srum::snapshot_copy() {
            Ok(copy) => {
                let until = w.now + jiff::SignedDuration::from_hours(1);
                pcsleuth_sources::srum::read_usage(&copy.db_path(), w.since, until)
            }
            Err(access) => Sourced::unreadable(SourceId::Srum, access),
        }
    })
}

/// The recorder's ring file is not read yet.
// ponytail: the lead wires the real reader after the recorder package merges. Until then the
// recorder is reported missing, which is also what a PC that never turned it on gets.
fn recorder() -> Sourced<pcsleuth_core::RecorderRow> {
    Sourced::unreadable(SourceId::Recorder, Access::Missing)
}

pub fn wake_input(w: &Window) -> wake::Input {
    wake::Input {
        wakes: wakes(w),
        kernel_power: kernel_power(w),
        timers: wake_timers(),
        armed: armed_devices(),
        tasks: wake_tasks(),
    }
}

pub fn nosleep_input(w: &Window) -> nosleep::Input {
    nosleep::Input {
        settings: sleep_settings(),
        requests: power_requests(),
        execution_state: execution_state(),
        last_input: last_input(),
        wakes: wakes(w),
        recorder: recorder(),
    }
}

pub fn battery_input(w: &Window) -> battery::Input {
    battery::Input {
        report: battery_report(),
        srum: srum(w),
    }
}

pub fn crash_input(w: &Window) -> crash::Input {
    crash::Input {
        applications: applications(w),
        lifecycle: lifecycle(w),
        kernel_power: kernel_power(w),
    }
}

pub fn slow_input(w: &Window) -> slow::Input {
    slow::Input {
        perf: perf(w),
        applications: applications(w),
        processor_caps: processor_caps(w),
        resource: resource(w),
        srum: srum(w),
        recorder: recorder(),
    }
}

/// How long `now` waits between its two process samples.
const SAMPLE_GAP: std::time::Duration = std::time::Duration::from_secs(1);

pub fn now_input() -> now::Input {
    let first = process_sample();
    std::thread::sleep(SAMPLE_GAP);
    let second = process_sample();
    now::Input {
        first,
        second,
        power_source: power_source(),
        execution_state: execution_state(),
        requests: power_requests(),
        timers: wake_timers(),
    }
}

pub fn timeline_input(w: &Window) -> timeline::Input {
    timeline::Input {
        wakes: wakes(w),
        kernel_power: kernel_power(w),
        lifecycle: lifecycle(w),
        applications: applications(w),
        perf: perf(w),
        processor_caps: processor_caps(w),
        resource: resource(w),
    }
}

/// The access of each source, read the way a question reads it.
pub fn doctor_input(w: &Window) -> doctor::Input {
    use pcsleuth_sources::eventlog::channel_for_source;

    let channel_status = |source: SourceId| -> Access {
        #[cfg(windows)]
        {
            match channel_for_source(source) {
                Some(channel) => {
                    std::panic::catch_unwind(|| pcsleuth_sources::eventlog::channel_status(channel))
                        .unwrap_or(Access::Failed {
                            code: 0,
                            message: "the reader stopped unexpectedly".into(),
                        })
                }
                None => Access::Missing,
            }
        }
        #[cfg(not(windows))]
        {
            let _ = channel_for_source(source);
            Access::Missing
        }
    };
    // PowerState is several reads; the first that is not fully readable speaks for it.
    let power_state = [
        execution_state().access,
        last_input().access,
        power_source().access,
    ]
    .into_iter()
    .find(|access| !access.is_ok())
    .unwrap_or(Access::Ok);

    let probes = SourceId::ALL
        .iter()
        .map(|&source| {
            let access = match source {
                SourceId::EventLogSystem
                | SourceId::EventLogApplication
                | SourceId::EventLogResourceExhaustion
                | SourceId::EventLogDiagnosticsPerformance => channel_status(source),
                SourceId::PowerSettings => sleep_settings().access,
                SourceId::PowerState => power_state.clone(),
                SourceId::ArmedDevices => armed_devices().access,
                SourceId::PowerRequests => power_requests().access,
                SourceId::WakeTimers => wake_timers().access,
                SourceId::BatteryReport => battery_report().access,
                SourceId::Srum => srum(w).access,
                SourceId::ScheduledTasks => wake_tasks().access,
                SourceId::Processes => process_sample().access,
                SourceId::Recorder => recorder().access,
            };
            let log = (source == SourceId::ScheduledTasks).then(|| channel_status(source));
            doctor::Probe {
                source,
                access,
                log,
            }
        })
        .collect();
    doctor::Input { probes }
}
