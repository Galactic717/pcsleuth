//! `timeline`: every event-based finding of the other questions, merged and sorted.
//!
//! Only the event logs feed it. Live state (power requests, wake timers, armed devices, running
//! processes) and the battery report are left out: they describe now, not a moment in the past.

use pcsleuth_core::{Answer, Question, Sourced};
use pcsleuth_sources::eventlog::{
    ApplicationEvent, KernelPowerEvent, LifecycleEvent, PerfEvent, PowerTroubleshooterWake,
    ProcessorCapped, ResourceExhaustion,
};

use crate::common::{Limits, Window, finish};
use crate::{crash, slow, wake};

pub struct Input {
    pub wakes: Sourced<PowerTroubleshooterWake>,
    pub kernel_power: Sourced<KernelPowerEvent>,
    pub lifecycle: Sourced<LifecycleEvent>,
    pub applications: Sourced<ApplicationEvent>,
    pub perf: Sourced<PerfEvent>,
    pub processor_caps: Sourced<ProcessorCapped>,
    pub resource: Sourced<ResourceExhaustion>,
}

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.wakes);
    limits.note(&input.kernel_power);
    limits.note(&input.lifecycle);
    limits.note(&input.applications);
    limits.note(&input.perf);
    limits.note(&input.processor_caps);
    limits.note(&input.resource);

    let mut findings = wake::event_findings(&input.wakes, &input.kernel_power, window).0;
    findings.extend(
        crash::event_findings(
            &input.applications,
            &input.lifecycle,
            &input.kernel_power,
            window,
        )
        .0,
    );
    // `crash` already reports the hangs, so `slow` is given none, and a hang appears once.
    let no_hangs: Sourced<ApplicationEvent> = Sourced::ok(input.applications.source, Vec::new());
    findings.extend(
        slow::event_findings(
            &input.perf,
            &no_hangs,
            &input.processor_caps,
            &input.resource,
            window,
        )
        .0,
    );
    finish(Question::Timeline, window, findings, limits)
}
