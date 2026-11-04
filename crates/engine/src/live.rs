//! Live state shared by `nosleep` and `now`: power requests and the awake flags.

use jiff::Timestamp;
use pcsleuth_core::{Evidence, Finding, FindingError, Question, SourceId, Sourced};
use pcsleuth_sources::power::{ExecutionState, PowerRequest, Reason, RequestType, Requester};

use crate::common::{Findings, exe_name, file_name, live};

fn predicate(kind: RequestType) -> &'static str {
    match kind {
        RequestType::System => "keeping the PC from sleeping",
        RequestType::Display => "keeping the screen on",
        RequestType::AwayMode => "keeping the PC working while it looks asleep (away mode)",
        RequestType::Execution => "asking to keep running in the background",
        RequestType::PerfBoost => "asking for a performance boost",
        RequestType::ActiveLockScreen => "keeping the lock screen active",
    }
}

/// One finding per live power request, or one saying there are none. Does nothing when the read
/// failed: the limit explains that.
pub fn request_findings(
    requests: &Sourced<PowerRequest>,
    question: Question,
    now: Timestamp,
    out: &mut Findings,
) {
    if !requests.access.is_ok() && requests.data.is_empty() {
        return;
    }
    if requests.data.is_empty() {
        out.push(Finding::recorded(
            format!("{question}.no_requests"),
            question,
            "No program or driver is holding a power request right now",
            "Windows lists no outstanding power request. A power request is how a program or \
             driver asks Windows to keep the PC or screen awake.",
            [live(SourceId::PowerRequests, now).with_field("requests", "0")],
        ));
        return;
    }
    for request in &requests.data {
        out.push(request_finding(request, question, now));
    }
}

fn request_finding(
    request: &PowerRequest,
    question: Question,
    now: Timestamp,
) -> Result<Finding, FindingError> {
    let mut evidence = live(SourceId::PowerRequests, now);
    let owner = match &request.requester {
        Requester::Process { image, .. } => {
            let image = image.as_deref().unwrap_or("A program");
            if let Some(exe) = exe_name(image) {
                evidence = evidence.with_field("process", exe);
            }
            file_name(image).to_owned()
        }
        Requester::Service { image, tag, .. } => {
            let image = image.as_deref().unwrap_or("A service host");
            if let Some(exe) = exe_name(image) {
                evidence = evidence.with_field("process", exe);
            }
            format!(
                "A Windows service running inside {} (service tag {tag})",
                file_name(image)
            )
        }
        Requester::Driver {
            description,
            device_path,
        } => {
            let name = description.as_deref().or(device_path.as_deref());
            if let Some(name) = name {
                evidence = evidence.with_field("driver", name);
            }
            format!("The driver {}", name.unwrap_or("(unnamed)"))
        }
        Requester::Unknown(kind) => format!("An owner of type {kind}"),
    };
    let held: Vec<&str> = request
        .active
        .iter()
        .map(|(kind, _)| predicate(*kind))
        .collect();
    evidence = evidence.with_field(
        "held",
        request
            .active
            .iter()
            .map(|(kind, count)| format!("{kind:?}x{count}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    let reason = match &request.reason {
        Some(Reason::Text(text)) => format!(" The reason it gave: \"{text}\"."),
        _ => String::new(),
    };
    Finding::recorded(
        format!("{question}.power_request"),
        question,
        format!("{owner} is {}", held.join(" and ")),
        format!(
            "Windows lists this as a live power request, which is how a program or driver asks \
             Windows to stay awake.{reason}"
        ),
        [evidence],
    )
}

pub fn execution_state_finding(
    state: &Sourced<ExecutionState>,
    question: Question,
    now: Timestamp,
    out: &mut Findings,
) {
    let Some(state) = state.data.first() else {
        return;
    };
    let mut set = Vec::new();
    if state.system_required {
        set.push("system required");
    }
    if state.display_required {
        set.push("display required");
    }
    if state.away_mode_required {
        set.push("away mode required");
    }
    let evidence: Evidence = live(SourceId::PowerState, now)
        .with_field("execution_state", format!("0x{:08x}", state.raw))
        .with_field("flags", set.join(", "));
    let id = format!("{question}.execution_state");
    if set.is_empty() {
        out.push(Finding::recorded(
            id,
            question,
            "Windows' keep-awake flags are all clear right now",
            "No program has set a keep-awake flag. This does not rule out a power request (how a \
             program asks Windows to stay awake) that this account cannot see; those need admin.",
            [evidence],
        ));
    } else {
        out.push(Finding::recorded(
            id,
            question,
            "Windows has a keep-awake flag set right now",
            format!(
                "These flags are set: {}. \"System required\" stops the PC sleeping on its own \
                 and \"display required\" keeps the screen on. A flag does not say who set it; \
                 the live power requests, which need admin, name the owner.",
                set.join(", ")
            ),
            [evidence],
        ));
    }
}
