//! Scheduled tasks that may wake the PC, as `wake` lists them.

mod support;

use pcsleuth_core::{Access, SourceId, Sourced};
use pcsleuth_engine::wake;
use pcsleuth_sources::tasks::{TaskScan, TaskState, WakeTask};
use support::{by_id, ts, window};

fn task(path: &str, enabled: bool, next: Option<&str>) -> WakeTask {
    WakeTask {
        path: path.into(),
        enabled: Some(enabled),
        state: if enabled {
            TaskState::Ready
        } else {
            TaskState::Disabled
        },
        next_run: next.map(ts),
        last_run: None,
    }
}

fn input(scan: TaskScan, access: Access) -> wake::Input {
    wake::Input {
        wakes: Sourced::ok(SourceId::EventLogSystem, vec![]),
        kernel_power: Sourced::ok(SourceId::EventLogSystem, vec![]),
        timers: Sourced::unreadable(SourceId::WakeTimers, Access::NeedsAdmin),
        armed: Sourced::unreadable(SourceId::ArmedDevices, Access::Missing),
        tasks: Sourced {
            source: SourceId::ScheduledTasks,
            access,
            data: vec![scan],
        },
    }
}

#[test]
fn wake_tasks_are_listed_with_any_user_sid_collapsed() {
    let scan = TaskScan {
        elevated: false,
        wake_tasks: vec![
            task(
                r"\Microsoft\Windows\UpdateOrchestrator\Reboot",
                true,
                Some("2026-11-05T09:00:00Z"),
            ),
            task(
                r"\OneDrive Reporting Task-S-1-5-21-111-222-333-1001",
                true,
                None,
            ),
            task(r"\Disabled", false, None),
        ],
        ..TaskScan::default()
    };
    let answer = wake::answer(
        &input(scan, Access::NeedsAdmin),
        &window("2026-11-01T00:00:00Z"),
    );
    let finding = by_id(&answer.findings, "wake.scheduled_tasks")[0];
    assert_eq!(
        finding.headline(),
        "2 scheduled tasks are set to wake the PC"
    );
    assert!(
        finding
            .explanation()
            .contains("Among the tasks this user can see")
    );
    assert!(finding.explanation().contains("(next run in 24 h)"));
    assert!(finding.explanation().contains("Reporting Task-<user>"));
    assert!(!finding.explanation().contains("S-1-5-21"));
    for evidence in finding.evidence() {
        assert!(!evidence.fields["task"].contains("S-1-5-21"));
        assert!(!evidence.fields.contains_key("process"));
    }
    // Elevation would show tasks hidden from this user.
    let limit = answer
        .limits
        .iter()
        .find(|l| l.source == SourceId::ScheduledTasks)
        .unwrap();
    assert_eq!(
        limit.adds.as_deref(),
        Some("scheduled tasks hidden from this user")
    );
}

#[test]
fn no_wake_task_is_said_with_the_caveat_when_unelevated() {
    let answer = wake::answer(
        &input(TaskScan::default(), Access::NeedsAdmin),
        &window("2026-11-01T00:00:00Z"),
    );
    let finding = by_id(&answer.findings, "wake.scheduled_tasks")[0];
    assert_eq!(
        finding.headline(),
        "No scheduled task is set to wake the PC"
    );
    assert!(finding.explanation().contains("this user can see"));
}
