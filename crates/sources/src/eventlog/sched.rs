//! Microsoft-Windows-TaskScheduler/Operational: 100, 102, 107, 110, 200 and 201.
//!
//! The channel is disabled by default, and it is disabled on the development machine, so the
//! parsers are built from the manifest and exercised on a synthetic fixture only. The meaning of
//! each id is the manifest's event description (`ProviderMetadata`, en-US).
//!
//! There is no event source of its own for this channel in the contract, so evidence is filed
//! under [`SourceId::ScheduledTasks`].

use pcsleuth_core::{Evidence, SourceId};

use super::common::{EvidenceExt, FromRawError, Meta};
use super::raw::RawEvent;

const PROVIDER: &[&str] = &["Microsoft-Windows-TaskScheduler"];

/// What the Task Scheduler did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskEventKind {
    /// 100: started an instance of a task.
    Started,
    /// 102: an instance finished successfully.
    Finished,
    /// 107: launched an instance because a time trigger fired.
    TimeTriggered,
    /// 110: launched an instance for a user.
    LaunchedForUser,
    /// 200: launched an action of an instance.
    ActionStarted,
    /// 201: an action completed.
    ActionCompleted,
}

impl TaskEventKind {
    fn from_id(id: u32) -> Option<Self> {
        Some(match id {
            100 => Self::Started,
            102 => Self::Finished,
            107 => Self::TimeTriggered,
            110 => Self::LaunchedForUser,
            200 => Self::ActionStarted,
            201 => Self::ActionCompleted,
            _ => return None,
        })
    }

    fn id(self) -> u32 {
        match self {
            Self::Started => 100,
            Self::Finished => 102,
            Self::TimeTriggered => 107,
            Self::LaunchedForUser => 110,
            Self::ActionStarted => 200,
            Self::ActionCompleted => 201,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Started => "task started",
            Self::Finished => "task finished",
            Self::TimeTriggered => "launched by time trigger",
            Self::LaunchedForUser => "launched for user",
            Self::ActionStarted => "action started",
            Self::ActionCompleted => "action completed",
        }
    }
}

/// One Task Scheduler Operational record.
///
/// The instance id is `InstanceId` in events 100, 102, 107 and 110 and `TaskInstanceId` in 200 and
/// 201; both end up in [`TaskEvent::instance_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEvent {
    pub meta: Meta,
    pub kind: TaskEventKind,
    /// Full task path such as `\Microsoft\Windows\Maintenance\Maintenance`.
    pub task_name: String,
    pub instance_id: Option<String>,
    pub user_context: Option<String>,
    pub action_name: Option<String>,
    /// Event 201 version 1 and later. A Win32 error or HRESULT, 0 for success.
    pub result_code: Option<u32>,
    /// Event 200 version 1 and 201 version 2.
    pub engine_pid: Option<u32>,
}

impl TaskEvent {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let kind = raw
            .event_id
            .and_then(TaskEventKind::from_id)
            .ok_or_else(|| FromRawError::WrongEvent {
                expected: "Task Scheduler 100, 102, 107, 110, 200 or 201",
                provider: raw.provider.clone(),
                event_id: raw.event_id,
            })?;
        let meta = Meta::expect(raw, "Task Scheduler event", PROVIDER, &[kind.id()])?;
        Ok(Self {
            meta,
            kind,
            task_name: raw
                .text("TaskName")
                .ok_or(FromRawError::MissingField("TaskName"))?,
            instance_id: raw
                .text("InstanceId")
                .or_else(|| raw.text("TaskInstanceId")),
            user_context: raw.text("UserContext"),
            action_name: raw.text("ActionName"),
            result_code: raw.u32("ResultCode"),
            engine_pid: raw.u32("EnginePID"),
        })
    }

    /// `user_context` is not in the evidence: it names the account the task ran as.
    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SourceId::ScheduledTasks, self.kind.id())
            .with_field("task_event", self.kind.label())
            .with_field("task_name", self.task_name.as_str())
            .opt("instance_id", self.instance_id.as_deref())
            .opt("action_name", self.action_name.as_deref())
            .opt(
                "result_code",
                self.result_code.map(|c| format!("0x{c:08x}")),
            )
            .opt("engine_pid", self.engine_pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::fixture_events;

    /// Built from the manifest, not real validation: Task Scheduler history is disabled here.
    #[test]
    fn synthetic_task_events_parse_across_versions() {
        let events: Vec<_> = fixture_events("synthetic-task-scheduler-operational.xml")
            .iter()
            .map(|r| TaskEvent::from_raw(r).unwrap())
            .collect();
        assert_eq!(events.len(), 9);
        let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
        for kind in [
            TaskEventKind::Started,
            TaskEventKind::Finished,
            TaskEventKind::TimeTriggered,
            TaskEventKind::LaunchedForUser,
            TaskEventKind::ActionStarted,
            TaskEventKind::ActionCompleted,
        ] {
            assert!(kinds.contains(&kind), "{kind:?}");
        }
        let task = r"\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work";
        assert!(events.iter().all(|e| e.task_name == task));
        assert!(events.iter().all(|e| e.instance_id.as_deref() == Some("{4C0B5F6E-2A1D-4B7A-9E36-5D2F1C8A7B90}")));

        let trigger = &events[0];
        assert_eq!(trigger.kind, TaskEventKind::TimeTriggered);
        assert_eq!(
            trigger.to_evidence().fields["task_event"],
            "launched by time trigger"
        );
        assert_eq!(trigger.to_evidence().source, SourceId::ScheduledTasks);
        // 200 v0 has no engine pid, v1 has; 201 v0 has no result code, v1 and v2 do.
        assert_eq!(events[3].engine_pid, None);
        assert_eq!(events[4].engine_pid, Some(1888));
        assert_eq!(events[5].result_code, None);
        assert_eq!(events[6].result_code, Some(0));
        assert_eq!(events[7].result_code, Some(2_147_942_402));
        assert_eq!(events[7].to_evidence().fields["result_code"], "0x80070002");
        assert_eq!(
            events[2].user_context.as_deref(),
            Some(r"NT AUTHORITY\SYSTEM")
        );
        assert!(
            events
                .iter()
                .all(|e| !e.to_evidence().fields.contains_key("user_context"))
        );
    }

    #[test]
    fn other_events_are_refused() {
        let power = fixture_events("kernel-power-41.xml").remove(0);
        assert!(TaskEvent::from_raw(&power).is_err());
        let mut nameless = fixture_events("synthetic-task-scheduler-operational.xml").remove(0);
        nameless
            .data
            .retain(|d| d.name.as_deref() != Some("TaskName"));
        assert_eq!(
            TaskEvent::from_raw(&nameless),
            Err(FromRawError::MissingField("TaskName"))
        );
    }
}
