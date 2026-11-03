//! Scheduled tasks that may wake the machine, read through the Task Scheduler COM API
//! (`ITaskService`) and not through the Task Scheduler event log, which is another package's job.
//!
//! A task wakes the computer only when its settings have `WakeToRun` on. Without admin the API
//! shows only part of the task tree. That is reported as data: [`TaskScan`] names every folder and
//! task it could not open, and the read's access is [`Access::NeedsAdmin`] when anything was
//! denied, with the tasks that were readable still in `data`.

use jiff::Timestamp;
use jiff::civil::date;
use jiff::tz::TimeZone;

#[cfg(windows)]
use pcsleuth_core::{Access, SourceId, Sourced};

/// Whether a task can run now, from `TASK_STATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Unknown,
    Disabled,
    Queued,
    Ready,
    Running,
}

impl TaskState {
    pub fn from_raw(raw: i32) -> TaskState {
        match raw {
            1 => TaskState::Disabled,
            2 => TaskState::Queued,
            3 => TaskState::Ready,
            4 => TaskState::Running,
            _ => TaskState::Unknown,
        }
    }
}

/// A task whose settings say it may wake the computer to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeTask {
    /// Full path in the task tree, such as `\Microsoft\Windows\UpdateOrchestrator\Reboot`.
    pub path: String,
    /// The task's own switch. A disabled task never wakes anything.
    pub enabled: bool,
    pub state: TaskState,
    /// When the scheduler will next start it, if it knows.
    pub next_run: Option<Timestamp>,
    pub last_run: Option<Timestamp>,
}

/// What one walk of the task tree found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaskScan {
    /// Whether the scan ran elevated. Unelevated, a task whose permissions hide it from this user
    /// is not listed at all, and nothing can count what is not listed, so "no wake tasks" is
    /// complete only when this is true.
    pub elevated: bool,
    /// Tasks with `WakeToRun` set, in tree order.
    pub wake_tasks: Vec<WakeTask>,
    /// Task folders opened and listed.
    pub folders_scanned: u32,
    /// Tasks whose settings were read, wake or not.
    pub tasks_seen: u32,
    /// Folders that could not be opened or listed. Their tasks are not in the counts.
    pub unreadable_folders: Vec<String>,
    /// Tasks seen in a listing whose settings could not be read.
    pub unreadable_tasks: Vec<String>,
}

/// An OLE automation `DATE` (days since 1899-12-30, local time) as a timestamp in `tz`.
///
/// The Task Scheduler returns 0 when a time does not exist (a task that never ran); that and any
/// value that is not a plausible date give `None`.
pub fn ole_date_to_timestamp(value: f64, tz: &TimeZone) -> Option<Timestamp> {
    if !value.is_finite() || value < 1.0 || value > 2_958_465.0 {
        return None;
    }
    let days = value.floor();
    let seconds = ((value - days) * 86_400.0).round() as i64;
    let civil = date(1899, 12, 30)
        .at(0, 0, 0, 0)
        .checked_add(jiff::Span::new().days(days as i64).seconds(seconds))
        .ok()?;
    tz.to_timestamp(civil).ok()
}

/// Walk the whole task tree and return the tasks that may wake the machine.
///
/// A scheduler that cannot be reached at all is [`Access::Failed`]. A tree that was only partly
/// readable is [`Access::NeedsAdmin`] with what could be read; see [`TaskScan`].
#[cfg(windows)]
pub fn wake_tasks() -> Sourced<TaskScan> {
    let source = SourceId::ScheduledTasks;
    let com = com::Initialized::new();
    let result = com::scan();
    drop(com);
    match result {
        Err(access) => Sourced::unreadable(source, access),
        Ok((scan, other_failure)) => {
            let access = match (
                other_failure,
                scan.unreadable_folders.is_empty() && scan.unreadable_tasks.is_empty(),
            ) {
                (Some(access), _) => access,
                (None, true) => Access::Ok,
                (None, false) => Access::NeedsAdmin,
            };
            Sourced {
                source,
                access,
                data: vec![scan],
            }
        }
    }
}

#[cfg(windows)]
mod com {
    use pcsleuth_core::Access;
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{ITaskFolder, ITaskService, TaskScheduler};
    use windows::Win32::System::Variant::{VARIANT, VT_I4};
    use windows::core::BSTR;

    use super::{TaskScan, TaskState, WakeTask, ole_date_to_timestamp};
    use crate::power::access_from_hresult;

    /// `TASK_ENUM_HIDDEN`: include hidden tasks in a listing.
    const TASK_ENUM_HIDDEN: i32 = 1;
    const E_ACCESSDENIED: u32 = 0x8007_0005;

    /// COM initialised for the current thread, undone on drop. If the thread already has COM in
    /// another apartment mode that is fine: the objects below work in it.
    pub(super) struct Initialized(bool);

    impl Initialized {
        pub(super) fn new() -> Initialized {
            // SAFETY: plain COM initialisation; the matching CoUninitialize is in Drop.
            Initialized(unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok())
        }
    }

    impl Drop for Initialized {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balances the successful CoInitializeEx in `new`.
                unsafe { CoUninitialize() };
            }
        }
    }

    /// A `VT_I4` variant, the form the 1-based collection indexers take.
    fn index(i: i32) -> VARIANT {
        let mut variant = VARIANT::default();
        // SAFETY: fills the plain-data fields of a zeroed VARIANT with a type that owns nothing.
        unsafe {
            let inner = &mut *variant.Anonymous.Anonymous;
            inner.vt = VT_I4;
            inner.Anonymous.lVal = i;
        }
        variant
    }

    fn denied(e: &windows::core::Error) -> bool {
        e.code().0 as u32 == E_ACCESSDENIED
    }

    /// Returns the scan plus the first failure that was not "access denied", if any.
    pub(super) fn scan() -> Result<(TaskScan, Option<Access>), Access> {
        let tz = jiff::tz::TimeZone::system();
        // SAFETY: standard COM object creation with a valid CLSID.
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| access_from_hresult(e.code().0))?;
        let none = VARIANT::default();
        // SAFETY: four empty VARIANTs mean "this computer, current user".
        unsafe { service.Connect(&none, &none, &none, &none) }
            .map_err(|e| access_from_hresult(e.code().0))?;

        let mut scan = TaskScan {
            elevated: crate::power::is_elevated(),
            ..TaskScan::default()
        };
        let mut other: Option<Access> = None;
        let mut note = |e: &windows::core::Error, other: &mut Option<Access>| {
            if !denied(e) && other.is_none() {
                *other = Some(access_from_hresult(e.code().0));
            }
        };
        let mut pending = vec![String::from("\\")];
        while let Some(path) = pending.pop() {
            // SAFETY: `service` is connected and the path is a valid BSTR.
            let folder: ITaskFolder = match unsafe { service.GetFolder(&BSTR::from(path.as_str())) }
            {
                Ok(folder) => folder,
                Err(e) => {
                    note(&e, &mut other);
                    scan.unreadable_folders.push(path);
                    continue;
                }
            };
            read_tasks(&folder, &path, &tz, &mut scan, &mut other, &mut note);
            // SAFETY: `folder` is a live ITaskFolder.
            match unsafe { folder.GetFolders(0) } {
                Ok(children) => {
                    // SAFETY: `children` is a live collection; items are 1-based.
                    let count = unsafe { children.Count() }.unwrap_or(0);
                    for i in 1..=count {
                        // SAFETY: as above, `i` is within 1..=Count.
                        if let Ok(child) = unsafe { children.get_Item(&index(i)) }
                            && let Ok(child_path) = unsafe { child.Path() }
                        {
                            pending.push(child_path.to_string());
                        }
                    }
                }
                Err(e) => {
                    note(&e, &mut other);
                    scan.unreadable_folders.push(path);
                }
            }
        }
        scan.wake_tasks.sort_by(|a, b| a.path.cmp(&b.path));
        scan.unreadable_folders.sort();
        scan.unreadable_folders.dedup();
        Ok((scan, other))
    }

    fn read_tasks(
        folder: &ITaskFolder,
        path: &str,
        tz: &jiff::tz::TimeZone,
        scan: &mut TaskScan,
        other: &mut Option<Access>,
        note: &mut impl FnMut(&windows::core::Error, &mut Option<Access>),
    ) {
        // SAFETY: `folder` is a live ITaskFolder.
        let tasks = match unsafe { folder.GetTasks(TASK_ENUM_HIDDEN) } {
            Ok(tasks) => tasks,
            Err(e) => {
                note(&e, other);
                scan.unreadable_folders.push(path.to_owned());
                return;
            }
        };
        scan.folders_scanned += 1;
        // SAFETY: `tasks` is a live collection; items are 1-based.
        let count = unsafe { tasks.Count() }.unwrap_or(0);
        for i in 1..=count {
            // SAFETY: `i` is within 1..=Count.
            let Ok(task) = (unsafe { tasks.get_Item(&index(i)) }) else {
                continue;
            };
            // SAFETY: `task` is a live IRegisteredTask.
            let task_path = unsafe { task.Path() }
                .map(|p| p.to_string())
                .unwrap_or_default();
            // SAFETY: as above.
            let wake = unsafe {
                task.Definition().and_then(|d| d.Settings()).and_then(|s| {
                    let mut flag = VARIANT_BOOL(0);
                    s.WakeToRun(&mut flag).map(|()| flag.as_bool())
                })
            };
            let wake = match wake {
                Ok(flag) => flag,
                Err(e) => {
                    note(&e, other);
                    scan.unreadable_tasks.push(task_path);
                    continue;
                }
            };
            scan.tasks_seen += 1;
            if !wake {
                continue;
            }
            // SAFETY: `task` is a live IRegisteredTask; each property read is independent.
            let (enabled, state, next, last) = unsafe {
                (
                    task.Enabled().map(|b| b.as_bool()).unwrap_or(false),
                    task.State().map(|s| s.0).unwrap_or(0),
                    task.NextRunTime().ok(),
                    task.LastRunTime().ok(),
                )
            };
            scan.wake_tasks.push(WakeTask {
                path: task_path,
                enabled,
                state: TaskState::from_raw(state),
                next_run: next.and_then(|d| ole_date_to_timestamp(d, tz)),
                last_run: last.and_then(|d| ole_date_to_timestamp(d, tz)),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn ole_dates_become_timestamps_in_the_given_zone() {
        // 2026-11-03 18:00 local; 46_329 days after 1899-12-30.
        let date = 46_329.75;
        assert_eq!(
            ole_date_to_timestamp(date, &TimeZone::UTC),
            Some(utc("2026-11-03T18:00:00Z"))
        );
        let kyiv = TimeZone::get("Europe/Kyiv").unwrap();
        // UTC+2 in November.
        assert_eq!(
            ole_date_to_timestamp(date, &kyiv),
            Some(utc("2026-11-03T16:00:00Z"))
        );
    }

    #[test]
    fn missing_or_absurd_dates_are_none() {
        for value in [0.0, -1.0, 0.5, f64::NAN, f64::INFINITY, 3_000_000.0] {
            assert_eq!(
                ole_date_to_timestamp(value, &TimeZone::UTC),
                None,
                "{value}"
            );
        }
        // 1899-12-30 + 1 day is the first valid date.
        assert_eq!(
            ole_date_to_timestamp(1.0, &TimeZone::UTC),
            Some(utc("1899-12-31T00:00:00Z"))
        );
    }

    #[test]
    fn task_states() {
        assert_eq!(TaskState::from_raw(1), TaskState::Disabled);
        assert_eq!(TaskState::from_raw(3), TaskState::Ready);
        assert_eq!(TaskState::from_raw(4), TaskState::Running);
        assert_eq!(TaskState::from_raw(2), TaskState::Queued);
        assert_eq!(TaskState::from_raw(0), TaskState::Unknown);
        assert_eq!(TaskState::from_raw(99), TaskState::Unknown);
    }

    /// Live read. Without admin the tree is partly closed, which must show as `NeedsAdmin` with the
    /// readable tasks still present, never as a failure.
    #[cfg(windows)]
    #[test]
    fn live_wake_tasks() {
        let read = wake_tasks();
        assert_eq!(read.source, SourceId::ScheduledTasks);
        assert!(
            matches!(read.access, Access::Ok | Access::NeedsAdmin),
            "{read:?}"
        );
        let scan = &read.data[0];
        assert!(scan.tasks_seen > 0, "{scan:?}");
        assert!(scan.folders_scanned > 0);
        assert!(scan.wake_tasks.iter().all(|t| t.path.starts_with('\\')));
        assert_eq!(
            read.access == Access::Ok,
            scan.unreadable_folders.is_empty() && scan.unreadable_tasks.is_empty()
        );
        eprintln!(
            "tasks: {} folders, {} tasks seen, {} wake, {} unreadable folders, {} unreadable tasks, access {}",
            scan.folders_scanned,
            scan.tasks_seen,
            scan.wake_tasks.len(),
            scan.unreadable_folders.len(),
            scan.unreadable_tasks.len(),
            read.access
        );
        for task in &scan.wake_tasks {
            eprintln!(
                "  wake: {} enabled={} state={:?} next={:?}",
                task.path, task.enabled, task.state, task.next_run
            );
        }
        for folder in &scan.unreadable_folders {
            eprintln!("  unreadable folder: {folder}");
        }
    }
}
