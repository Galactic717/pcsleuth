//! Scheduled tasks that may wake the machine, read through the Task Scheduler COM API
//! (`ITaskService`) and not through the Task Scheduler event log, which is another package's job.
//!
//! A task wakes the computer only when its settings have `WakeToRun` on. Without admin the API
//! shows only part of the task tree. That is reported as data: [`TaskScan`] names every folder and
//! task it could not open or read, and the read's access says how far to trust the list:
//!
//! 1. any folder or task denied: [`Access::NeedsAdmin`], with what could be read still in `data`;
//! 2. otherwise any other failure while walking (a task deleted mid-scan, a broken collection):
//!    [`Access::Failed`], again with what could be read;
//! 3. otherwise, when the scan ran unelevated: [`Access::NeedsAdmin`]. Nothing was denied, but a
//!    task hidden from this user by its permissions is simply not listed, and nothing can count
//!    what is not listed, so "no wake tasks" is not a complete answer;
//! 4. otherwise [`Access::Ok`].

use jiff::Timestamp;
use jiff::civil::date;
use jiff::tz::TimeZone;
use pcsleuth_core::Access;
#[cfg(windows)]
use pcsleuth_core::{SourceId, Sourced};

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
    /// The task's own switch. A disabled task never wakes anything. `None` when it could not be
    /// read, which is also listed in [`TaskScan::unreadable_tasks`].
    pub enabled: Option<bool>,
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
    /// Tasks with `WakeToRun` set, in path order.
    pub wake_tasks: Vec<WakeTask>,
    /// Task folders opened and listed.
    pub folders_scanned: u32,
    /// Tasks whose settings were read, wake or not.
    pub tasks_seen: u32,
    /// Folders, or parts of a folder (its subfolder list, its task list), that could not be read.
    /// Whatever was behind them is not in the counts.
    pub unreadable_folders: Vec<String>,
    /// Tasks that could not be read, or whose state could not be read. A name here may also be in
    /// `wake_tasks`, with the unreadable field left unknown.
    pub unreadable_tasks: Vec<String>,
}

/// What went wrong during a walk, kept apart so that "denied" can outrank everything else.
#[derive(Debug, Default)]
#[cfg_attr(not(windows), allow(dead_code))]
struct Problems {
    denied: bool,
    other: Option<Access>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl Problems {
    const E_ACCESSDENIED: u32 = 0x8007_0005;

    /// Record a failed COM call. Access denied is remembered as such; any other `HRESULT` is kept
    /// as a plain failure, the first one only. A task-level error is never "missing": a task that
    /// disappeared mid-scan says nothing about whether the scheduler exists.
    fn note(&mut self, code: u32, message: String) {
        if code == Self::E_ACCESSDENIED {
            self.denied = true;
        } else if self.other.is_none() {
            self.other = Some(Access::Failed { code, message });
        }
    }

    /// The access for the whole read, by the order in the module documentation.
    fn access(self, elevated: bool) -> Access {
        if self.denied {
            Access::NeedsAdmin
        } else if let Some(other) = self.other {
            other
        } else if !elevated {
            Access::NeedsAdmin
        } else {
            Access::Ok
        }
    }
}

/// An OLE automation `DATE` (days since 1899-12-30, local time) as a timestamp in `tz`.
///
/// The Task Scheduler returns 0 when a time does not exist (a task that never ran); that and any
/// value that is not a plausible date give `None`.
pub fn ole_date_to_timestamp(value: f64, tz: &TimeZone) -> Option<Timestamp> {
    if !value.is_finite() || !(1.0..=2_958_465.0).contains(&value) {
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
/// A scheduler that cannot be reached at all is unreadable. Otherwise the access follows the order
/// in the module documentation, and `data` holds one [`TaskScan`] with whatever could be read.
#[cfg(windows)]
pub fn wake_tasks() -> Sourced<TaskScan> {
    let source = SourceId::ScheduledTasks;
    let com = com::Initialized::new();
    let result = com::scan();
    drop(com);
    match result {
        Err(access) => Sourced::unreadable(source, access),
        Ok((scan, problems)) => Sourced {
            source,
            access: problems.access(scan.elevated),
            data: vec![scan],
        },
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

    use super::{Problems, TaskScan, TaskState, WakeTask, ole_date_to_timestamp};
    use crate::power::access_from_hresult;

    /// `TASK_ENUM_HIDDEN`: include hidden tasks in a listing.
    const TASK_ENUM_HIDDEN: i32 = 1;

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

    impl Problems {
        fn fail(&mut self, e: &windows::core::Error) {
            self.note(e.code().0 as u32, e.message());
        }
    }

    /// Walk the tree. An `Err` means the scheduler itself could not be reached; everything else is
    /// recorded in the scan and in the returned [`Problems`].
    pub(super) fn scan() -> Result<(TaskScan, Problems), Access> {
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
        let mut problems = Problems::default();
        let mut pending = vec![String::from("\\")];
        while let Some(path) = pending.pop() {
            // SAFETY: `service` is connected and the path is a valid BSTR.
            let folder: ITaskFolder = match unsafe { service.GetFolder(&BSTR::from(path.as_str())) }
            {
                Ok(folder) => folder,
                Err(e) => {
                    problems.fail(&e);
                    scan.unreadable_folders.push(path);
                    continue;
                }
            };
            read_tasks(&folder, &path, &tz, &mut scan, &mut problems);
            // SAFETY: `folder` is a live ITaskFolder.
            let children = match unsafe { folder.GetFolders(0) } {
                Ok(children) => children,
                Err(e) => {
                    problems.fail(&e);
                    scan.unreadable_folders.push(format!("{path} (subfolders)"));
                    continue;
                }
            };
            // SAFETY: `children` is a live collection; items are 1-based.
            let count = match unsafe { children.Count() } {
                Ok(count) => count,
                Err(e) => {
                    problems.fail(&e);
                    scan.unreadable_folders.push(format!("{path} (subfolders)"));
                    continue;
                }
            };
            for i in 1..=count {
                // SAFETY: `i` is within 1..=Count and the child is a live ITaskFolder.
                let child_path =
                    unsafe { children.get_Item(&index(i)).and_then(|child| child.Path()) };
                match child_path {
                    Ok(child_path) => pending.push(child_path.to_string()),
                    Err(e) => {
                        problems.fail(&e);
                        scan.unreadable_folders
                            .push(format!("{path} (subfolder {i})"));
                    }
                }
            }
        }
        scan.wake_tasks.sort_by(|a, b| a.path.cmp(&b.path));
        scan.unreadable_folders.sort();
        scan.unreadable_folders.dedup();
        Ok((scan, problems))
    }

    fn read_tasks(
        folder: &ITaskFolder,
        path: &str,
        tz: &jiff::tz::TimeZone,
        scan: &mut TaskScan,
        problems: &mut Problems,
    ) {
        // SAFETY: `folder` is a live ITaskFolder.
        let tasks = match unsafe { folder.GetTasks(TASK_ENUM_HIDDEN) } {
            Ok(tasks) => tasks,
            Err(e) => {
                problems.fail(&e);
                scan.unreadable_folders.push(path.to_owned());
                return;
            }
        };
        // SAFETY: `tasks` is a live collection; items are 1-based.
        let count = match unsafe { tasks.Count() } {
            Ok(count) => count,
            Err(e) => {
                problems.fail(&e);
                scan.unreadable_folders.push(format!("{path} (tasks)"));
                return;
            }
        };
        scan.folders_scanned += 1;
        for i in 1..=count {
            // SAFETY: `i` is within 1..=Count.
            let task = match unsafe { tasks.get_Item(&index(i)) } {
                Ok(task) => task,
                Err(e) => {
                    problems.fail(&e);
                    scan.unreadable_tasks.push(format!("{path} (task {i})"));
                    continue;
                }
            };
            // SAFETY: `task` is a live IRegisteredTask.
            let task_path = match unsafe { task.Path() } {
                Ok(task_path) => task_path.to_string(),
                Err(e) => {
                    problems.fail(&e);
                    scan.unreadable_tasks.push(format!("{path} (task {i})"));
                    continue;
                }
            };
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
                    problems.fail(&e);
                    scan.unreadable_tasks.push(task_path);
                    continue;
                }
            };
            scan.tasks_seen += 1;
            if !wake {
                continue;
            }
            // SAFETY: `task` is a live IRegisteredTask; each property read is independent.
            let enabled = match unsafe { task.Enabled() } {
                Ok(flag) => Some(flag.as_bool()),
                Err(e) => {
                    problems.fail(&e);
                    scan.unreadable_tasks
                        .push(format!("{task_path} (enabled state)"));
                    None
                }
            };
            // SAFETY: as above. An unreadable state or time stays unknown, which the types allow.
            let (state, next, last) = unsafe {
                (
                    task.State().map_or(0, |s| s.0),
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

    const DENIED: u32 = 0x8007_0005;
    const NOT_FOUND: u32 = 0x8007_0002;

    fn problems(codes: &[u32]) -> Problems {
        let mut p = Problems::default();
        for code in codes {
            p.note(*code, format!("code {code:#x}"));
        }
        p
    }

    #[test]
    fn an_elevated_clean_scan_is_ok() {
        assert_eq!(problems(&[]).access(true), Access::Ok);
    }

    #[test]
    fn an_unelevated_clean_scan_is_still_not_complete() {
        // Nothing was denied, but permission-hidden tasks are invisible, so it cannot say "none".
        assert_eq!(problems(&[]).access(false), Access::NeedsAdmin);
    }

    #[test]
    fn denied_wins_over_every_other_failure() {
        for elevated in [false, true] {
            assert_eq!(
                problems(&[NOT_FOUND, DENIED]).access(elevated),
                Access::NeedsAdmin
            );
            assert_eq!(
                problems(&[DENIED, NOT_FOUND]).access(elevated),
                Access::NeedsAdmin
            );
        }
    }

    #[test]
    fn a_vanished_task_is_a_failure_never_missing() {
        // 0x80070002 is ERROR_FILE_NOT_FOUND. As a task-level error it must not make the whole
        // source "missing"; it is a plain failure, whether or not the scan was elevated.
        for elevated in [false, true] {
            assert_eq!(
                problems(&[NOT_FOUND]).access(elevated),
                Access::Failed {
                    code: NOT_FOUND,
                    message: "code 0x80070002".into()
                }
            );
        }
    }

    #[test]
    fn the_first_non_denied_failure_is_the_one_reported() {
        let access = problems(&[NOT_FOUND, 0x8000_4005]).access(true);
        assert!(matches!(
            access,
            Access::Failed {
                code: NOT_FOUND,
                ..
            }
        ));
    }

    /// Live read. The tree may be partly closed or a task may vanish mid-scan; both must come back
    /// as typed access with the readable tasks still present. Unelevated, a scan is never `Ok`.
    #[cfg(windows)]
    #[test]
    fn live_wake_tasks() {
        let read = wake_tasks();
        assert_eq!(read.source, SourceId::ScheduledTasks);
        let scan = &read.data[0];
        let unreadable = !scan.unreadable_folders.is_empty() || !scan.unreadable_tasks.is_empty();
        match &read.access {
            Access::Ok => assert!(scan.elevated && !unreadable, "{read:?}"),
            Access::NeedsAdmin => {}
            Access::Failed { .. } => assert!(unreadable, "{read:?}"),
            other => panic!("unexpected {other}"),
        }
        if !scan.elevated {
            assert!(matches!(
                read.access,
                Access::NeedsAdmin | Access::Failed { .. }
            ));
        }
        assert!(scan.tasks_seen > 0, "{scan:?}");
        assert!(scan.folders_scanned > 0);
        assert!(scan.wake_tasks.iter().all(|t| t.path.starts_with('\\')));
        eprintln!(
            "tasks: {} folders, {} tasks seen, {} wake, {} unreadable folders, {} unreadable tasks, elevated {}, access {}",
            scan.folders_scanned,
            scan.tasks_seen,
            scan.wake_tasks.len(),
            scan.unreadable_folders.len(),
            scan.unreadable_tasks.len(),
            scan.elevated,
            read.access
        );
        for task in &scan.wake_tasks {
            eprintln!(
                "  wake: {} enabled={:?} state={:?} next={:?}",
                task.path, task.enabled, task.state, task.next_run
            );
        }
        for folder in &scan.unreadable_folders {
            eprintln!("  unreadable folder: {folder}");
        }
    }
}
