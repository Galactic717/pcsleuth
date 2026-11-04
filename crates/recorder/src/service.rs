//! The Windows service: register it, remove it, and run as it.
//!
//! Nothing here runs unless the user types `pcsleuth-recorder install` in an elevated prompt. The
//! service runs as LocalSystem, which is what lets it see power request owners. It is installed for
//! manual start unless `--auto-start` is given, and it is never installed by anything else.
//!
//! None of this can be exercised without administrator rights. The `elevated_*` tests in
//! `tests/elevated.rs` do, and are ignored by default.

use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use windows::Win32::Storage::FileSystem::DELETE;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW, SC_HANDLE,
    SC_MANAGER_ALL_ACCESS, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};

use crate::ring::{DEFAULT_BYTES, RingWriter};
use crate::runner::{self, Live};
use crate::{service_ring_path, winapi};

/// The service's name, as `sc query` shows it.
pub const SERVICE_NAME: &str = "pcsleuth-recorder";
const DISPLAY_NAME: &str = "pcsleuth recorder";
const DESCRIPTION: &str = "Records the busiest processes and power requests into a fixed-size \
    file for pcsleuth. Optional; remove it with pcsleuth-recorder uninstall.";

/// Win32 error codes the code below tells apart.
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
const ERROR_SERVICE_EXISTS: u32 = 1073;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;
const NO_ERROR: u32 = 0;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// How the service starts after install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartType {
    /// Only when someone starts it (`sc start pcsleuth-recorder`). The default.
    Manual,
    /// At boot.
    Auto,
}

/// Why a service operation failed, with the Win32 code when there is one.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("the service {SERVICE_NAME} is already installed; run uninstall first")]
    AlreadyInstalled,
    #[error(
        "run-service is the entry point the Service Control Manager starts; to record from a \
         terminal use --foreground"
    )]
    NotStartedByScm,
    #[error(
        "refusing to install from {exe}.\n\
         The service runs as SYSTEM, so its program file must be somewhere only administrators can \
         change, or any program running as you could overwrite it and be started as SYSTEM.\n\
         Copy pcsleuth-recorder.exe into a folder under {program_files} (for example \
         {program_files}\\pcsleuth\\) from an elevated prompt, then run install from that copy."
    )]
    UnsafeLocation { exe: String, program_files: String },
    #[error("{what}: {source}")]
    Os {
        what: &'static str,
        source: io::Error,
    },
}

fn os(what: &'static str) -> impl FnOnce(windows::core::Error) -> ServiceError {
    move |e| ServiceError::Os {
        what,
        source: io::Error::from_raw_os_error(win32_code(&e) as i32),
    }
}

/// The Win32 error behind a `windows` error (an `HRESULT` of the form `0x8007xxxx`).
fn win32_code(e: &windows::core::Error) -> u32 {
    let hr = e.code().0 as u32;
    if hr >> 16 == 0x8007 { hr & 0xFFFF } else { hr }
}

/// Closes a service control manager or service handle when dropped.
struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW, OpenServiceW or CreateServiceW and is closed once.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_manager() -> Result<Handle, ServiceError> {
    // SAFETY: null machine and database names mean the local active database.
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) }
        .map(Handle)
        .map_err(os("could not open the service control manager"))
}

/// The command line the service runs: this executable, quoted, with its arguments.
pub fn service_command_line(exe: &Path, interval_secs: u32) -> String {
    format!(
        "\"{}\" run-service --interval {interval_secs}",
        exe.display()
    )
}

/// The executable's real path if it is inside `C:\Program Files` (found with the shell's known
/// folder, not an environment variable), else [`ServiceError::UnsafeLocation`].
///
/// Both paths are resolved first, so a junction or link out of Program Files, `..`, and a change of
/// case do not get past it. It does not look at the permissions of the folders in between: it
/// relies on Program Files being writable only by administrators, which is Windows' default.
pub fn check_install_location(exe: &Path) -> Result<PathBuf, ServiceError> {
    let program_files = winapi::program_files_dir().map_err(|source| ServiceError::Os {
        what: "could not find the Program Files folder",
        source,
    })?;
    let real = |path: &Path| {
        std::fs::canonicalize(path).map_err(|source| ServiceError::Os {
            what: "could not resolve a path",
            source,
        })
    };
    let (exe_real, root) = (real(exe)?, real(&program_files)?);
    if winapi::path_is_under(&exe_real, &root) {
        Ok(winapi::strip_verbatim(&exe_real))
    } else {
        Err(ServiceError::UnsafeLocation {
            exe: winapi::strip_verbatim(&exe_real).display().to_string(),
            program_files: winapi::strip_verbatim(&root).display().to_string(),
        })
    }
}

/// What `install` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub folder: PathBuf,
    pub ring: PathBuf,
    pub start: StartType,
}

/// Register the service and create its protected data folder. The caller must be elevated; this
/// does not check, so that a refusal can be worded by the caller.
///
/// The service is not started. The folder is created first, with permissions for SYSTEM,
/// Administrators and the installing user only, so the ring never exists in a readable place.
pub fn install(
    exe: &Path,
    start: StartType,
    interval_secs: u32,
) -> Result<Installed, ServiceError> {
    // Before anything is touched: a program file anyone can replace would run as SYSTEM.
    let exe = check_install_location(exe)?;
    let exe = exe.as_path();
    let ring = service_ring_path();
    let folder = ring
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let sid = winapi::current_user_sid().map_err(|source| ServiceError::Os {
        what: "could not read the installing user",
        source,
    })?;
    winapi::create_protected_dir(&folder, &sid).map_err(|source| ServiceError::Os {
        what: "could not create the protected data folder",
        source,
    })?;

    let manager = open_manager()?;
    let command = HSTRING::from(service_command_line(exe, interval_secs));
    // SAFETY: every string is a valid nul-terminated HSTRING alive for the call; the optional
    // arguments are null, meaning no load order group, tag, dependencies, account or password
    // (so the service runs as LocalSystem).
    let created = unsafe {
        CreateServiceW(
            manager.0,
            &HSTRING::from(SERVICE_NAME),
            &HSTRING::from(DISPLAY_NAME),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            match start {
                StartType::Manual => SERVICE_DEMAND_START,
                StartType::Auto => SERVICE_AUTO_START,
            },
            SERVICE_ERROR_NORMAL,
            &command,
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };
    let service = match created {
        Ok(handle) => Handle(handle),
        Err(e) if win32_code(&e) == ERROR_SERVICE_EXISTS => {
            return Err(ServiceError::AlreadyInstalled);
        }
        Err(e) => return Err(os("could not create the service")(e)),
    };
    let mut text = winapi::wide(DESCRIPTION);
    let description = SERVICE_DESCRIPTIONW {
        lpDescription: PWSTR(text.as_mut_ptr()),
    };
    // SAFETY: `service` is open and `description` points at a nul-terminated string, both alive for
    // the call. The description is cosmetic, so a failure is ignored.
    let _ = unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some(std::ptr::from_ref(&description).cast::<c_void>()),
        )
    };
    Ok(Installed {
        folder,
        ring,
        start,
    })
}

/// What `uninstall` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uninstalled {
    /// False when the service was not registered.
    pub service_removed: bool,
    pub ring_removed: bool,
    pub folder_removed: bool,
}

/// Stop and remove the service, then delete the ring and its folder. The caller must be elevated.
/// Missing pieces are not errors: running it twice is fine.
pub fn uninstall() -> Result<Uninstalled, ServiceError> {
    let manager = open_manager()?;
    // SAFETY: `manager` is open and the name is a valid HSTRING.
    let opened = unsafe {
        OpenServiceW(
            manager.0,
            &HSTRING::from(SERVICE_NAME),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE.0,
        )
    };
    let service_removed = match opened {
        Ok(handle) => {
            let service = Handle(handle);
            stop_and_wait(&service, Duration::from_secs(20));
            // SAFETY: `service` is open with DELETE access.
            unsafe { DeleteService(service.0) }.map_err(os("could not delete the service"))?;
            true
        }
        Err(e) if win32_code(&e) == ERROR_SERVICE_DOES_NOT_EXIST => false,
        Err(e) => return Err(os("could not open the service")(e)),
    };
    let ring = service_ring_path();
    let ring_removed = match std::fs::remove_file(&ring) {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(ServiceError::Os {
                what: "could not delete the ring file",
                source,
            });
        }
    };
    // The folder goes only if nothing else is in it.
    let folder_removed = ring
        .parent()
        .is_some_and(|folder| std::fs::remove_dir(folder).is_ok());
    Ok(Uninstalled {
        service_removed,
        ring_removed,
        folder_removed,
    })
}

/// Ask the service to stop and wait up to `limit` for it to. A service that is not running, or
/// does not stop in time, is left for `DeleteService`, which marks it for removal.
fn stop_and_wait(service: &Handle, limit: Duration) {
    let mut status = SERVICE_STATUS::default();
    // SAFETY: `service` is open with stop access and `status` is a valid out-pointer.
    if let Err(e) = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) }
        && win32_code(&e) == ERROR_SERVICE_NOT_ACTIVE
    {
        return;
    }
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        // SAFETY: `service` is open with query access and `status` is a valid out-pointer.
        let queried = unsafe { QueryServiceStatus(service.0, &mut status) };
        if queried.is_err() || status.dwCurrentState == SERVICE_STOPPED {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Settings the service entry point reads, set once by [`run`] before the dispatcher starts.
static SETTINGS: OnceLock<(Duration, PathBuf)> = OnceLock::new();
/// The handle `RegisterServiceCtrlHandlerExW` returned, as an integer so a static can hold it.
static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);

/// Connect to the Service Control Manager and record until it says stop. Blocks until the service
/// has stopped. Run from a terminal it fails with [`ServiceError::NotStartedByScm`].
pub fn run(interval: Duration, ring: PathBuf) -> Result<(), ServiceError> {
    let _ = SETTINGS.set((interval, ring));
    let mut name = winapi::wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: `table` is a terminated array and `name` outlives the call, which returns only when
    // the service has stopped.
    match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        Ok(()) => Ok(()),
        Err(e) if win32_code(&e) == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT => {
            Err(ServiceError::NotStartedByScm)
        }
        Err(e) => Err(os("could not connect to the service control manager")(e)),
    }
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32, wait_hint_ms: u32) {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and stays valid until the service
    // has reported SERVICE_STOPPED; `status` is a valid SERVICE_STATUS.
    let _ = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(raw as *mut c_void), &status) };
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report(SERVICE_STOP_PENDING, NO_ERROR, 10_000);
            runner::request_stop();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    // SAFETY: the name is a valid HSTRING and `control_handler` has the signature Windows expects.
    let registered = unsafe {
        RegisterServiceCtrlHandlerExW(&HSTRING::from(SERVICE_NAME), Some(control_handler), None)
    };
    let Ok(handle) = registered else { return };
    STATUS_HANDLE.store(handle.0 as usize, Ordering::SeqCst);
    // The stop channel exists before the service reports running, so an early stop is not lost.
    let stop = runner::stop_channel();
    report(SERVICE_START_PENDING, NO_ERROR, 5_000);

    let Some((interval, ring_path)) = SETTINGS.get() else {
        report(SERVICE_STOPPED, ERROR_CALL_NOT_IMPLEMENTED, 0);
        return;
    };
    let mut ring = match RingWriter::open(
        ring_path,
        DEFAULT_BYTES,
        u32::try_from(interval.as_secs()).unwrap_or(u32::MAX),
    ) {
        Ok(ring) => ring,
        Err(e) => {
            let code = match &e {
                crate::ring::RingError::Io(io) => io.raw_os_error().unwrap_or(1) as u32,
                _ => 13, // ERROR_INVALID_DATA: the file in the way is not our ring
            };
            report(SERVICE_STOPPED, code, 0);
            return;
        }
    };
    report(SERVICE_RUNNING, NO_ERROR, 0);
    // Best effort: the service still works, only at normal priority, if this fails.
    let _ = winapi::lower_thread_priority();
    let mut live = Live::start();
    let stats = runner::run(&mut ring, *interval, &stop, None, || live.tick(), |_| {});
    // If it gave up because nothing could be recorded, stop with that error code instead of
    // staying Running. `sc query pcsleuth-recorder` shows it as WIN32_EXIT_CODE, and the Service
    // Control Manager logs it.
    report(SERVICE_STOPPED, stats.failed.unwrap_or(NO_ERROR), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_command_line_quotes_the_path_and_carries_the_interval() {
        let line = service_command_line(
            Path::new(r"C:\Program Files\pcsleuth\pcsleuth-recorder.exe"),
            30,
        );
        assert_eq!(
            line,
            r#""C:\Program Files\pcsleuth\pcsleuth-recorder.exe" run-service --interval 30"#
        );
    }

    #[test]
    fn a_program_outside_program_files_is_refused_before_anything_is_touched() {
        // This test binary lives in a build folder, which any program running as the user can write.
        let exe = std::env::current_exe().unwrap();
        match check_install_location(&exe) {
            Err(ServiceError::UnsafeLocation { program_files, .. }) => {
                assert!(program_files.to_lowercase().contains("program files"));
            }
            other => panic!("{other:?}"),
        }
        // `install` refuses the same way, and does so before the folder or the service manager is
        // reached, so this is safe to run without admin rights.
        let refused = install(&exe, StartType::Manual, 60);
        assert!(
            matches!(refused, Err(ServiceError::UnsafeLocation { .. })),
            "{refused:?}"
        );
        let message = refused.unwrap_err().to_string();
        assert!(message.contains("Copy pcsleuth-recorder.exe"), "{message}");
    }

    #[test]
    fn win32_errors_are_told_apart_from_other_hresults() {
        let win32 =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x8007_0431u32 as i32));
        assert_eq!(win32_code(&win32), ERROR_SERVICE_EXISTS);
        let other =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x8000_4005u32 as i32));
        assert_eq!(win32_code(&other), 0x8000_4005);
    }

    #[test]
    fn run_from_a_terminal_is_refused_with_the_reason() {
        // No Service Control Manager started this test, so the dispatcher cannot connect.
        let refused = run(Duration::from_secs(60), PathBuf::from("unused.ring"));
        assert!(
            matches!(refused, Err(ServiceError::NotStartedByScm)),
            "{refused:?}"
        );
    }
}
