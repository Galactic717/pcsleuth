//! The few OS calls the harness itself makes. The injectors keep their own Win32 calls in
//! their own files so each one reads as the fault it creates.

use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// True once Ctrl+C, Ctrl+Break or a console close was seen. Every wait loop polls this, so the
/// owner unwinds and its guards clean up instead of the process dying mid-scenario.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

#[cfg(windows)]
pub use win::*;

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use std::sync::atomic::Ordering;

    use anyhow::Result;
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows::Win32::System::Power::SetSuspendState;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::BOOL;

    use super::INTERRUPTED;

    unsafe extern "system" fn on_ctrl(_kind: u32) -> BOOL {
        INTERRUPTED.store(true, Ordering::Relaxed);
        // Handled: do not let the default handler end the process before the guards run.
        BOOL(1)
    }

    pub fn install_ctrl_handler() {
        // SAFETY: `on_ctrl` only touches an atomic.
        unsafe {
            let _ = SetConsoleCtrlHandler(Some(on_ctrl), true);
        }
    }

    /// Is this process running with an elevated token?
    pub fn is_elevated() -> bool {
        // SAFETY: the token handle is opened and closed here; the buffer matches its length.
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned = 0u32;
            let read = GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            let _ = CloseHandle(token);
            read.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    /// `major.minor.build` from `RtlGetVersion`, which unlike `GetVersionEx` does not lie.
    pub fn os_build() -> String {
        let mut info = OSVERSIONINFOW {
            dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        // SAFETY: `info` is a valid, correctly sized OSVERSIONINFOW.
        let status = unsafe { RtlGetVersion(&mut info) };
        if status.0 != 0 {
            return "unknown".to_owned();
        }
        format!(
            "{}.{}.{}",
            info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
        )
    }

    /// Put the machine to sleep, or hibernate. Only the `--sleep` path calls this.
    pub fn suspend(hibernate: bool) -> bool {
        // SAFETY: plain call, no pointers.
        unsafe { SetSuspendState(hibernate, false, false) }
    }

    /// A job object whose processes are all killed when the last handle closes, so injected
    /// processes die with the runner however the runner ends: panic, Ctrl+C or a hard kill.
    pub struct Job(HANDLE);

    impl Job {
        pub fn new() -> Result<Job> {
            // SAFETY: the structure is zeroed, then one flag is set, and its size is passed.
            unsafe {
                let job = CreateJobObjectW(None, None)?;
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )?;
                Ok(Job(job))
            }
        }

        pub fn assign(&self, child: &Child) -> Result<()> {
            // SAFETY: both handles are live for the call.
            unsafe { AssignProcessToJobObject(self.0, HANDLE(child.as_raw_handle()))? };
            Ok(())
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: the handle is owned by this value.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
pub use other::*;

#[cfg(not(windows))]
mod other {
    use std::process::Child;

    use anyhow::{Result, bail};

    pub fn install_ctrl_handler() {}

    pub fn is_elevated() -> bool {
        false
    }

    pub fn os_build() -> String {
        std::env::consts::OS.to_owned()
    }

    pub fn suspend(_hibernate: bool) -> bool {
        false
    }

    pub struct Job;

    impl Job {
        pub fn new() -> Result<Job> {
            bail!("the evaluation harness runs on Windows only")
        }

        pub fn assign(&self, _child: &Child) -> Result<()> {
            Ok(())
        }
    }
}
