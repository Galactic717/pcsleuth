//! Fault: arms a waitable timer that may wake the machine from sleep, far in the future, so it
//! never wakes anything during an evaluation. `--secs N` bounds the process (default 30, at most
//! 600); closing the timer cancels it. Needs no admin, changes no setting.
//!
//! `--fire-in N` sets the timer N seconds ahead instead (at most 7 days). Only the sleep
//! scenarios use it, because only they want the machine to wake.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use pcsleuth_eval::fault;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_NOT_SUPPORTED, GetLastError, SetLastError, WIN32_ERROR,
    };
    use windows::Win32::System::Threading::{
        CancelWaitableTimer, CreateWaitableTimerW, SetWaitableTimer,
    };

    const WEEK: u64 = 7 * 24 * 3600;
    const TICKS_PER_SEC: i64 = 10_000_000;

    let run = fault::start(30);
    let ahead = fault::number("--fire-in", WEEK, 1, WEEK) as i64;
    // A negative due time is relative to now, in 100 ns ticks.
    let due = -(ahead * TICKS_PER_SEC);
    // SAFETY: `due` outlives the call; the handle is closed below.
    unsafe {
        let timer = match CreateWaitableTimerW(None, true, None) {
            Ok(timer) => timer,
            Err(error) => return fault::fail(error),
        };
        SetLastError(WIN32_ERROR(0));
        if let Err(error) = SetWaitableTimer(timer, &due, 0, None, None, true) {
            let _ = CloseHandle(timer);
            return fault::fail(error);
        }
        // With a resume timer, success plus ERROR_NOT_SUPPORTED means the PC cannot be woken.
        if GetLastError() == ERROR_NOT_SUPPORTED {
            let _ = CloseHandle(timer);
            return fault::fail("this PC does not support timers that resume it from sleep");
        }
        fault::ready();
        run.hold();
        let _ = CancelWaitableTimer(timer);
        let _ = CloseHandle(timer);
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    pcsleuth_eval::fault::unsupported()
}
