//! Fault: an unhandled exception, so Windows logs Application Error 1000 for this exe.
//! `--delay-ms N` waits before crashing (default 1000, at most 10000). Needs no admin.
//!
//! It raises an access violation (0xC0000005) with `RaiseException` and installs no handler, so
//! the default unhandled-exception path runs: Windows Error Reporting, then process exit. A Rust
//! `abort` was not used; it ends in a different exception code.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::time::Duration;

    use pcsleuth_eval::fault;
    use windows::Win32::System::Diagnostics::Debug::{RaiseException, SEM_ALL_ERRORS, SetErrorMode};

    const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
    const EXCEPTION_NONCONTINUABLE: u32 = 1;

    // A parent such as a shell or a CI agent often passes down SEM_NOGPFAULTERRORBOX (seen here:
    // the inherited mode was 3), and then Windows does not report the crash at all. Clear it for
    // this process only.
    // SAFETY: sets this process's own error mode.
    unsafe { SetErrorMode(SEM_ALL_ERRORS) };
    fault::ready();
    std::thread::sleep(Duration::from_millis(fault::number("--delay-ms", 1000, 0, 10_000)));
    // SAFETY: raising an exception is the point; nothing continues afterwards.
    unsafe { RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE, None) };
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    pcsleuth_eval::fault::unsupported()
}
