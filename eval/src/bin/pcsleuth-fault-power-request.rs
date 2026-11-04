//! Fault: holds a system-required power request, which blocks idle sleep, then clears it.
//! `--secs N` (default 30, at most 600). Needs no admin, changes no setting; Windows also drops
//! the request when this process exits.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use pcsleuth_eval::fault;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Power::{
        PowerClearRequest, PowerCreateRequest, PowerRequestSystemRequired, PowerSetRequest,
    };
    use windows::Win32::System::Threading::{
        POWER_REQUEST_CONTEXT_SIMPLE_STRING, REASON_CONTEXT, REASON_CONTEXT_0,
    };
    use windows::core::{PWSTR, w};

    let run = fault::start(30);
    let context = REASON_CONTEXT {
        Version: 0,
        Flags: POWER_REQUEST_CONTEXT_SIMPLE_STRING,
        Reason: REASON_CONTEXT_0 {
            SimpleReasonString: PWSTR(w!("pcsleuth evaluation fault: power request").0.cast_mut()),
        },
    };
    // SAFETY: `context` and the reason string outlive the call; the handle is closed below.
    unsafe {
        let request = match PowerCreateRequest(&context) {
            Ok(request) => request,
            Err(error) => return fault::fail(error),
        };
        if let Err(error) = PowerSetRequest(request, PowerRequestSystemRequired) {
            let _ = CloseHandle(request);
            return fault::fail(error);
        }
        fault::ready();
        run.hold();
        let _ = PowerClearRequest(request, PowerRequestSystemRequired);
        let _ = CloseHandle(request);
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    pcsleuth_eval::fault::unsupported()
}
