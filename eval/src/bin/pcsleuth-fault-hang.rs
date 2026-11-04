//! Fault: a visible window whose thread stops pumping messages, so Windows treats it as not
//! responding. `--secs N` bounds the process (default 60, at most 600). Needs no admin.
//!
//! What was found on Windows 11 build 26300 (details in docs/EVAL.md): a window left hung for
//! 90 s with nobody present produced no Application Hang 1002. Windows logs 1002 when a person
//! closes the not-responding window. So, once Windows itself says the window is hung
//! (`IsHungAppWindow`), a helper thread calls `WerReportHang` on it, the same API the shell's
//! close path uses. WER then writes a real 1002 for this exe and ends the process. The event is
//! genuine; its trigger is synthetic, and its `HangType` reads `Unknown`.
//!
//! `--no-report` leaves it a plain hang that is never reported, until the time bound ends it.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::time::Duration;

    use pcsleuth_eval::fault;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::Diagnostics::Debug::{SEM_ALL_ERRORS, SetErrorMode};
    use windows::Win32::System::ErrorReporting::WerReportHang;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, IsHungAppWindow, MSG,
        PM_REMOVE, PeekMessageW, RegisterClassW, TranslateMessage, WINDOW_EX_STYLE, WNDCLASSW,
        WS_OVERLAPPEDWINDOW, WS_VISIBLE,
    };
    use windows::core::w;

    unsafe extern "system" fn window_proc(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        // SAFETY: forwards the arguments Windows gave us.
        unsafe { DefWindowProcW(window, message, wparam, lparam) }
    }

    let run = fault::start(60);
    let report = !std::env::args().any(|arg| arg == "--no-report");
    // SAFETY: standard window creation; the class name and title are static.
    unsafe {
        // Same reason as in the crash injector: an inherited mode can suppress the report.
        SetErrorMode(SEM_ALL_ERRORS);
        let instance = match GetModuleHandleW(None) {
            Ok(module) => module.into(),
            Err(error) => return fault::fail(error),
        };
        let class = w!("PcsleuthFaultHang");
        let class_info = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class,
            ..Default::default()
        };
        if RegisterClassW(&class_info) == 0 {
            return fault::fail("could not register the window class");
        }
        let window = match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            w!("pcsleuth hang fault"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            200,
            200,
            360,
            120,
            None,
            None,
            Some(instance),
            None,
        ) {
            Ok(window) => window,
            Err(error) => return fault::fail(error),
        };

        // Let the window finish being created and shown, then never pump again.
        let mut message = MSG::default();
        for _ in 0..50 {
            while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        fault::ready();

        if report {
            // The window handle crosses threads as a number; Windows allows it.
            let raw = window.0 as isize;
            std::thread::spawn(move || {
                let window = HWND(raw as *mut std::ffi::c_void);
                for _ in 0..300 {
                    if IsHungAppWindow(window).as_bool() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                let _ = WerReportHang(window, w!("pcsleuth-fault-hang.exe"));
            });
        }
        run.hold();
        let _ = DestroyWindow(window);
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    pcsleuth_eval::fault::unsupported()
}
