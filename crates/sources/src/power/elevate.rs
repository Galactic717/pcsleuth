//! Elevation per ADR 0003: run unelevated, and relaunch the same command once through UAC when the
//! user asks. The elevated copy writes its JSON to a file the parent reads and deletes.
//!
//! Quoting is pure and tested everywhere. The UAC path is never called from a test: it needs a
//! person to click the prompt.

use std::fmt;

/// The argument that tells the elevated copy where to write its output. [`relaunch_elevated`]
/// appends it to the arguments it is given, followed by the path, so the command line must accept
/// `--out-file <path>`.
pub const OUT_FILE_ARG: &str = "--out-file";

/// Quote one argument so `CommandLineToArgvW` and the C runtime read it back unchanged.
///
/// Rules (Microsoft, "Parsing C command-line arguments"): wrap in quotes when the argument is empty
/// or holds a space, tab, newline or quote; double every run of backslashes that precedes a quote
/// or the closing quote; escape each quote with a backslash.
pub fn quote_arg(arg: &str) -> String {
    let plain = !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']);
    if plain {
        return arg.to_owned();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Join arguments into one command line, each quoted with [`quote_arg`].
pub fn command_line<S: AsRef<str>>(args: &[S]) -> String {
    args.iter()
        .map(|a| quote_arg(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why the elevated relaunch did not produce output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelaunchError {
    /// The user declined the UAC prompt.
    Declined,
    /// Windows could not start the elevated copy.
    Failed { code: u32, message: String },
    /// The elevated copy was still running after the wait limit.
    TimedOut,
}

impl fmt::Display for RelaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelaunchError::Declined => f.write_str("the elevation prompt was declined"),
            RelaunchError::Failed { code, message } => {
                write!(
                    f,
                    "could not start the elevated copy (0x{code:08x}): {message}"
                )
            }
            RelaunchError::TimedOut => f.write_str("the elevated copy did not finish in time"),
        }
    }
}

impl std::error::Error for RelaunchError {}

/// True when this process runs with an elevated token. A failure to ask counts as not elevated.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing, and `token` is a
    // valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION and its size is passed; `token` is open.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    }
    .is_ok();
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    ok && elevation.TokenIsElevated != 0
}

/// How long [`relaunch_elevated`] waits for the elevated copy once it has started. The wait does
/// not include the time the user spends on the UAC prompt.
#[cfg(windows)]
const ELEVATED_RUN_LIMIT_MS: u32 = 120_000;

/// Start this executable again, elevated, with `args` followed by [`OUT_FILE_ARG`] and `out_file`,
/// wait for it, and return its exit code. The caller reads `out_file` and deletes it.
///
/// This shows the UAC prompt. It uses `ShellExecuteExW` with the `runas` verb, the extended form of
/// the `ShellExecuteW` call in ADR 0003, because only the extended form hands back the process to
/// wait on. `out_file` should be a fresh path in the user's temp folder.
///
/// Never call this from a test.
#[cfg(windows)]
pub fn relaunch_elevated(
    args: &[String],
    out_file: &std::path::Path,
) -> Result<u32, RelaunchError> {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    const ERROR_CANCELLED: u32 = 1223;

    let failed = |code: u32, what: &str| RelaunchError::Failed {
        code,
        message: what.to_owned(),
    };
    let exe = std::env::current_exe()
        .map_err(|e| failed(e.raw_os_error().unwrap_or(0) as u32, &e.to_string()))?;
    let mut all: Vec<String> = args.to_vec();
    all.push(OUT_FILE_ARG.to_owned());
    all.push(out_file.to_string_lossy().into_owned());
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&command_line(&all));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: `info` is fully initialised and the three wide strings it points to outlive the call.
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        let code = (e.code().0 as u32) & 0xFFFF;
        return Err(if code == ERROR_CANCELLED {
            RelaunchError::Declined
        } else {
            failed(e.code().0 as u32, &e.message())
        });
    }
    let process = info.hProcess;
    if process.is_invalid() {
        return Err(failed(0, "no process handle was returned"));
    }
    // SAFETY: `process` is the handle ShellExecuteExW returned because of SEE_MASK_NOCLOSEPROCESS.
    let waited = unsafe { WaitForSingleObject(process, ELEVATED_RUN_LIMIT_MS) };
    let result = if waited == WAIT_OBJECT_0 {
        let mut code = 0u32;
        // SAFETY: the process has exited and `code` is a valid out-pointer.
        match unsafe { GetExitCodeProcess(process, &mut code) } {
            Ok(()) => Ok(code),
            Err(e) => Err(failed(e.code().0 as u32, &e.message())),
        }
    } else {
        Err(RelaunchError::TimedOut)
    };
    // SAFETY: closed exactly once, after its last use.
    let _ = unsafe { CloseHandle(process) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_are_left_alone() {
        assert_eq!(quote_arg("wake"), "wake");
        assert_eq!(quote_arg("--json"), "--json");
        assert_eq!(quote_arg(r"C:\Temp\out.json"), r"C:\Temp\out.json");
    }

    #[test]
    fn arguments_that_need_quotes_get_them() {
        assert_eq!(quote_arg(""), r#""""#);
        assert_eq!(quote_arg("a b"), r#""a b""#);
        assert_eq!(quote_arg("a\tb"), "\"a\tb\"");
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(
            quote_arg(r"C:\Users\A B\out.json"),
            r#""C:\Users\A B\out.json""#
        );
    }

    #[test]
    fn backslashes_before_a_quote_or_the_end_are_doubled() {
        // Trailing backslashes must not escape the closing quote.
        assert_eq!(quote_arg(r"C:\a b\"), r#""C:\a b\\""#);
        assert_eq!(quote_arg(r"a\\ b\\"), r#""a\\ b\\\\""#);
        // Backslashes before an embedded quote double, and the quote is escaped.
        assert_eq!(quote_arg(r#"a\"b"#), r#""a\\\"b""#);
        // Backslashes elsewhere stay as they are.
        assert_eq!(quote_arg(r"a\b c"), r#""a\b c""#);
    }

    #[test]
    fn command_line_joins_quoted_arguments() {
        let args = [
            "now",
            "--since",
            "2 hours",
            "--out-file",
            r"C:\Users\A B\o.json",
        ];
        assert_eq!(
            command_line(&args),
            r#"now --since "2 hours" --out-file "C:\Users\A B\o.json""#
        );
        assert_eq!(command_line::<&str>(&[]), "");
    }

    /// The real parser agrees: whatever we quote comes back as the same arguments.
    #[cfg(windows)]
    #[test]
    fn quoting_round_trips_through_commandlinetoargvw() {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::UI::Shell::CommandLineToArgvW;
        use windows::core::PCWSTR;

        let cases: Vec<Vec<&str>> = vec![
            vec!["wake", "--json"],
            vec!["", "a b", "x"],
            vec![r#"say "hi""#, r"C:\a b\", r"a\\ b\\", r#"a\"b"#],
            vec![r"\\server\share\dir with space\", "tab\there", "ünï cödé"],
            vec![r#""""#, r#"\"#, r#"\\"#, r#" \ "#, r#"\" "#],
        ];
        for args in cases {
            let line = format!("prog.exe {}", command_line(&args));
            let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
            let mut n = 0i32;
            // SAFETY: `wide` is NUL-terminated and `n` is a valid out-pointer.
            let argv = unsafe { CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut n) };
            assert!(!argv.is_null());
            let parsed: Vec<String> = (0..n as usize)
                .map(|i| {
                    // SAFETY: argv holds `n` valid NUL-terminated wide strings.
                    unsafe { argv.add(i).read().to_string().unwrap() }
                })
                .collect();
            // SAFETY: the array was allocated by CommandLineToArgvW and is freed once.
            let _ = unsafe { LocalFree(Some(HLOCAL(argv.cast()))) };
            assert_eq!(parsed[0], "prog.exe");
            assert_eq!(&parsed[1..], &args[..], "line: {line}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn this_test_process_is_not_elevated_unless_the_runner_is() {
        // Only checks that asking works and answers consistently; the value depends on the runner.
        assert_eq!(is_elevated(), is_elevated());
    }
}
