//! Elevation per ADR 0003: run unelevated, and relaunch the same command once through UAC when the
//! user asks. The elevated copy writes its JSON to a file the parent reads and deletes.
//!
//! Quoting is pure and tested everywhere. The UAC path is never called from a test: it needs a
//! person to click the prompt.
//!
//! # The output file
//!
//! The elevated copy writes with administrator rights to a path the unelevated parent chose in a
//! folder the user can write to. To keep another process of the same user from planting a link at
//! that path and turning the write into an elevated overwrite:
//!
//! 1. The parent creates the file's directory with [`create_output_dir`]: a new directory in the
//!    temp folder whose name is 128 random bits (`pcsleuth-` and 32 hex digits). The path cannot be
//!    guessed before the directory exists. [`relaunch_elevated`] refuses any other path.
//! 2. The elevated copy creates the file with [`open_output_file`], which opens with `create_new`
//!    so it fails if anything, including a link, is already there. It never overwrites.
//! 3. The parent reads the file and then removes the whole directory, also when the child timed
//!    out, so a child that outlives the wait has nowhere to write.

use std::fmt;
use std::fs::File;
use std::path::Path;

/// The argument that tells the elevated copy where to write its output. [`relaunch_elevated`]
/// appends it to the arguments it is given, followed by the path, so the command line must accept
/// `--out-file <path>` and open that path with [`open_output_file`].
pub const OUT_FILE_ARG: &str = "--out-file";

/// Prefix of every output directory name.
const OUTPUT_DIR_PREFIX: &str = "pcsleuth-";

/// The directory name for 128 random bits: `pcsleuth-` and 32 lower case hex digits.
pub fn output_dir_name(random: [u8; 16]) -> String {
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{OUTPUT_DIR_PREFIX}{hex}")
}

/// True when `path` has the shape [`create_output_dir`] makes: a file name inside a directory named
/// by [`output_dir_name`].
pub fn is_output_path(path: &Path) -> bool {
    let dir_name = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str());
    let named_like_ours = dir_name
        .and_then(|n| n.strip_prefix(OUTPUT_DIR_PREFIX))
        .is_some_and(|hex| {
            hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
    named_like_ours && path.file_name().is_some()
}

/// Open `path` for writing as a brand new file. It fails if the path already exists, as a file or
/// as a link, so a planted path is never followed or overwritten. The elevated copy writes its
/// output through this.
pub fn open_output_file(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Create a fresh directory in the temp folder named by 128 random bits and return its path. Put
/// the output file inside it. The caller removes the directory when done.
#[cfg(windows)]
pub fn create_output_dir() -> std::io::Result<std::path::PathBuf> {
    // The same system generator Rust's own standard library uses; it cannot fail on Windows 10+.
    windows::core::link!("bcryptprimitives.dll" "system" fn ProcessPrng(data: *mut u8, len: usize) -> i32);

    let mut random = [0u8; 16];
    // SAFETY: the pointer and length describe `random` exactly.
    if unsafe { ProcessPrng(random.as_mut_ptr(), random.len()) } == 0 {
        return Err(std::io::Error::other("the system random generator failed"));
    }
    let dir = std::env::temp_dir().join(output_dir_name(random));
    // `create_dir`, not `create_dir_all`: an existing directory is an error, never reused.
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

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
    /// The elevated copy was still running after the wait limit. `terminated` says whether this
    /// process managed to end it; an unelevated process often cannot end an elevated one, so the
    /// caller must remove the output directory either way.
    TimedOut { terminated: bool },
    /// `out_file` is not a new file inside a directory from [`create_output_dir`].
    BadOutFile,
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
            RelaunchError::TimedOut { terminated } => write!(
                f,
                "the elevated copy did not finish in time ({})",
                if *terminated {
                    "it was ended"
                } else {
                    "it could not be ended"
                }
            ),
            RelaunchError::BadOutFile => f.write_str(
                "the output file must be a new file in a directory made by create_output_dir",
            ),
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
/// wait for it, and return its exit code. The caller reads `out_file`, then removes its directory.
///
/// `out_file` must be a file name inside a directory made by [`create_output_dir`] and must not
/// exist yet, or this returns [`RelaunchError::BadOutFile`] without prompting. The elevated copy
/// must create the file with [`open_output_file`]. See the module documentation for why.
///
/// This shows the UAC prompt. It uses `ShellExecuteExW` with the `runas` verb, the extended form of
/// the `ShellExecuteW` call in ADR 0003, because only the extended form hands back the process to
/// wait on. On a timeout it tries to end the elevated copy, which an unelevated process usually
/// cannot do; the caller's removal of the output directory is what stops a late write.
///
/// Never call this from a test.
#[cfg(windows)]
pub fn relaunch_elevated(args: &[String], out_file: &Path) -> Result<u32, RelaunchError> {
    use windows::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    };
    use windows::Win32::UI::Shell::{
        SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::PCWSTR;

    const ERROR_CANCELLED: u32 = 1223;

    if !is_output_path(out_file) || out_file.exists() {
        return Err(RelaunchError::BadOutFile);
    }
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
        // NOASYNC: the calling thread has no message loop, so the launch must finish before return.
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
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
    } else if waited == WAIT_TIMEOUT {
        // SAFETY: `process` is open; ending it is the point. The caller's removal of the output
        // directory is what stops a copy that survives this.
        let terminated = unsafe { TerminateProcess(process, 1) }.is_ok();
        Err(RelaunchError::TimedOut { terminated })
    } else {
        // WAIT_FAILED (or an abandoned or other result that a process handle cannot give).
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() }.0;
        Err(failed(code, "waiting for the elevated copy failed"))
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

    #[test]
    fn output_dir_names_are_128_random_bits_in_hex() {
        let name = output_dir_name([0xab; 16]);
        assert_eq!(name, format!("pcsleuth-{}", "ab".repeat(16)));
        assert_eq!(
            output_dir_name([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255]),
            "pcsleuth-000102030405060708090a0b0c0d0eff"
        );
    }

    #[test]
    fn only_paths_in_a_random_named_directory_are_output_paths() {
        let dir = std::env::temp_dir().join(output_dir_name([7; 16]));
        assert!(is_output_path(&dir.join("answer.json")));
        // Guessable or hand-made places are refused.
        assert!(!is_output_path(&std::env::temp_dir().join("answer.json")));
        assert!(!is_output_path(
            &std::env::temp_dir().join("pcsleuth").join("a.json")
        ));
        let upper = std::env::temp_dir().join(format!("pcsleuth-{}", "AB".repeat(16)));
        assert!(!is_output_path(&upper.join("a.json")));
        let short = std::env::temp_dir().join(format!("pcsleuth-{}", "ab".repeat(15)));
        assert!(!is_output_path(&short.join("a.json")));
        let long = std::env::temp_dir().join(format!("pcsleuth-{}", "ab".repeat(17)));
        assert!(!is_output_path(&long.join("a.json")));
        assert!(!is_output_path(Path::new("")));
        assert!(!is_output_path(Path::new("answer.json")));
    }

    #[test]
    fn the_output_file_is_created_new_and_never_overwritten() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("pcsleuth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("answer.json");
        let _ = std::fs::remove_file(&path);

        let mut file = open_output_file(&path).unwrap();
        file.write_all(b"first").unwrap();
        drop(file);
        // A second open, as a planted path would be, fails and leaves the content alone.
        let err = open_output_file(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        // A directory in the way is refused too.
        let as_dir = dir.join("sub");
        std::fs::create_dir(&as_dir).unwrap();
        assert!(open_output_file(&as_dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn create_output_dir_makes_a_new_random_directory_each_time() {
        let a = create_output_dir().unwrap();
        let b = create_output_dir().unwrap();
        assert_ne!(a, b);
        for dir in [&a, &b] {
            assert!(dir.is_dir());
            assert!(is_output_path(&dir.join("answer.json")));
            assert_eq!(dir.parent().unwrap(), std::env::temp_dir());
        }
        std::fs::remove_dir(&a).unwrap();
        std::fs::remove_dir(&b).unwrap();
    }

    /// `relaunch_elevated` refuses a path that is not ours before it shows any prompt, so this is
    /// safe to run: it never reaches `ShellExecuteExW`.
    #[cfg(windows)]
    #[test]
    fn relaunch_refuses_a_guessable_or_existing_output_path_without_prompting() {
        let guessable = std::env::temp_dir().join("pcsleuth-out.json");
        assert_eq!(
            relaunch_elevated(&["now".to_owned()], &guessable),
            Err(RelaunchError::BadOutFile)
        );
        let dir = create_output_dir().unwrap();
        let existing = dir.join("answer.json");
        std::fs::write(&existing, b"planted").unwrap();
        assert_eq!(
            relaunch_elevated(&[], &existing),
            Err(RelaunchError::BadOutFile)
        );
        std::fs::remove_dir_all(&dir).unwrap();
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
