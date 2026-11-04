//! The Windows calls behind the recorder, apart from the service itself: low priority, the
//! numbers `--measure` reports, the Ctrl+C handler, and the protected data folder.
//!
//! Each `unsafe` block says why it is sound. Nothing here changes a system setting, asks Windows to
//! stay awake or changes the timer resolution.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, FILETIME, HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, SetConsoleCtrlHandler,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessIoCounters, GetProcessTimes, GetThreadTimes,
    IO_COUNTERS, OpenProcessToken, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
};
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::runner;

/// A nul-terminated UTF-16 copy of `s`.
pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

fn to_io(e: windows::core::Error) -> io::Error {
    io::Error::other(e)
}

/// A Windows known folder such as `C:\Program Files`, from the shell and not from an environment
/// variable, which the user who runs us can set to anything.
fn known_folder(id: &windows::core::GUID) -> io::Result<PathBuf> {
    // SAFETY: `id` is a valid GUID; on success Windows returns a nul-terminated string that is
    // freed with CoTaskMemFree below, once.
    let path = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None) }.map_err(to_io)?;
    // SAFETY: `path` is a valid nul-terminated string from the call above.
    let folder = PathBuf::from(OsString::from_wide(unsafe { path.as_wide() }));
    // SAFETY: allocated by SHGetKnownFolderPath, freed exactly once.
    unsafe { CoTaskMemFree(Some(path.0.cast_const().cast())) };
    Ok(folder)
}

/// `C:\Program Files` (the native one), where only administrators can create or change files.
pub fn program_files_dir() -> io::Result<PathBuf> {
    known_folder(&FOLDERID_ProgramFiles)
}

/// `C:\ProgramData`.
pub fn program_data_dir() -> io::Result<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

/// True if `path` lies strictly inside `root`, comparing whole components without regard to case.
/// A path with `.` or `..` in it is never inside anything: resolve it first with `canonicalize`.
pub fn path_is_under(path: &Path, root: &Path) -> bool {
    fn parts(p: &Path) -> Option<Vec<String>> {
        p.components()
            .map(|c| match c {
                Component::ParentDir | Component::CurDir => None,
                other => Some(other.as_os_str().to_string_lossy().to_lowercase()),
            })
            .collect()
    }
    match (parts(path), parts(root)) {
        (Some(p), Some(r)) => !r.is_empty() && p.len() > r.len() && p[..r.len()] == r[..],
        _ => false,
    }
}

/// `\\?\C:\x` as `C:\x`. `canonicalize` returns the first form, which the service manager does
/// not take as a program path. A `\\?\UNC\` path is left alone.
pub fn strip_verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

/// Run the calling thread in background mode: lowest CPU, IO and memory priority, for as long as
/// the thread lives. It affects only this thread, so call it on the thread that samples.
pub fn lower_thread_priority() -> io::Result<()> {
    // SAFETY: the current-thread pseudo handle is always valid, and background mode applies only
    // to the thread that asks.
    unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) }.map_err(to_io)
}

fn ticks(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

/// Kernel plus user CPU time of this process so far, in 100 ns ticks. The kernel accounts it in
/// scheduler quanta of about 15.6 ms, so short spans read in coarse steps.
pub fn process_cpu_ticks() -> u64 {
    let mut t = [FILETIME::default(); 4];
    // SAFETY: the pseudo handle is valid and each out-pointer is a distinct local FILETIME.
    let read = unsafe {
        let [created, exited, kernel, user] = &mut t;
        GetProcessTimes(GetCurrentProcess(), created, exited, kernel, user)
    };
    if read.is_ok() {
        ticks(t[2]) + ticks(t[3])
    } else {
        0
    }
}

/// Kernel plus user CPU time of the calling thread so far, in 100 ns ticks.
pub fn thread_cpu_ticks() -> u64 {
    let mut t = [FILETIME::default(); 4];
    // SAFETY: as for `process_cpu_ticks`, with the thread pseudo handle.
    let read = unsafe {
        let [created, exited, kernel, user] = &mut t;
        GetThreadTimes(GetCurrentThread(), created, exited, kernel, user)
    };
    if read.is_ok() {
        ticks(t[2]) + ticks(t[3])
    } else {
        0
    }
}

/// This process's memory in use now and at its peak, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryUse {
    pub working_set: u64,
    pub peak_working_set: u64,
}

pub fn memory_use() -> Option<MemoryUse> {
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    // SAFETY: the pseudo handle is valid and `counters` has its size set and outlives the call.
    unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) }.ok()?;
    Some(MemoryUse {
        working_set: counters.WorkingSetSize as u64,
        peak_working_set: counters.PeakWorkingSetSize as u64,
    })
}

/// Bytes this process has asked Windows to write, of every kind (files and console).
pub fn write_transfer_bytes() -> Option<u64> {
    let mut io = IO_COUNTERS::default();
    // SAFETY: the pseudo handle is valid and `io` is a local of the right type.
    unsafe { GetProcessIoCounters(GetCurrentProcess(), &mut io) }.ok()?;
    Some(io.WriteTransferCount)
}

unsafe extern "system" fn on_console_event(kind: u32) -> BOOL {
    match kind {
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT => {
            runner::request_stop();
            BOOL(1)
        }
        _ => BOOL(0),
    }
}

/// Make Ctrl+C, Ctrl+Break and closing the console end the loop made by `runner::stop_channel`.
pub fn stop_on_ctrl_c() -> io::Result<()> {
    // SAFETY: `on_console_event` has the signature Windows expects and lives for the whole run.
    unsafe { SetConsoleCtrlHandler(Some(on_console_event), true) }.map_err(to_io)
}

/// Free a string or descriptor that Windows allocated with `LocalAlloc`.
fn local_free(ptr: *mut core::ffi::c_void) {
    // SAFETY: only called with pointers returned by the security functions, once each.
    let _ = unsafe { LocalFree(Some(HLOCAL(ptr))) };
}

fn win32_result(code: WIN32_ERROR) -> io::Result<()> {
    if code.0 == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.0 as i32))
    }
}

/// The string form of the SID of the user this process runs as, such as `S-1-5-21-...`.
pub fn current_user_sid() -> io::Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo handle is valid and `token` is a valid out-pointer.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(to_io)?;
    let sid = token_user_sid(token);
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    sid
}

fn token_user_sid(token: HANDLE) -> io::Result<String> {
    let mut needed = 0u32;
    // SAFETY: a size query with no buffer; `needed` is a valid out-pointer. It fails by design.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    // Words, so the buffer is 8-aligned for the TOKEN_USER that Windows writes into it.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` is writable for at least `needed` bytes, which is passed as the length.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(to_io)?;
    // SAFETY: Windows filled `buf` with a TOKEN_USER, and the buffer is suitably aligned.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut text = PWSTR::null();
    // SAFETY: the SID points into `buf`, which is alive, and `text` is a valid out-pointer.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.map_err(to_io)?;
    // SAFETY: on success `text` is a nul-terminated string that this function now owns.
    let sid = unsafe { text.to_string() }.map_err(io::Error::other);
    local_free(text.0.cast());
    sid
}

/// The security descriptor string for the data folder: protected (nothing inherited from
/// `%ProgramData%`), full control for SYSTEM, Administrators and the one user, and inherited by the
/// ring file inside.
pub fn protected_folder_sddl(user_sid: &str) -> String {
    format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})")
}

/// Create `dir` (one level) with the descriptor from [`protected_folder_sddl`], or, if it exists,
/// replace its permissions with it. Nobody else can read what is inside.
pub fn create_protected_dir(dir: &Path, user_sid: &str) -> io::Result<()> {
    let sddl = wide(protected_folder_sddl(user_sid));
    let path = wide(dir);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is nul-terminated and `descriptor` is a valid out-pointer.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1, // SDDL_REVISION_1
            &mut descriptor,
            None,
        )
    }
    .map_err(to_io)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: BOOL(0),
    };
    // SAFETY: `path` is nul-terminated and `attributes` points at a valid descriptor, both alive
    // for the call. The folder is created with the descriptor, so it is never open to others.
    let created = unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&attributes)) };
    let result = match created {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => apply_dacl(&path, descriptor),
        Err(e) => Err(to_io(e)),
    };
    local_free(descriptor.0);
    result
}

/// Replace the permissions of the existing object at `path` with the DACL of `descriptor`, and stop
/// it inheriting from its parent.
fn apply_dacl(path: &[u16], descriptor: PSECURITY_DESCRIPTOR) -> io::Result<()> {
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `descriptor` is valid and the out-pointers are distinct locals. `dacl` points into
    // `descriptor`, which the caller keeps alive until this returns.
    unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        .map_err(to_io)?;
    // SAFETY: `path` is nul-terminated and `dacl` is the valid DACL read just above.
    let code = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    win32_result(code)
}

/// The permissions of `path` as an SDDL string, for checking the folder is as intended.
pub fn dacl_sddl(path: &Path) -> io::Result<String> {
    let wide_path = wide(path);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide_path` is nul-terminated and `descriptor` is a valid out-pointer; Windows
    // allocates the descriptor, which is freed below.
    let code = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    win32_result(code)?;
    let mut text = PWSTR::null();
    // SAFETY: `descriptor` was returned just above and `text` is a valid out-pointer.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    };
    local_free(descriptor.0);
    converted.map_err(to_io)?;
    // SAFETY: on success `text` is a nul-terminated string that this function now owns.
    let sddl = unsafe { text.to_string() }.map_err(io::Error::other);
    local_free(text.0.cast());
    sddl
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn a_path_is_under_a_folder_by_whole_components_ignoring_case() {
        let root = Path::new(r"C:\Program Files");
        assert!(path_is_under(
            Path::new(r"C:\Program Files\pcsleuth\r.exe"),
            root
        ));
        assert!(path_is_under(Path::new(r"c:\PROGRAM FILES\x\r.exe"), root));
        // A sibling that merely starts with the same letters is not inside.
        assert!(!path_is_under(
            Path::new(r"C:\Program Files (x86)\x\r.exe"),
            root
        ));
        assert!(!path_is_under(
            Path::new(r"C:\Program FilesEvil\r.exe"),
            root
        ));
        assert!(!path_is_under(
            Path::new(r"C:\Users\me\Downloads\r.exe"),
            root
        ));
        assert!(!path_is_under(Path::new(r"D:\Program Files\r.exe"), root));
        // The folder itself is not inside itself, and an empty root contains nothing.
        assert!(!path_is_under(root, root));
        assert!(!path_is_under(Path::new(r"C:\x"), Path::new("")));
        // `..` is never trusted; resolve it first.
        assert!(!path_is_under(
            Path::new(r"C:\Program Files\..\Users\me\r.exe"),
            root
        ));
        // Both in the form `canonicalize` gives.
        assert!(path_is_under(
            Path::new(r"\\?\C:\Program Files\pcsleuth\r.exe"),
            Path::new(r"\\?\C:\Program Files")
        ));
    }

    #[test]
    fn the_verbatim_prefix_comes_off_drive_paths_only() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\Program Files\r.exe")),
            PathBuf::from(r"C:\Program Files\r.exe")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\UNC\server\share\r.exe")),
            PathBuf::from(r"\\?\UNC\server\share\r.exe")
        );
        assert_eq!(
            strip_verbatim(Path::new(r"C:\plain\r.exe")),
            PathBuf::from(r"C:\plain\r.exe")
        );
    }

    #[test]
    fn the_known_folders_exist() {
        let program_files = program_files_dir().unwrap();
        assert!(program_files.is_dir(), "{program_files:?}");
        assert!(program_data_dir().unwrap().is_dir());
    }

    #[test]
    fn this_process_has_a_sid_and_a_working_set() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        let mem = memory_use().unwrap();
        assert!(mem.working_set > 0 && mem.peak_working_set >= mem.working_set);
        assert!(write_transfer_bytes().is_some());
        // CPU time is accounted in steps of 15.6 ms, so a fresh test process can still read zero.
        // Spin for four steps first; then both the process and this thread have used some.
        let end = Instant::now() + Duration::from_millis(60);
        let mut x = 0u64;
        while Instant::now() < end {
            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(7));
        }
        assert!(process_cpu_ticks() > 0 && thread_cpu_ticks() > 0);
    }

    #[test]
    fn a_new_folder_is_protected_with_exactly_system_administrators_and_the_user() {
        let dir = std::env::temp_dir().join(format!("pcsleuth-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let sid = current_user_sid().unwrap();
        create_protected_dir(&dir, &sid).unwrap();
        let sddl = dacl_sddl(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("DACL: {sddl}");
        assert!(sddl.starts_with("D:P"), "not protected: {sddl}");
        assert_eq!(sddl.matches("(A;").count(), 3, "{sddl}");
        assert!(sddl.contains("(A;OICI;FA;;;SY)"), "{sddl}");
        assert!(sddl.contains("(A;OICI;FA;;;BA)"), "{sddl}");
        assert!(sddl.contains(&format!("(A;OICI;FA;;;{sid})")), "{sddl}");
    }

    #[test]
    fn an_existing_open_folder_is_closed_down_and_a_file_inside_inherits() {
        let dir = std::env::temp_dir().join(format!("pcsleuth-acl2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let before = dacl_sddl(&dir).unwrap();
        let file = dir.join("recorder.ring");
        std::fs::write(&file, b"x").unwrap();
        let sid = current_user_sid().unwrap();
        create_protected_dir(&dir, &sid).unwrap();
        let after = dacl_sddl(&dir).unwrap();
        let inner = dacl_sddl(&file).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("before: {before}\nafter:  {after}\nfile:   {inner}");
        assert!(after.starts_with("D:P"), "{after}");
        assert_eq!(after.matches("(A;").count(), 3, "{after}");
        // The file's own permissions followed the folder's.
        assert_eq!(inner.matches("(A;").count(), 3, "{inner}");
    }

    #[test]
    fn waiting_in_the_loop_uses_no_cpu() {
        use std::sync::mpsc;
        let (_keep, rx) = mpsc::channel::<()>();
        let before = thread_cpu_ticks();
        let started = Instant::now();
        // A second of waiting in the sampler's own wait, with a tick every 100 ms that does nothing.
        let mut ring = crate::ring::RingWriter::start(
            std::io::Cursor::new(Vec::new()),
            4 * crate::ring::BLOCK as u64,
            1,
            jiff::Timestamp::now(),
        )
        .unwrap();
        let stats = runner::run(
            &mut ring,
            Duration::from_millis(100),
            &rx,
            Some(started + Duration::from_secs(1)),
            || runner::Tick::Baseline,
            |_| {},
        );
        let used = Duration::from_nanos((thread_cpu_ticks() - before) * 100);
        assert!(stats.ticks >= 9, "{stats:?}");
        // A busy wait would burn the whole second; scheduler accounting is in 15.6 ms steps.
        assert!(used < Duration::from_millis(60), "{used:?}");
    }
}
