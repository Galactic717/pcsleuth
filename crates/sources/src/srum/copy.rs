//! Getting a readable copy: a private scratch folder, log replay on a copy, and the elevated
//! snapshot of the live database.

use std::ffi::{OsString, c_void};
use std::path::{Path, PathBuf};
use std::process::Command;

use pcsleuth_core::Access;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::ese::{EseError, Instance, Params, database_is_dirty, database_page_size};
use super::scratch::ScratchDir;

/// The log prefix of the SRUM database (`SRU.log`, `SRU18268.log`, ...).
const LOG_BASE: &str = "SRU";

/// Replay the transaction logs next to `db` into `db`, in place. The caller owns the copy: this
/// rewrites the database and adds log files beside it. Replay is pointed at the copy's folder, so
/// the live `C:\Windows\System32\SRU` named inside the logs is never touched.
pub(super) fn recover(db: &Path, scratch: &Path) -> Result<(), EseError> {
    let dir = db.parent().unwrap_or(Path::new("."));
    let log_file_kb = std::fs::metadata(dir.join(format!("{LOG_BASE}.log")))
        .ok()
        .map(|m| (m.len() / 1024) as u32)
        .filter(|&kb| kb > 0)
        .unwrap_or(64);
    let instance = Instance::start(&Params {
        name: &format!("pcsleuth-srum-recover-{}", std::process::id()),
        recovery: true,
        system_dir: dir,
        log_dir: dir,
        temp_dir: scratch,
        base_name: LOG_BASE,
        page_size: database_page_size(db)?,
        log_file_kb,
        recovery_db_dir: Some(dir),
    })?;
    // Ending the instance cleanly detaches the database in the clean state.
    drop(instance);
    if database_is_dirty(db)? {
        return Err(EseError {
            code: windows::Win32::Storage::Jet::JET_errDatabaseDirtyShutdown,
            call: "recovery",
        });
    }
    Ok(())
}

/// A private copy of the live SRUM database, replayed and ready to read. Dropping it deletes the
/// copy and everything beside it.
pub struct TempCopy {
    dir: ScratchDir,
}

impl TempCopy {
    /// The recovered `SRUDB.dat` to pass to [`read_usage`](super::read_usage).
    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join("SRUDB.dat")
    }

    /// Delete the copy now and say whether that worked. Dropping a `TempCopy` tries the same but
    /// has nowhere to report a failure, so call this when a copy that is left behind matters.
    pub fn close(self) -> Result<(), Access> {
        self.dir.remove().map_err(|err| io_access(&err))
    }
}

/// True when this process has an elevated token.
pub(super) fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: `token` outlives the call; the pseudo handle of the current process needs no close.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: the buffer is a `TOKEN_ELEVATION` and the length says so.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: `token` was opened above and is closed once.
    let _ = unsafe { CloseHandle(token) };
    queried.is_ok() && elevation.TokenIsElevated != 0
}

/// True for `SRU.log` and `SRU` plus five hex digits plus `.log`: the log generations replay
/// needs. The checkpoint file, the temporary log and the reserve logs are left out on purpose; a
/// checkpoint copied from a later snapshot than the database can start replay too late.
pub(super) fn is_srum_log(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".log") else {
        return false;
    };
    let Some(generation) = stem.strip_prefix(LOG_BASE) else {
        return false;
    };
    generation.is_empty()
        || (generation.len() == 5 && generation.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The SRUM log file names among a directory listing, sorted. A listing entry that cannot be read
/// is an error: a log left out of the copy would make replay fail or start from the wrong place,
/// so it must not be skipped quietly. A name that is not valid Unicode is not a SRUM log, whose
/// names are plain ASCII, and is left out.
fn srum_log_names(
    entries: impl Iterator<Item = std::io::Result<OsString>>,
) -> std::io::Result<Vec<String>> {
    let mut logs = Vec::new();
    for entry in entries {
        if let Ok(name) = entry?.into_string()
            && is_srum_log(&name)
        {
            logs.push(name);
        }
    }
    logs.sort();
    Ok(logs)
}

/// The system directory from `GetSystemDirectoryW`, not from the `SystemRoot` environment
/// variable: this runs elevated, and the environment must not choose which `esentutl.exe` does.
fn system32() -> Result<PathBuf, Access> {
    crate::power::system_directory().map_err(|err| io_access(&err))
}

/// Copy the live SRUM database and its logs out of a volume shadow copy, replay the logs on the
/// copy, and return it.
///
/// Needs an elevated process: returns [`Access::NeedsAdmin`] without trying when this one is not.
/// Every file is copied by its own `esentutl.exe /y <file> /vss /d <copy>` call, which makes its
/// own shadow copy and takes several seconds. The database goes first, then the logs, so every
/// log the database needs is at least as new as the database.
pub fn snapshot_copy() -> Result<TempCopy, Access> {
    if !is_elevated() {
        return Err(Access::NeedsAdmin);
    }
    let system32 = system32()?;
    let esentutl = system32.join("esentutl.exe");
    let source = system32.join("SRU");
    let dir = ScratchDir::new("srum-copy").map_err(|err| io_access(&err))?;

    let mut files = vec![String::from("SRUDB.dat")];
    let entries = std::fs::read_dir(&source).map_err(|err| io_access(&err))?;
    files.extend(
        srum_log_names(entries.map(|e| e.map(|e| e.file_name()))).map_err(|err| io_access(&err))?,
    );

    for name in &files {
        copy_from_shadow(&esentutl, &source.join(name), &dir.path().join(name))?;
    }
    let db = dir.path().join("SRUDB.dat");
    let scratch = dir.path().join("tmp");
    std::fs::create_dir_all(&scratch).map_err(|err| io_access(&err))?;
    recover(&db, &scratch).map_err(|err| Access::Failed {
        code: err.code as u32,
        message: err.to_string(),
    })?;
    Ok(TempCopy { dir })
}

fn copy_from_shadow(esentutl: &Path, from: &Path, to: &Path) -> Result<(), Access> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let output = Command::new(esentutl)
        .arg("/y")
        .arg(from)
        .arg("/vss")
        .arg("/d")
        .arg(to)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| io_access(&err))?;
    if output.status.success() && to.is_file() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stdout
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("no output")
        .to_owned();
    Err(Access::Failed {
        code: output.status.code().unwrap_or(-1) as u32,
        message: format!("esentutl could not copy {}: {detail}", from.display()),
    })
}

/// A plain I/O error as an access result.
pub(super) fn io_access(err: &std::io::Error) -> Access {
    match err.kind() {
        std::io::ErrorKind::NotFound => Access::Missing,
        std::io::ErrorKind::PermissionDenied => Access::NeedsAdmin,
        _ => Access::Failed {
            code: err.raw_os_error().unwrap_or(0) as u32,
            message: err.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_srum_log_generations_are_copied() {
        for name in ["SRU.log", "SRU18268.log", "SRU1826F.log", "SRU00001.log"] {
            assert!(is_srum_log(name), "{name}");
        }
        for name in [
            "SRUtmp.log",
            "SRU.chk",
            "SRUDB.dat",
            "SRUDB.jfm",
            "SRUres00001.jrs",
            "SRU1826.log",
            "SRU1826FF.log",
            "SRUXYZ12.log",
            "edb.log",
            "sru.log.bak",
        ] {
            assert!(!is_srum_log(name), "{name}");
        }
    }

    #[test]
    fn io_errors_map_to_access_results() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            io_access(&Error::from(ErrorKind::NotFound)),
            Access::Missing
        );
        assert_eq!(
            io_access(&Error::from(ErrorKind::PermissionDenied)),
            Access::NeedsAdmin
        );
        assert!(matches!(
            io_access(&Error::from_raw_os_error(32)),
            Access::Failed { code: 32, .. }
        ));
    }

    #[test]
    fn the_log_list_is_sorted_and_an_unreadable_entry_is_an_error_not_a_gap() {
        use std::io::{Error, ErrorKind};
        let name = |n: &str| Ok(OsString::from(n));
        let listing = vec![
            name("SRU18269.log"),
            name("SRUDB.dat"),
            name("SRU.log"),
            name("SRU.chk"),
            name("SRU18268.log"),
        ];
        assert_eq!(
            srum_log_names(listing.into_iter()).unwrap(),
            ["SRU.log", "SRU18268.log", "SRU18269.log"]
        );
        // One entry the directory listing could not read: replay would run with a log missing.
        let broken = vec![
            name("SRU.log"),
            Err(Error::from(ErrorKind::PermissionDenied)),
            name("SRU18268.log"),
        ];
        let err = srum_log_names(broken.into_iter()).unwrap_err();
        assert_eq!(io_access(&err), Access::NeedsAdmin);
    }

    #[test]
    fn a_temp_copy_reports_whether_it_could_be_deleted() {
        let copy = TempCopy {
            dir: ScratchDir::new("test").unwrap(),
        };
        let path = copy.db_path();
        std::fs::write(&path, b"x").unwrap();
        assert!(path.is_file());
        copy.close().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn a_process_without_the_elevated_token_gets_needs_admin_without_a_try() {
        // Running the suite elevated would really take a snapshot; that is the ignored test's job.
        if is_elevated() {
            return;
        }
        assert!(matches!(snapshot_copy(), Err(Access::NeedsAdmin)));
    }
}
