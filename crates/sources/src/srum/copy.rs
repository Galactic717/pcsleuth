//! Getting a readable copy: a private scratch folder, log replay on a copy, and the elevated
//! snapshot of the live database.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pcsleuth_core::Access;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::ese::{EseError, Instance, Params, database_is_dirty, database_page_size};

/// The log prefix of the SRUM database (`SRU.log`, `SRU18268.log`, ...).
const LOG_BASE: &str = "SRU";

/// A folder under the system temp dir that is deleted, with everything in it, on drop.
pub(super) struct ScratchDir(PathBuf);

impl ScratchDir {
    pub(super) fn new(tag: &str) -> std::io::Result<ScratchDir> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path = std::env::temp_dir().join(format!(
            "pcsleuth-{tag}-{}-{}-{nanos:x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path)?;
        Ok(ScratchDir(path))
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    let mut logs: Vec<String> = std::fs::read_dir(&source)
        .map_err(|err| io_access(&err))?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| is_srum_log(name))
        .collect();
    logs.sort();
    files.extend(logs);

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
    fn scratch_dirs_are_unique_and_deleted_on_drop() {
        let first = ScratchDir::new("test").unwrap();
        let second = ScratchDir::new("test").unwrap();
        assert_ne!(first.path(), second.path());
        let path = first.path().to_path_buf();
        std::fs::write(path.join("file"), b"x").unwrap();
        drop(first);
        assert!(!path.exists());
        assert!(second.path().is_dir());
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
