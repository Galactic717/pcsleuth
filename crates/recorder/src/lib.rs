//! The opt-in recorder (ADR 0006): what the logs miss, kept in one fixed-size ring file.
//!
//! This is the reading side the engine uses, plus the sampler and the Windows service behind the
//! `pcsleuth-recorder` binary. The OS calls are behind `#[cfg(windows)]`; the ring format, the
//! sample mapping and the loop build and test anywhere. `unsafe` appears only in the Windows
//! modules, each use with a safety comment.
//!
//! - [`default_ring_path`]: where to look. The service's ring if there is one, else the user's.
//! - [`read_rows`]: the rows since a time, as the contract type. No ring file is
//!   [`Access::Missing`], never an error. Each row says in `requests_visible` whether power
//!   requests could be seen, so an empty list is never taken for "none held".
//! - [`status`]: what is in the ring.

#[cfg(windows)]
pub mod measure;
pub mod ring;
pub mod runner;
pub mod sample;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod winapi;

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jiff::Timestamp;
use pcsleuth_core::{Access, RecorderRow, SourceId, Sourced};

pub use ring::{DEFAULT_BYTES, RingError, Sample};

/// File name of the ring inside its folder.
pub const RING_FILE: &str = "recorder.ring";
/// Folder name under `%ProgramData%` and `%LOCALAPPDATA%`.
pub const APP_DIR: &str = "pcsleuth";
/// Default sampling interval, in seconds.
pub const DEFAULT_INTERVAL_SECS: u32 = 60;

fn under_env(var: &str) -> PathBuf {
    // Without the variable (not Windows, or a stripped environment) fall back to the temp folder,
    // which is per user on Windows.
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_DIR)
        .join(RING_FILE)
}

/// Where the service keeps its ring: `%ProgramData%\pcsleuth\recorder.ring`.
pub fn service_ring_path() -> PathBuf {
    // The shell's known folder, not the environment variable: whoever runs `install` can set
    // that variable, and the folder must be the real one that only administrators can change.
    #[cfg(windows)]
    if let Ok(dir) = winapi::program_data_dir() {
        return dir.join(APP_DIR).join(RING_FILE);
    }
    under_env("ProgramData")
}

/// Where `--foreground` keeps its ring: `%LOCALAPPDATA%\pcsleuth\recorder.ring`.
pub fn user_ring_path() -> PathBuf {
    under_env("LOCALAPPDATA")
}

/// The ring to read: the service's if that file is there, else the user's. The path may not exist,
/// and reading it then says [`Access::Missing`].
///
/// A service ring that this user is not allowed to see counts as there: it is `Access::NeedsAdmin`
/// to read, which is the truth, not "missing". (`Path::exists` would say false for it.)
pub fn default_ring_path() -> PathBuf {
    pick_ring(&service_ring_path(), &user_ring_path())
}

fn pick_ring(service: &Path, user: &Path) -> PathBuf {
    if ring_is_there(std::fs::metadata(service).map(|_| ())) {
        service.to_path_buf()
    } else {
        user.to_path_buf()
    }
}

/// True if the probe found the file, or found it but was not allowed to look.
fn ring_is_there(probe: io::Result<()>) -> bool {
    match probe {
        Ok(()) => true,
        Err(e) => e.kind() == io::ErrorKind::PermissionDenied,
    }
}

/// Win32 `ERROR_INVALID_DATA`, for a file that is not a usable ring.
const ERROR_INVALID_DATA: u32 = 13;
/// Win32 `ERROR_NOT_SUPPORTED`, for a ring from another format version.
const ERROR_NOT_SUPPORTED: u32 = 50;

fn access_from_error(e: &RingError) -> Access {
    match e {
        RingError::Io(io) if io.kind() == io::ErrorKind::NotFound => Access::Missing,
        // The service's folder is readable only by SYSTEM, Administrators and the installing user.
        RingError::Io(io) if io.kind() == io::ErrorKind::PermissionDenied => Access::NeedsAdmin,
        RingError::Io(io) => Access::Failed {
            code: io.raw_os_error().map_or(0, |c| c as u32),
            message: io.to_string(),
        },
        RingError::BadVersion(_) => Access::Failed {
            code: ERROR_NOT_SUPPORTED,
            message: e.to_string(),
        },
        RingError::BadMagic
        | RingError::HeaderCorrupt
        | RingError::TooShort
        | RingError::WrongLength { .. } => Access::Failed {
            code: ERROR_INVALID_DATA,
            message: e.to_string(),
        },
    }
}

fn read_scan(path: &Path) -> Result<ring::Scan, RingError> {
    ring::scan(&mut File::open(path)?)
}

/// The rows at or after `since`, oldest first.
///
/// A missing file is [`Access::Missing`] and an unreadable one [`Access::NeedsAdmin`] or
/// [`Access::Failed`], all with no data. A ring with torn or damaged slots is
/// [`Access::Partial`] saying how many were skipped, with the rest returned.
///
/// Rows recorded without admin are returned like any other and the read is still
/// [`Access::Ok`]: they are good samples of CPU and IO, and each says in
/// [`RecorderRow::requests_visible`] that its empty `power_requests` means "not visible", not
/// "none held". Whoever reads power requests must look at that flag.
pub fn read_rows(path: &Path, since: Timestamp) -> Sourced<RecorderRow> {
    let source = SourceId::Recorder;
    let scan = match read_scan(path) {
        Ok(scan) => scan,
        Err(e) => return Sourced::unreadable(source, access_from_error(&e)),
    };
    let data: Vec<RecorderRow> = scan
        .samples
        .into_iter()
        .map(|(_, sample)| sample.row)
        .filter(|row| row.at >= since)
        .collect();
    if scan.skipped == 0 {
        return Sourced::ok(source, data);
    }
    let message = format!(
        "{} ring slot(s) were torn or damaged and were skipped",
        scan.skipped
    );
    Sourced {
        source,
        access: Access::Partial { message },
        data,
    }
}

/// What a ring file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub slot_count: u32,
    /// Interval the last writer was started with.
    pub interval_secs: u32,
    pub created: Option<Timestamp>,
    /// Readable samples in the ring.
    pub rows: u32,
    /// Slots that were written but are torn or damaged, or missing from a short file.
    pub skipped: u32,
    /// Rows recorded without admin, whose empty power request list means "not visible".
    pub rows_without_request_visibility: u32,
    pub oldest: Option<Timestamp>,
    pub newest: Option<Timestamp>,
}

impl Status {
    /// How much history a full ring holds at the interval it was started with.
    pub fn capacity(&self) -> Duration {
        Duration::from_secs(u64::from(self.slot_count) * u64::from(self.interval_secs))
    }

    /// How old the newest row is at `now`. `None` for a ring with no rows, or when the newest row
    /// is dated after `now` (the clock was set back).
    pub fn newest_age(&self, now: Timestamp) -> Option<Duration> {
        Duration::try_from(now.duration_since(self.newest?)).ok()
    }

    /// True if the newest row is old enough that the recorder is probably not running. It may also
    /// be that the machine slept: the ring cannot tell the two apart.
    pub fn looks_stopped(&self, now: Timestamp) -> bool {
        self.newest_age(now)
            .is_some_and(|age| is_stale(age, self.interval_secs))
    }
}

/// A newest row older than three intervals, and than a minute, is stale.
pub fn is_stale(age: Duration, interval_secs: u32) -> bool {
    age > Duration::from_secs(u64::from(interval_secs) * 3).max(Duration::from_secs(60))
}

/// Describe the ring at `path`. Missing, unreadable and damaged files are [`Access`] values.
pub fn status(path: &Path) -> Sourced<Status> {
    let source = SourceId::Recorder;
    let scan = match read_scan(path) {
        Ok(scan) => scan,
        Err(e) => return Sourced::unreadable(source, access_from_error(&e)),
    };
    let size_bytes = std::fs::metadata(path).map_or(scan.header.file_bytes(), |m| m.len());
    let times = scan.samples.iter().map(|(_, s)| s.row.at);
    let status = Status {
        path: path.to_path_buf(),
        size_bytes,
        slot_count: scan.header.slot_count,
        interval_secs: scan.header.interval_secs,
        created: Timestamp::from_millisecond(scan.header.created_ms).ok(),
        rows: scan.samples.len() as u32,
        skipped: scan.skipped,
        rows_without_request_visibility: scan
            .samples
            .iter()
            .filter(|(_, s)| !s.row.requests_visible)
            .count() as u32,
        oldest: times.clone().min(),
        newest: times.max(),
    };
    if scan.skipped == 0 {
        return Sourced::ok(source, vec![status]);
    }
    Sourced {
        source,
        access: Access::Partial {
            message: format!(
                "{} ring slot(s) were torn or damaged and were skipped",
                scan.skipped
            ),
        },
        data: vec![status],
    }
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::{RecordedProcess, RecordedRequest};

    use super::*;
    use crate::ring::{BLOCK, RingWriter};

    const T0: i64 = 1_793_692_800;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_second(T0 + secs).unwrap()
    }

    fn sample(secs: i64, visible: bool) -> Sample {
        Sample {
            row: RecorderRow {
                at: at(secs),
                interval_secs: 60,
                top_cpu: vec![RecordedProcess {
                    name: "a.exe".into(),
                    cpu_permille: 5,
                    io_bytes_per_sec: 6,
                }],
                top_io: vec![],
                power_requests: if visible {
                    vec![RecordedRequest {
                        owner: "o.exe".into(),
                        kind: "system".into(),
                        reason: None,
                    }]
                } else {
                    vec![]
                },
                requests_visible: visible,
            },
            truncated: false,
        }
    }

    struct Dir(PathBuf);
    impl Dir {
        fn new(name: &str) -> Dir {
            let dir =
                std::env::temp_dir().join(format!("pcsleuth-lib-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }
        fn ring(&self) -> PathBuf {
            self.0.join(RING_FILE)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, samples: &[Sample]) {
        let mut w = RingWriter::open(path, 9 * BLOCK as u64, 60).unwrap();
        for s in samples {
            w.append(s).unwrap();
        }
    }

    #[test]
    fn no_ring_file_is_missing_never_an_error() {
        let dir = Dir::new("missing");
        let rows = read_rows(&dir.ring(), at(0));
        assert_eq!(rows.access, Access::Missing);
        assert!(rows.data.is_empty());
        assert_eq!(rows.source, SourceId::Recorder);
        assert_eq!(status(&dir.ring()).access, Access::Missing);
    }

    #[test]
    fn rows_since_a_time_come_back_oldest_first() {
        let dir = Dir::new("since");
        write(
            &dir.ring(),
            &[sample(0, true), sample(60, true), sample(120, true)],
        );
        let all = read_rows(&dir.ring(), at(0));
        assert_eq!(all.access, Access::Ok);
        assert_eq!(all.data.len(), 3);
        let later = read_rows(&dir.ring(), at(60));
        let times: Vec<_> = later.data.iter().map(|r| r.at).collect();
        assert_eq!(times, vec![at(60), at(120)]);
        assert!(read_rows(&dir.ring(), at(121)).data.is_empty());
    }

    #[test]
    fn rows_recorded_without_admin_read_ok_and_say_so_themselves() {
        let dir = Dir::new("blind");
        write(
            &dir.ring(),
            &[sample(0, false), sample(60, true), sample(120, false)],
        );
        let rows = read_rows(&dir.ring(), at(0));
        // Good samples of CPU and IO: the read is Ok, not Partial.
        assert_eq!(rows.access, Access::Ok);
        assert_eq!(
            rows.data
                .iter()
                .map(|r| r.requests_visible)
                .collect::<Vec<_>>(),
            vec![false, true, false]
        );
        // The row that could not see requests has none to show, and says why.
        assert!(rows.data[0].power_requests.is_empty() && !rows.data[0].requests_visible);
        assert_eq!(rows.data[1].power_requests.len(), 1);
    }

    #[test]
    fn a_damaged_slot_is_partial_with_the_rest_returned() {
        let dir = Dir::new("torn");
        write(
            &dir.ring(),
            &[sample(0, true), sample(60, true), sample(120, true)],
        );
        let mut bytes = std::fs::read(dir.ring()).unwrap();
        bytes[2 * BLOCK + 20] ^= 0xFF; // slot 1, sample 2
        std::fs::write(dir.ring(), &bytes).unwrap();
        let rows = read_rows(&dir.ring(), at(0));
        match &rows.access {
            Access::Partial { message } => assert!(message.starts_with("1 ring slot"), "{message}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(rows.data.len(), 2);
        let st = status(&dir.ring());
        assert!(matches!(st.access, Access::Partial { .. }));
        assert_eq!(st.data[0].skipped, 1);
    }

    #[test]
    fn a_file_that_is_not_a_ring_is_failed_not_a_panic() {
        let dir = Dir::new("junk");
        std::fs::write(
            dir.ring(),
            b"this is not a ring file, just some text in the way",
        )
        .unwrap();
        let rows = read_rows(&dir.ring(), at(0));
        assert!(
            matches!(rows.access, Access::Failed { code: 13, .. }),
            "{:?}",
            rows.access
        );
        assert!(rows.data.is_empty());
        std::fs::write(dir.ring(), b"").unwrap();
        assert!(matches!(
            read_rows(&dir.ring(), at(0)).access,
            Access::Failed { .. }
        ));
    }

    #[test]
    fn status_describes_the_ring() {
        let dir = Dir::new("status");
        write(&dir.ring(), &[sample(0, false), sample(60, true)]);
        let read = status(&dir.ring());
        assert_eq!(read.access, Access::Ok);
        let st = &read.data[0];
        assert_eq!(st.size_bytes, 9 * BLOCK as u64);
        assert_eq!(st.slot_count, 8);
        assert_eq!(st.interval_secs, 60);
        assert_eq!(st.rows, 2);
        assert_eq!(st.rows_without_request_visibility, 1);
        assert_eq!(st.oldest, Some(at(0)));
        assert_eq!(st.newest, Some(at(60)));
        assert_eq!(st.capacity(), Duration::from_secs(8 * 60));
        assert!(st.created.is_some());
    }

    #[test]
    fn a_file_the_user_may_not_look_at_still_counts_as_there() {
        // A missing file is not there; a file that denies access is, and reads as needs-admin.
        assert!(ring_is_there(Ok(())));
        assert!(ring_is_there(Err(io::Error::from_raw_os_error(5)))); // ERROR_ACCESS_DENIED
        assert!(!ring_is_there(Err(io::Error::from_raw_os_error(2)))); // ERROR_FILE_NOT_FOUND
        assert!(!ring_is_there(Err(io::Error::from_raw_os_error(3)))); // ERROR_PATH_NOT_FOUND
        let denied = RingError::Io(io::Error::from_raw_os_error(5));
        assert_eq!(access_from_error(&denied), Access::NeedsAdmin);
    }

    /// Needs `icacls`, which is on every Windows; makes a real file this user cannot open.
    #[cfg(windows)]
    #[test]
    fn a_ring_the_user_cannot_open_is_chosen_and_reads_as_needs_admin_not_missing() {
        let dir = Dir::new("denied");
        let denied = dir.ring();
        write(&denied, &[sample(0, true)]);
        let icacls = |args: &[&str]| {
            std::process::Command::new("icacls")
                .arg(&dir.0)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        };
        // Only SYSTEM may use the folder, and the file inside inherits that. (No /T: icacls cannot
        // recurse into a folder it has just locked itself out of; the change reaches the file anyway.)
        assert!(icacls(&[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F"
        ]));
        let user = dir.0.join("user.ring");
        let picked = pick_ring(&denied, &user);
        let rows = read_rows(&denied, at(0));
        // Put the permissions back so the folder can be cleaned up, then judge.
        let restored = icacls(&["/reset", "/T"]);
        assert!(restored, "could not restore the folder's permissions");
        assert_eq!(
            picked, denied,
            "an unreadable service ring was treated as missing"
        );
        assert_eq!(rows.access, Access::NeedsAdmin);
        assert!(rows.data.is_empty());
    }

    #[test]
    fn a_ring_is_stale_after_three_intervals_and_at_least_a_minute() {
        let secs = Duration::from_secs;
        assert!(!is_stale(secs(59), 5));
        assert!(!is_stale(secs(60), 5));
        assert!(is_stale(secs(61), 5));
        assert!(!is_stale(secs(180), 60));
        assert!(is_stale(secs(181), 60));
        assert!(!is_stale(secs(0), 60));
    }

    #[test]
    fn status_says_how_old_the_newest_row_is() {
        let dir = Dir::new("age");
        write(&dir.ring(), &[sample(0, true), sample(60, true)]);
        let st = status(&dir.ring()).data.remove(0);
        // Judged at fixed moments, so the test does not depend on the clock it runs under.
        assert_eq!(st.newest_age(at(60 + 30)), Some(Duration::from_secs(30)));
        assert!(!st.looks_stopped(at(60 + 30)));
        assert!(st.looks_stopped(at(60 + 3_600)));
        // A newest row dated after `now` (the clock was set back) has no age and is not called stale.
        assert_eq!(st.newest_age(at(10)), None);
        assert!(!st.looks_stopped(at(10)));
        let empty = Dir::new("age-empty");
        write(&empty.ring(), &[]);
        let st = status(&empty.ring()).data.remove(0);
        assert_eq!(st.newest_age(at(1_000_000)), None);
        assert!(!st.looks_stopped(at(1_000_000)));
    }

    #[test]
    fn paths_end_in_the_app_folder_and_ring_file() {
        for path in [service_ring_path(), user_ring_path(), default_ring_path()] {
            assert!(
                path.ends_with(Path::new(APP_DIR).join(RING_FILE)),
                "{path:?}"
            );
        }
    }
}
