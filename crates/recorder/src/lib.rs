//! The opt-in recorder (ADR 0006): what the logs miss, kept in one fixed-size ring file.
//!
//! This is the reading side the engine uses, plus the sampler and the Windows service behind the
//! `pcsleuth-recorder` binary. The OS calls are behind `#[cfg(windows)]`; the ring format, the
//! sample mapping and the loop build and test anywhere. `unsafe` appears only in the Windows
//! modules, each use with a safety comment.
//!
//! - [`default_ring_path`]: where to look. The service's ring if there is one, else the user's.
//! - [`read_rows`]: the rows since a time, as the contract type. No ring file is
//!   [`Access::Missing`], never an error.
//! - [`read_samples`]: the same rows with whether each could see power requests. Prefer this when
//!   an empty `power_requests` must not be read as "none held".
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

/// The ring to read: the service's if that file exists, else the user's. The path may not exist,
/// and reading it then says [`Access::Missing`].
pub fn default_ring_path() -> PathBuf {
    let service = service_ring_path();
    if service.exists() {
        service
    } else {
        user_ring_path()
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

/// The samples at or after `since`, oldest first, with whether each could see power requests.
///
/// A missing file is [`Access::Missing`] and an unreadable one [`Access::NeedsAdmin`] or
/// [`Access::Failed`], all with no data. A ring with torn or damaged slots is
/// [`Access::Partial`] saying how many were skipped, with the rest returned.
pub fn read_samples(path: &Path, since: Timestamp) -> Sourced<Sample> {
    let source = SourceId::Recorder;
    let scan = match read_scan(path) {
        Ok(scan) => scan,
        Err(e) => return Sourced::unreadable(source, access_from_error(&e)),
    };
    let data: Vec<Sample> = scan
        .samples
        .into_iter()
        .map(|(_, sample)| sample)
        .filter(|s| s.row.at >= since)
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

/// The rows at or after `since`, oldest first, as the contract type.
///
/// `RecorderRow` cannot say that a row was recorded without admin, when power requests were not
/// visible and an empty list means nothing. So that is reported here as [`Access::Partial`]
/// together with any skipped slots; the engine should use [`read_samples`] to know which rows.
pub fn read_rows(path: &Path, since: Timestamp) -> Sourced<RecorderRow> {
    let read = read_samples(path, since);
    let blind = read.data.iter().filter(|s| !s.requests_visible).count();
    let access = match (read.access, blind) {
        (access, 0) => access,
        (Access::Ok, blind) => Access::Partial {
            message: blind_message(blind, read.data.len()),
        },
        (Access::Partial { message }, blind) => Access::Partial {
            message: format!("{message}; {}", blind_message(blind, read.data.len())),
        },
        (other, _) => other,
    };
    Sourced {
        source: read.source,
        access,
        data: read.data.into_iter().map(|s| s.row).collect(),
    }
}

fn blind_message(blind: usize, total: usize) -> String {
    format!(
        "power requests were not visible in {blind} of {total} row(s) because the recorder was \
         not elevated, so an empty list there does not mean none were held"
    )
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
            .filter(|(_, s)| !s.requests_visible)
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
            },
            requests_visible: visible,
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
        assert_eq!(read_samples(&dir.ring(), at(0)).access, Access::Missing);
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
    fn rows_recorded_without_admin_are_flagged_through_partial() {
        let dir = Dir::new("blind");
        write(
            &dir.ring(),
            &[sample(0, false), sample(60, true), sample(120, false)],
        );
        let samples = read_samples(&dir.ring(), at(0));
        assert_eq!(samples.access, Access::Ok);
        assert_eq!(
            samples
                .data
                .iter()
                .map(|s| s.requests_visible)
                .collect::<Vec<_>>(),
            vec![false, true, false]
        );
        let rows = read_rows(&dir.ring(), at(0));
        match rows.access {
            Access::Partial { message } => assert!(message.contains("2 of 3"), "{message}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(rows.data.len(), 3);
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
    fn paths_end_in_the_app_folder_and_ring_file() {
        for path in [service_ring_path(), user_ring_path(), default_ring_path()] {
            assert!(
                path.ends_with(Path::new(APP_DIR).join(RING_FILE)),
                "{path:?}"
            );
        }
    }
}
