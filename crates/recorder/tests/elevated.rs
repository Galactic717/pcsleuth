//! Paths that need administrator rights, so they could not be run when the recorder was written.
//! Every test here is ignored by default and refuses to start unless the test process is elevated.
//!
//! Run them from an elevated prompt, with the owner's permission, because one of them really
//! installs, starts, stops and removes the Windows service `pcsleuth-recorder`:
//!
//! ```text
//! cargo test -p pcsleuth-recorder --test elevated -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! They never trigger sleep and change nothing outside the service, its folder under
//! `%ProgramData%\pcsleuth` and a scratch folder in the temp directory.
#![cfg(windows)]

use std::process::Command;
use std::time::{Duration, Instant};

use pcsleuth_core::Access;
use pcsleuth_recorder::runner::{Live, Tick};
use pcsleuth_recorder::service::{self, SERVICE_NAME};
use pcsleuth_recorder::{read_samples, service_ring_path, status, winapi};
use pcsleuth_sources::power::is_elevated;

const BIN: &str = env!("CARGO_BIN_EXE_pcsleuth-recorder");

fn require_elevation() {
    assert!(
        is_elevated(),
        "run this test from an elevated prompt (Run as administrator)"
    );
}

fn sc(args: &[&str]) -> (i32, String) {
    let out = Command::new("sc.exe").args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn wait_for_state(wanted: &str, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        let (_, text) = sc(&["query", SERVICE_NAME]);
        if text.contains(wanted) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// Removes the service and its data when a test ends, however it ends.
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = service::uninstall();
    }
}

/// A copy of the recorder in a new folder under Program Files, the only kind of place `install`
/// accepts. Removed on drop; declare it before [`Cleanup`] so the service is gone first.
struct ProgramFilesCopy {
    dir: std::path::PathBuf,
    exe: std::path::PathBuf,
}

impl ProgramFilesCopy {
    fn new() -> ProgramFilesCopy {
        let dir = winapi::program_files_dir()
            .unwrap()
            .join(format!("pcsleuth-recorder-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("pcsleuth-recorder.exe");
        std::fs::copy(BIN, &exe).unwrap();
        ProgramFilesCopy { dir, exe }
    }
}

impl Drop for ProgramFilesCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
#[ignore = "needs an elevated prompt; installs and removes a real service"]
fn elevated_a_tick_sees_power_requests() {
    require_elevation();
    // A first sample, then a tick after a second: the row exists and says requests were visible.
    let mut live = Live::start();
    std::thread::sleep(Duration::from_millis(1_000));
    match live.tick() {
        Tick::Row(sample) => {
            assert!(
                sample.requests_visible,
                "power_requests was not readable while elevated"
            );
            eprintln!(
                "{} power request(s) held: {:?}",
                sample.row.power_requests.len(),
                sample.row.power_requests
            );
        }
        Tick::Baseline => panic!("expected a row from the second sample"),
        Tick::Unreadable => panic!("the process list was unreadable"),
    }
}

#[test]
#[ignore = "needs an elevated prompt; installs and removes a real service"]
fn elevated_install_start_record_stop_uninstall() {
    require_elevation();
    let copy = ProgramFilesCopy::new();
    let _cleanup = Cleanup;
    // Start from nothing: a leftover from an earlier run is removed first.
    let _ = service::uninstall();

    // Elevated, but run from the build folder, which any program of the user can write: refused
    // with exit code 6 and nothing created.
    let outside = Command::new(BIN).arg("install").output().unwrap();
    assert_eq!(outside.status.code(), Some(6), "{outside:?}");
    assert!(String::from_utf8_lossy(&outside.stderr).contains("Program Files"));
    assert_eq!(sc(&["query", SERVICE_NAME]).0, 1060);

    let install = Command::new(&copy.exe)
        .args(["install", "--interval", "2"])
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&install.stdout).into_owned();
    assert!(
        install.status.success(),
        "{said}\n{}",
        String::from_utf8_lossy(&install.stderr)
    );
    eprintln!("{said}");

    // Installed for manual start, not running, with the protected folder in place.
    let (code, text) = sc(&["qc", SERVICE_NAME]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("DEMAND_START"), "{text}");
    assert!(text.contains("LocalSystem"), "{text}");
    let (_, text) = sc(&["query", SERVICE_NAME]);
    assert!(text.contains("STOPPED"), "{text}");
    let folder = service_ring_path().parent().unwrap().to_path_buf();
    let sddl = winapi::dacl_sddl(&folder).unwrap();
    eprintln!("folder DACL: {sddl}");
    assert!(sddl.starts_with("D:P"), "{sddl}");
    assert_eq!(sddl.matches("(A;").count(), 3, "{sddl}");

    // A second install is refused, not duplicated.
    let again = Command::new(&copy.exe).arg("install").output().unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("already installed"));

    // Start it, wait for a few rows, and check what was recorded.
    let (code, text) = sc(&["start", SERVICE_NAME]);
    assert_eq!(code, 0, "{text}");
    assert!(
        wait_for_state("RUNNING", Duration::from_secs(15)),
        "did not reach RUNNING"
    );
    let ring = service_ring_path();
    let end = Instant::now() + Duration::from_secs(30);
    let since = jiff::Timestamp::from_second(1_700_000_000).unwrap();
    while Instant::now() < end && read_samples(&ring, since).data.len() < 3 {
        std::thread::sleep(Duration::from_millis(500));
    }
    let samples = read_samples(&ring, since);
    assert!(
        samples.data.len() >= 3,
        "{} rows, {:?}",
        samples.data.len(),
        samples.access
    );
    // LocalSystem can read the power request list, so every row says requests were visible.
    assert!(
        samples.data.iter().all(|s| s.requests_visible),
        "{:?}",
        samples.access
    );
    let st = status(&ring);
    assert_eq!(st.access, Access::Ok);
    assert_eq!(st.data[0].size_bytes, pcsleuth_recorder::DEFAULT_BYTES);

    // Stop: it reports STOPPED and the file keeps its size.
    let (code, text) = sc(&["stop", SERVICE_NAME]);
    assert_eq!(code, 0, "{text}");
    assert!(
        wait_for_state("STOPPED", Duration::from_secs(20)),
        "did not stop"
    );
    assert_eq!(
        std::fs::metadata(&ring).unwrap().len(),
        pcsleuth_recorder::DEFAULT_BYTES
    );

    // Uninstall removes the service, the ring and the folder.
    let uninstall = Command::new(BIN).arg("uninstall").output().unwrap();
    assert!(
        uninstall.status.success(),
        "{}",
        String::from_utf8_lossy(&uninstall.stderr)
    );
    let (code, _) = sc(&["query", SERVICE_NAME]);
    assert_eq!(code, 1060, "the service should be gone");
    assert!(!ring.exists());
    assert!(!folder.exists());
}

#[test]
#[ignore = "needs an elevated prompt; installs and removes a real service"]
fn elevated_service_started_at_boot_is_what_auto_start_asks_for() {
    require_elevation();
    let copy = ProgramFilesCopy::new();
    let _cleanup = Cleanup;
    let _ = service::uninstall();
    let install = Command::new(&copy.exe)
        .args(["install", "--auto-start"])
        .output()
        .unwrap();
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    let (_, text) = sc(&["qc", SERVICE_NAME]);
    assert!(text.contains("AUTO_START"), "{text}");
    // Not started here: the point is only that the start type was recorded as asked.
    let (_, text) = sc(&["query", SERVICE_NAME]);
    assert!(text.contains("STOPPED"), "{text}");
}
