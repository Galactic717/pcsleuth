//! Runs the real `pcsleuth-recorder` binary. None of these install anything: the ones that
//! would need administrator rights are skipped when the test itself is elevated, so a CI runner
//! that is an administrator never registers a service. The elevated paths are in `elevated.rs`.
#![cfg(windows)]

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use pcsleuth_core::Access;
use pcsleuth_recorder::{read_rows, ring, status};
use pcsleuth_sources::power::is_elevated;

const BIN: &str = env!("CARGO_BIN_EXE_pcsleuth-recorder");
const T0: i64 = 1_700_000_000; // well before any ring in these tests

struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("pcsleuth-bin-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
    fn ring(&self) -> PathBuf {
        self.0.join("test.ring")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn service_query() -> (Option<i32>, String) {
    let out = Command::new("sc.exe")
        .args(["query", "pcsleuth-recorder"])
        .output()
        .unwrap();
    (out.status.code(), text(&out.stdout))
}

#[test]
fn install_and_uninstall_refuse_without_elevation_and_change_nothing() {
    if is_elevated() {
        eprintln!("skipped: this test run is elevated, so install would really install");
        return;
    }
    let before = service_query();
    for command in ["install", "uninstall"] {
        let out = run(&[command]);
        assert_eq!(out.status.code(), Some(5), "{command}");
        let message = text(&out.stderr);
        assert!(message.contains("administrator"), "{message}");
        assert!(message.contains("Nothing was changed"), "{message}");
        assert!(out.stdout.is_empty());
        if command == "install" {
            // This binary is in a build folder, which is the second reason it is refused.
            assert!(message.contains("Program Files"), "{message}");
        }
    }
    assert_eq!(service_query(), before);
}

#[test]
fn run_service_from_a_terminal_is_refused_with_the_reason() {
    let out = run(&["run-service"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("--foreground"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_command_is_required_and_the_help_names_them() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    let message = text(&out.stderr);
    assert!(
        message.contains("--foreground") && message.contains("install"),
        "{message}"
    );
    let help = text(&run(&["--help"]).stdout);
    for word in [
        "--foreground",
        "--measure",
        "--interval",
        "install",
        "uninstall",
        "status",
        "run-service",
    ] {
        assert!(help.contains(word), "{word} missing from help");
    }
}

#[test]
fn status_of_a_missing_ring_says_so_and_fails() {
    let dir = Scratch::new("nostatus");
    let out = run(&["status", "--ring", dir.ring().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("No ring file"),
        "{}",
        text(&out.stdout)
    );
}

fn a_sample(secs: i64) -> ring::Sample {
    ring::Sample {
        row: pcsleuth_core::RecorderRow {
            at: jiff::Timestamp::from_second(T0 + secs).unwrap(),
            interval_secs: 60,
            top_cpu: vec![],
            top_io: vec![],
            power_requests: vec![],
            requests_visible: true,
        },
        truncated: false,
    }
}

#[test]
fn measure_never_deletes_a_ring_that_was_already_there() {
    let dir = Scratch::new("measure-keeps");
    let path = dir.ring();
    {
        let mut w = ring::RingWriter::open(&path, 8 * ring::BLOCK as u64, 60).unwrap();
        for n in 0..3 {
            w.append(&a_sample(n)).unwrap();
        }
    }
    let out = run(&[
        "--measure",
        "2",
        "--interval",
        "1",
        "--ring",
        path.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    // Still there, still the same size, and its three old rows are still in it.
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        8 * ring::BLOCK as u64
    );
    let since = jiff::Timestamp::from_second(T0).unwrap();
    let rows = read_rows(&path, since);
    assert!(rows.data.len() >= 3, "{} rows", rows.data.len());
    assert!(rows.data.iter().take(3).all(|r| r.interval_secs == 60));
}

#[test]
fn a_damaged_ring_is_refused_with_the_reason_and_kept_until_reset_is_asked_for() {
    let dir = Scratch::new("damaged");
    let path = dir.ring();
    {
        let mut w = ring::RingWriter::open(&path, 8 * ring::BLOCK as u64, 60).unwrap();
        for n in 0..3 {
            w.append(&a_sample(n)).unwrap();
        }
    }
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[24] ^= 0xFF; // the header's creation time, which its checksum covers
    std::fs::write(&path, &bytes).unwrap();
    let ring_arg = path.to_str().unwrap();

    // Recording is refused at once, says why and how to start over, and changes nothing.
    let out = run(&["--foreground", "--ring", ring_arg]);
    assert_eq!(out.status.code(), Some(1));
    let message = text(&out.stderr);
    assert!(
        message.contains("damaged") && message.contains("reset"),
        "{message}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    // So does a second recorder-run, and reading it reports the damage rather than panicking.
    let shown = run(&["status", "--ring", ring_arg]);
    assert_eq!(shown.status.code(), Some(1));
    assert!(
        text(&shown.stdout).contains("damaged"),
        "{}",
        text(&shown.stdout)
    );

    // Only the explicit command starts over.
    let reset = run(&["reset", "--ring", ring_arg]);
    assert!(reset.status.success(), "{}", text(&reset.stderr));
    assert!(text(&reset.stdout).contains("history is gone"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), ring::DEFAULT_BYTES);
    let st = status(&path);
    assert_eq!((st.access, st.data[0].rows), (Access::Ok, 0));

    // And it will not touch a file that is not a ring.
    std::fs::write(&path, b"not a ring, just a file somebody cares about").unwrap();
    let refused = run(&["reset", "--ring", ring_arg]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"not a ring, just a file somebody cares about"
    );
}

#[test]
fn measure_runs_real_ticks_and_reports_cpu_memory_and_bytes() {
    let dir = Scratch::new("measure");
    let out = run(&[
        "--measure",
        "3",
        "--interval",
        "1",
        "--ring",
        dir.ring().to_str().unwrap(),
    ]);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}\n{}", text(&out.stderr));
    for needle in [
        "window (wall clock)",
        "ticks:",
        "CPU used (GetProcessTimes)",
        "working set:",
        "bytes written:",
    ] {
        assert!(stdout.contains(needle), "{needle} missing:\n{stdout}");
    }
    eprintln!("{stdout}");
    // The measurement ring is scratch and is removed afterwards.
    assert!(!dir.ring().exists());
}

fn wait_for(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Needs a console to send Ctrl+Break through, which a test run without one (some CI hosts, an
/// IDE) does not have, so it is run by hand: `cargo test -p pcsleuth-recorder -- --ignored console`.
#[test]
#[ignore = "needs a console to send Ctrl+Break through"]
fn console_ctrl_break_stops_foreground_cleanly_and_what_it_wrote_reads_back() {
    use windows::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};

    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let dir = Scratch::new("foreground");
    let mut child = Command::new(BIN)
        .args([
            "--foreground",
            "--interval",
            "1",
            "--ring",
            dir.ring().to_str().unwrap(),
        ])
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(5_500));
    // The new process group id is the child's pid. Ctrl+Break reaches only that group.
    // SAFETY: plain call with a pid and a signal kind; no pointers.
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) }
        .expect("no console to send Ctrl+Break through");
    let Some(exit) = wait_for(&mut child, Duration::from_secs(15)) else {
        let _ = child.kill();
        panic!("the recorder did not stop on Ctrl+Break");
    };
    let out = child.wait_with_output().unwrap();
    let stdout = text(&out.stdout);
    eprintln!("{stdout}\n{}", text(&out.stderr));
    assert!(exit.success(), "{exit:?}");
    assert!(stdout.contains("Stopped."), "{stdout}");

    // What it wrote reads back through the library and through `status`, and the file is the size
    // it was created with.
    let since = jiff::Timestamp::from_second(T0).unwrap();
    let rows = read_rows(&dir.ring(), since);
    assert!(
        rows.data.len() >= 3,
        "{} rows, {:?}",
        rows.data.len(),
        rows.access
    );
    assert!(rows.data.iter().all(|r| r.interval_secs >= 1));
    // Every row says whether power requests could be seen. Unelevated they cannot, and the read is
    // still Ok: these are good samples, not a damaged ring.
    assert!(
        rows.data
            .iter()
            .all(|r| r.requests_visible == is_elevated())
    );
    assert_eq!(rows.access, Access::Ok);
    let st = status(&dir.ring());
    assert_eq!(st.data[0].size_bytes, ring::DEFAULT_BYTES);
    assert_eq!(
        std::fs::metadata(dir.ring()).unwrap().len(),
        ring::DEFAULT_BYTES
    );
    let shown = text(&run(&["status", "--ring", dir.ring().to_str().unwrap()]).stdout);
    eprintln!("{shown}");
    assert!(
        shown.contains("rows:") && shown.contains("16777216 bytes"),
        "{shown}"
    );
}
