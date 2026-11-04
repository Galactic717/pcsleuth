//! Runs the safe injectors for real: each says `ready`, exits by itself, and leaves nothing behind.
//! The crash and hang injectors are not run here: they write events into the owner's log, so only
//! the evaluation run itself does that.
#![cfg(windows)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::{Duration, Instant};

use pcsleuth_eval::fault::disk_dir;
use pcsleuth_eval::runner::Injected;
use pcsleuth_eval::scenario::Fault;
use pcsleuth_eval::sys::Job;

fn spawn(job: &Job, exe: &str, fault: Fault, args: &[&str]) -> anyhow::Result<Injected> {
    let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
    Injected::spawn(job, Path::new(exe), fault, &args)
}

const CPU: &str = env!("CARGO_BIN_EXE_pcsleuth-fault-cpu");
const DISK: &str = env!("CARGO_BIN_EXE_pcsleuth-fault-disk");
const POWER: &str = env!("CARGO_BIN_EXE_pcsleuth-fault-power-request");
const TIMER: &str = env!("CARGO_BIN_EXE_pcsleuth-fault-wake-timer");
const IDLE: &str = env!("CARGO_BIN_EXE_pcsleuth-fault-idle");

#[test]
fn the_safe_injectors_say_ready_and_exit_by_themselves() {
    let job = Job::new().unwrap();
    for (exe, fault) in [
        (CPU, Fault::Cpu),
        (DISK, Fault::Disk),
        (POWER, Fault::PowerRequest),
        (IDLE, Fault::Idle),
    ] {
        let started = Instant::now();
        let mut injected = spawn(&job, exe, fault, &["--secs", "1"]).unwrap();
        injected.wait_ready().unwrap();
        let status = injected.wait_exit(Duration::from_secs(15)).unwrap();
        assert!(status.success(), "{}: {status}", fault.exe());
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "{}",
            fault.exe()
        );
    }
}

#[test]
fn the_wake_timer_injector_arms_or_says_why_it_cannot() {
    let job = Job::new().unwrap();
    let mut injected = spawn(&job, TIMER, Fault::WakeTimer, &["--secs", "1"]).unwrap();
    match injected.wait_ready() {
        Ok(()) => assert!(
            injected
                .wait_exit(Duration::from_secs(15))
                .unwrap()
                .success()
        ),
        // A VM or a PC without resume timers: the injector must say so, not crash.
        Err(error) => assert!(error.to_string().contains("reported error:"), "{error:#}"),
    }
}

#[test]
fn the_disk_hog_deletes_its_scratch_directory() {
    let job = Job::new().unwrap();
    let mut injected = spawn(&job, DISK, Fault::Disk, &["--secs", "2", "--mb", "8"]).unwrap();
    injected.wait_ready().unwrap();
    let dir = disk_dir(injected.pid());
    assert!(dir.is_dir(), "the scratch directory exists while it runs");
    assert!(
        injected
            .wait_exit(Duration::from_secs(20))
            .unwrap()
            .success()
    );
    assert!(!dir.exists(), "{} was not deleted", dir.display());
}

#[test]
fn the_disk_hog_never_writes_more_than_it_was_told() {
    let job = Job::new().unwrap();
    let mut injected = spawn(&job, DISK, Fault::Disk, &["--secs", "5", "--mb", "4"]).unwrap();
    injected.wait_ready().unwrap();
    let dir = disk_dir(injected.pid());
    // Watch the directory while it runs; it must never hold more than the 4 MiB budget.
    let mut largest = 0;
    while injected.wait_exit(Duration::from_millis(100)).is_err() {
        if let Ok(meta) = std::fs::metadata(dir.join("hog.bin")) {
            largest = largest.max(meta.len());
        }
    }
    assert!(largest <= 4 * 1024 * 1024, "wrote {largest} bytes");
}

#[test]
fn dropping_an_injector_kills_it_and_cleans_up() {
    let job = Job::new().unwrap();
    let mut injected = spawn(&job, DISK, Fault::Disk, &["--secs", "120", "--mb", "8"]).unwrap();
    injected.wait_ready().unwrap();
    let dir = disk_dir(injected.pid());
    let started = Instant::now();
    drop(injected);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "drop waited for the time bound"
    );
    assert!(!dir.exists(), "{} was left behind", dir.display());
}

#[test]
fn a_panic_in_a_scenario_still_cleans_up() {
    let job = Job::new().unwrap();
    let mut dir = None;
    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut injected = spawn(&job, DISK, Fault::Disk, &["--secs", "120", "--mb", "8"]).unwrap();
        injected.wait_ready().unwrap();
        dir = Some(disk_dir(injected.pid()));
        panic!("a scenario blew up");
    }));
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(20));
    let dir = dir.expect("the injector started");
    assert!(
        !dir.exists(),
        "{} was left behind after a panic",
        dir.display()
    );
}

#[test]
fn an_injector_that_does_not_exist_is_an_error_not_a_panic() {
    let job = Job::new().unwrap();
    assert!(spawn(&job, r"C:\no\such\pcsleuth-fault-cpu.exe", Fault::Cpu, &[]).is_err());
}
