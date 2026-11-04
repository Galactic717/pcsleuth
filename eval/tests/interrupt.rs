//! Ctrl+C handling. This file holds one test on purpose: the interrupt flag is process-wide, and
//! each file under tests/ is its own process, so setting it here cannot leak into other tests.
#![cfg(windows)]

use std::path::Path;
use std::time::{Duration, Instant};

use pcsleuth_eval::fault::disk_dir;
use pcsleuth_eval::runner::Injected;
use pcsleuth_eval::scenario::Fault;
use pcsleuth_eval::sys::{self, Job};

const DISK: &str = env!("CARGO_BIN_EXE_pcsleuth-fault-disk");

#[test]
fn an_interrupt_stops_the_waits_and_the_guard_cleans_up() {
    let job = Job::new().unwrap();
    let args = ["--secs", "120", "--mb", "8"].map(String::from);
    let mut injected = Injected::spawn(&job, Path::new(DISK), Fault::Disk, &args).unwrap();
    injected.wait_ready().unwrap();
    let dir = disk_dir(injected.pid());
    assert!(dir.is_dir());

    assert!(!sys::interrupted());
    sys::request_interrupt();
    assert!(sys::interrupted());

    // The same call that would wait up to 140 s gives up at once.
    let started = Instant::now();
    let error = injected.wait_exit(Duration::from_secs(140)).unwrap_err();
    assert!(error.to_string().contains("interrupted"), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(2));

    // And unwinding the guard kills the injector and removes its scratch directory.
    drop(injected);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(!dir.exists(), "{} was left behind", dir.display());
}
