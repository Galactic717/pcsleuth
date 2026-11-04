//! Fault: writes to disk, paced, under one scratch directory in the temp folder that it deletes
//! on exit. `--secs N` (default 20, at most 600), `--mb N` total to write (default 256, at most
//! 1024), `--mb-per-sec N` (default 32, at most 256). Needs no admin and touches nothing else.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use pcsleuth_eval::fault;

const MIB: usize = 1024 * 1024;

/// Deletes the scratch directory however the run ends, including a panic.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn main() -> ExitCode {
    let run = fault::start(20);
    let budget = fault::number("--mb", 256, 1, 1024) * MIB as u64;
    let rate = fault::number("--mb-per-sec", 32, 1, 256) as f64 * MIB as f64;

    let dir = fault::disk_dir(std::process::id());
    let _ = fs::remove_dir_all(&dir);
    if let Err(error) = fs::create_dir_all(&dir) {
        return fault::fail(error);
    }
    let scratch = Scratch(dir);
    let mut file = match File::create(scratch.0.join("hog.bin")) {
        Ok(file) => file,
        Err(error) => return fault::fail(error),
    };

    fault::ready();
    let chunk = vec![0xA5u8; MIB];
    let started = Instant::now();
    let mut written = 0u64;
    while !run.expired() && written < budget {
        // sync_data makes each chunk reach the disk, so the I/O is real and not just cache.
        if let Err(error) = file.write_all(&chunk).and_then(|()| file.sync_data()) {
            return fault::fail(error);
        }
        written += MIB as u64;
        let due = Duration::from_secs_f64(written as f64 / rate);
        if let Some(wait) = due.checked_sub(started.elapsed()) {
            std::thread::sleep(wait.min(Duration::from_millis(500)));
        }
    }
    // The budget is spent: free the space now, stay alive until the deadline.
    drop(file);
    let _ = fs::remove_dir_all(&scratch.0);
    run.hold();
    ExitCode::SUCCESS
}
