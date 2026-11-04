//! What every `pcsleuth-fault-*` injector shares: a hard time bound, the `ready` line, Ctrl+C.
//!
//! Protocol with the runner: the first line on stdout is `ready` once the fault is active, or
//! `error: <why>` followed by exit code 1. Every injector exits on its own by `--secs` at the
//! latest, never later than [`MAX_SECS`] whatever it is told.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::sys;

/// No injector runs longer than this, even when asked to.
pub const MAX_SECS: u64 = 600;

/// The exe names the scorer looks for. One per fault, see `scenario::Fault`.
pub const EXE_PREFIX: &str = "pcsleuth-fault-";

/// `--secs`, clamped to `1..=MAX_SECS`; `default` when absent or not a number.
pub fn clamp_secs(raw: Option<&str>, default: u64) -> u64 {
    raw.and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(1, MAX_SECS)
}

/// The value after `name` on the command line, such as `--secs 30`.
pub fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}

/// A numeric option, clamped to `min..=max`, or `default`.
pub fn number(name: &str, default: u64, min: u64, max: u64) -> u64 {
    arg(name)
        .and_then(|text| text.parse::<u64>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

/// The deadline of one injector run.
#[derive(Clone, Copy)]
pub struct Bounded {
    end: Instant,
}

/// Install the Ctrl+C handler and start the clock. `default_secs` applies without `--secs`.
pub fn start(default_secs: u64) -> Bounded {
    sys::install_ctrl_handler();
    let secs = clamp_secs(arg("--secs").as_deref(), default_secs);
    Bounded {
        end: Instant::now() + Duration::from_secs(secs),
    }
}

impl Bounded {
    /// True at the deadline or after Ctrl+C.
    pub fn expired(&self) -> bool {
        Instant::now() >= self.end || sys::interrupted()
    }

    /// Sleep until the deadline, waking often enough to notice Ctrl+C.
    pub fn hold(&self) {
        while !self.expired() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Tell the runner the fault is active. Not `println!`, which panics when the pipe is gone.
pub fn ready() {
    say("ready");
}

/// Tell the runner why the fault could not be created, and fail.
pub fn fail(why: impl std::fmt::Display) -> ExitCode {
    say(&format!("error: {why}"));
    ExitCode::FAILURE
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// For platforms the faults cannot be created on.
pub fn unsupported() -> ExitCode {
    fail("the fault injectors run on Windows only")
}

/// The scratch directory of the disk hog with this process id. The hog deletes it itself; the
/// runner deletes it too in case the hog was killed first.
pub fn disk_dir(pid: u32) -> PathBuf {
    std::env::temp_dir().join(format!("{EXE_PREFIX}disk-{pid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secs_are_bounded_whatever_the_input() {
        assert_eq!(clamp_secs(None, 30), 30);
        assert_eq!(clamp_secs(Some("5"), 30), 5);
        assert_eq!(clamp_secs(Some("0"), 30), 1);
        assert_eq!(clamp_secs(Some("99999999"), 30), MAX_SECS);
        assert_eq!(clamp_secs(Some("-3"), 30), 30);
        assert_eq!(clamp_secs(Some("soon"), 30), 30);
        assert_eq!(clamp_secs(Some("99999999999999999999999"), 30), 30);
        assert_eq!(clamp_secs(None, 100_000), MAX_SECS);
    }

    #[test]
    fn the_disk_dir_is_under_temp_and_per_process() {
        let dir = disk_dir(4242);
        assert!(dir.starts_with(std::env::temp_dir()));
        assert!(dir.ends_with("pcsleuth-fault-disk-4242"));
    }
}
