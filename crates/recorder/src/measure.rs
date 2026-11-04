//! `--measure`: run real ticks for a stated time and report what the recorder itself costs.
//!
//! The ticks are the production ones (same loop, same sources, same ring writes, same thread
//! priority). The window starts after the ring exists and the baseline sample is taken, so it
//! covers steady state; the process start and the ring creation are one-off and reported apart.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::ring::{DEFAULT_BYTES, RingError, RingWriter};
use crate::runner::{self, Event, Live};
use crate::winapi;

/// The CPU a process used, as a percentage of the whole machine (all logical processors).
pub fn percent_of_machine(cpu: Duration, wall: Duration, logical_cpus: u32) -> f64 {
    if wall.is_zero() {
        return 0.0;
    }
    cpu.as_secs_f64() / (wall.as_secs_f64() * f64::from(logical_cpus.max(1))) * 100.0
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub ring: PathBuf,
    pub elevated: bool,
    pub logical_cpus: u32,
    pub interval: Duration,
    /// The wall time the window really lasted.
    pub wall: Duration,
    pub ticks: u32,
    pub rows: u32,
    pub rows_with_requests_visible: u32,
    /// Kernel plus user CPU time of this process in the window, from `GetProcessTimes`.
    pub cpu: Duration,
    /// `cpu` as a percentage of the whole machine.
    pub cpu_percent: f64,
    /// Wall time spent inside ticks (reading, ranking, writing). The CPU the recorder used cannot
    /// be more than this on one thread, and unlike `cpu` it is not read in 15.6 ms steps.
    pub busy: Duration,
    /// `busy` as a percentage of the whole machine: an upper bound for the same quantity.
    pub busy_percent: f64,
    pub slowest_tick: Duration,
    pub working_set: u64,
    pub peak_working_set: u64,
    /// Bytes the ring writer wrote in the window (slots and header).
    pub ring_bytes_written: u64,
    /// Bytes the process asked Windows to write in the window, of every kind.
    pub write_transfer_bytes: Option<u64>,
    pub ring_file_bytes: u64,
}

/// Run the recorder's loop for `duration` and measure it. `stop` ends the run early, in which case
/// the report covers the time that passed.
pub fn measure(
    ring_path: &Path,
    duration: Duration,
    interval: Duration,
    stop: &Receiver<()>,
) -> Result<Report, RingError> {
    let mut ring = RingWriter::open(
        ring_path,
        DEFAULT_BYTES,
        u32::try_from(interval.as_secs()).unwrap_or(u32::MAX),
    )?;
    // Best effort, as in the service; the report does not claim priority it did not get.
    let _ = winapi::lower_thread_priority();
    let mut live = Live::start();

    let mut visible_rows = 0u32;
    let ring_before = ring.bytes_written();
    let io_before = winapi::write_transfer_bytes();
    let cpu_before = winapi::process_cpu_ticks();
    let started = Instant::now();
    let stats = runner::run(
        &mut ring,
        interval,
        stop,
        Some(started + duration),
        || live.tick(),
        |event| {
            if let Event::Row(sample) = event {
                visible_rows += u32::from(sample.requests_visible);
            }
        },
    );
    let wall = started.elapsed();
    let cpu = Duration::from_nanos((winapi::process_cpu_ticks() - cpu_before) * 100);
    let io_after = winapi::write_transfer_bytes();
    let memory = winapi::memory_use();
    let logical_cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);

    Ok(Report {
        ring: ring_path.to_path_buf(),
        elevated: pcsleuth_sources::power::is_elevated(),
        logical_cpus,
        interval,
        wall,
        ticks: stats.ticks,
        rows: stats.rows_written,
        rows_with_requests_visible: visible_rows,
        cpu,
        cpu_percent: percent_of_machine(cpu, wall, logical_cpus),
        busy: stats.busy,
        busy_percent: percent_of_machine(stats.busy, wall, logical_cpus),
        slowest_tick: stats.slowest_tick,
        working_set: memory.map_or(0, |m| m.working_set),
        peak_working_set: memory.map_or(0, |m| m.peak_working_set),
        ring_bytes_written: ring.bytes_written() - ring_before,
        write_transfer_bytes: io_before.zip(io_after).map(|(a, b)| b.saturating_sub(a)),
        ring_file_bytes: ring.header().file_bytes(),
    })
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
        writeln!(
            f,
            "ring file:               {} ({} bytes)",
            self.ring.display(),
            self.ring_file_bytes
        )?;
        writeln!(f, "elevated:                {}", self.elevated)?;
        writeln!(f, "logical processors:      {}", self.logical_cpus)?;
        writeln!(
            f,
            "interval:                {} s",
            self.interval.as_secs_f64()
        )?;
        writeln!(
            f,
            "window (wall clock):     {:.3} s",
            self.wall.as_secs_f64()
        )?;
        writeln!(
            f,
            "ticks:                   {} ({} rows written, {} with power requests visible)",
            self.ticks, self.rows, self.rows_with_requests_visible
        )?;
        writeln!(
            f,
            "CPU used (GetProcessTimes): {:.1} ms = {:.4}% of the whole machine",
            self.cpu.as_secs_f64() * 1000.0,
            self.cpu_percent
        )?;
        writeln!(
            f,
            "time inside ticks:       {:.1} ms = {:.4}% of the whole machine (upper bound), slowest tick {:.1} ms",
            self.busy.as_secs_f64() * 1000.0,
            self.busy_percent,
            self.slowest_tick.as_secs_f64() * 1000.0
        )?;
        writeln!(
            f,
            "working set:             {:.1} MiB now, {:.1} MiB peak of the process",
            mib(self.working_set),
            mib(self.peak_working_set)
        )?;
        write!(
            f,
            "bytes written:           {} to the ring",
            self.ring_bytes_written
        )?;
        match self.write_transfer_bytes {
            Some(n) => write!(f, ", {n} by the process in all"),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_percent_is_of_the_whole_machine() {
        // One core fully busy on an 8 logical processor machine is 12.5%.
        let p = percent_of_machine(Duration::from_secs(10), Duration::from_secs(10), 8);
        assert!((p - 12.5).abs() < 1e-9);
        let p = percent_of_machine(Duration::from_millis(30), Duration::from_secs(600), 16);
        assert!((p - 0.0003125).abs() < 1e-9);
        assert_eq!(
            percent_of_machine(Duration::from_secs(1), Duration::ZERO, 4),
            0.0
        );
        assert!(
            (percent_of_machine(Duration::from_secs(1), Duration::from_secs(1), 0) - 100.0).abs()
                < 1e-9
        );
    }
}
