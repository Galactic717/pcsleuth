//! Running processes: CPU time, memory and IO counters, and the rates between two samples.
//!
//! [`sample`] lists processes with ToolHelp and reads each one through a
//! `PROCESS_QUERY_LIMITED_INFORMATION` handle, which an unelevated process may hold for most
//! processes of its own session and many others. A process that refuses (protected system
//! processes) or that exits during the sample is counted in [`ProcessSample::denied`] or
//! [`ProcessSample::exited`] and skipped, never fatal. [`top`] is pure and turns two samples into
//! ranked rates, so the recorder and `now` share it.
//!
//! IO counters are the process totals Windows keeps for every kind of IO (disk, network, console),
//! so a high rate does not by itself mean disk use.

use std::time::Duration;

use jiff::Timestamp;

use crate::power::filetime_to_timestamp;
#[cfg(windows)]
use pcsleuth_core::{Access, SourceId, Sourced};

/// One process at the moment of a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    /// The executable file name, such as `chrome.exe`.
    pub name: String,
    /// Creation time as a `FILETIME` (100 ns since 1601). With `pid` it identifies a process, since
    /// Windows reuses pids.
    pub created: u64,
    /// Kernel plus user CPU time so far, in 100 ns ticks.
    pub cpu_time: u64,
    pub working_set_bytes: u64,
    /// Memory the process has committed for itself (`PrivateUsage`).
    pub private_bytes: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
}

/// Every readable process at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSample {
    pub taken_at: Timestamp,
    /// Logical processors, for turning CPU time into a share of the machine.
    pub logical_cpus: u32,
    pub processes: Vec<ProcessEntry>,
    /// Processes that refused to be opened or read.
    pub denied: u32,
    /// Processes that exited while the sample was being taken.
    pub exited: u32,
}

/// One process's activity between two samples.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessRate {
    pub pid: u32,
    pub name: String,
    /// CPU used per second of wall time, in cores: 1.0 is one core fully busy.
    pub cpu_cores: f64,
    /// `cpu_cores` as a share of all logical processors, 0 to 100.
    pub cpu_percent: f64,
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    pub io_read_bytes_per_sec: f64,
    pub io_write_bytes_per_sec: f64,
}

impl ProcessRate {
    fn io_bytes_per_sec(&self) -> f64 {
        self.io_read_bytes_per_sec + self.io_write_bytes_per_sec
    }
}

/// The busiest processes between two samples, three ways.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Top {
    /// Wall time between the samples. Zero when the samples cannot be compared.
    pub interval: Duration,
    /// Highest CPU first. Processes that used no CPU are left out.
    pub by_cpu: Vec<ProcessRate>,
    /// Largest working set first, from the later sample.
    pub by_memory: Vec<ProcessRate>,
    /// Highest read plus write rate first. Processes with no IO are left out.
    pub by_io: Vec<ProcessRate>,
}

/// Rank the processes in `next` by what they did since `prev`, keeping `n` of each ranking.
///
/// A process is matched by pid and creation time. One created after `prev` was taken counts from
/// zero. One that existed before `prev` but was not readable then has no baseline, so it appears
/// in `by_memory` only. If the samples are not in order, `interval` is zero and every list is empty.
pub fn top(prev: &ProcessSample, next: &ProcessSample, n: usize) -> Top {
    let elapsed = next.taken_at.duration_since(prev.taken_at);
    let Ok(interval) = Duration::try_from(elapsed) else {
        return Top::default();
    };
    if interval.is_zero() {
        return Top::default();
    }
    let secs = interval.as_secs_f64();
    let cpus = f64::from(next.logical_cpus.max(1));

    let before: std::collections::HashMap<(u32, u64), &ProcessEntry> = prev
        .processes
        .iter()
        .map(|p| ((p.pid, p.created), p))
        .collect();

    let mut all: Vec<(ProcessRate, bool)> = next
        .processes
        .iter()
        .map(|p| {
            let base = before
                .get(&(p.pid, p.created))
                .map(|b| (b.cpu_time, b.io_read_bytes, b.io_write_bytes));
            let started_since =
                filetime_to_timestamp(p.created as i64).is_some_and(|c| c >= prev.taken_at);
            let base = base.or(started_since.then_some((0, 0, 0)));
            let (cpu, read, write) = match base {
                Some((c, r, w)) => (
                    p.cpu_time.saturating_sub(c),
                    p.io_read_bytes.saturating_sub(r),
                    p.io_write_bytes.saturating_sub(w),
                ),
                None => (0, 0, 0),
            };
            let cores = cpu as f64 / 1e7 / secs;
            (
                ProcessRate {
                    pid: p.pid,
                    name: p.name.clone(),
                    cpu_cores: cores,
                    cpu_percent: cores / cpus * 100.0,
                    working_set_bytes: p.working_set_bytes,
                    private_bytes: p.private_bytes,
                    io_read_bytes_per_sec: read as f64 / secs,
                    io_write_bytes_per_sec: write as f64 / secs,
                },
                base.is_some(),
            )
        })
        .collect();

    let mut by_memory: Vec<ProcessRate> = all.iter().map(|(r, _)| r.clone()).collect();
    by_memory.sort_by(|a, b| {
        b.working_set_bytes
            .cmp(&a.working_set_bytes)
            .then(a.pid.cmp(&b.pid))
    });
    by_memory.truncate(n);

    all.retain(|(_, has_baseline)| *has_baseline);
    let mut by_cpu: Vec<ProcessRate> = all
        .iter()
        .map(|(r, _)| r)
        .filter(|r| r.cpu_cores > 0.0)
        .cloned()
        .collect();
    by_cpu.sort_by(|a, b| b.cpu_cores.total_cmp(&a.cpu_cores).then(a.pid.cmp(&b.pid)));
    by_cpu.truncate(n);

    let mut by_io: Vec<ProcessRate> = all
        .into_iter()
        .map(|(r, _)| r)
        .filter(|r| r.io_bytes_per_sec() > 0.0)
        .collect();
    by_io.sort_by(|a, b| {
        b.io_bytes_per_sec()
            .total_cmp(&a.io_bytes_per_sec())
            .then(a.pid.cmp(&b.pid))
    });
    by_io.truncate(n);

    Top {
        interval,
        by_cpu,
        by_memory,
        by_io,
    }
}

/// Take one sample of every process this user can read.
///
/// Costs a few milliseconds on a normal desktop. Fails only when the process list itself cannot be
/// taken; individual processes that cannot be read are counted in the result.
#[cfg(windows)]
pub fn sample() -> Sourced<ProcessSample> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows::Win32::System::Threading::{
        GetProcessIoCounters, GetProcessTimes, IO_COUNTERS, OpenProcess,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use crate::power::access_from_hresult;

    /// Closes a handle when dropped.
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by this module and is closed exactly once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    let source = SourceId::Processes;
    let taken_at = Timestamp::now();

    // SAFETY: plain snapshot of the process list; the handle is closed by the guard.
    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => Handle(handle),
        Err(e) => return Sourced::unreadable(source, access_from_hresult(e.code().0)),
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut sample = ProcessSample {
        taken_at,
        logical_cpus: std::thread::available_parallelism().map_or(1, |n| n.get() as u32),
        processes: Vec::with_capacity(512),
        denied: 0,
        exited: 0,
    };
    // SAFETY: `entry` has its size set and outlives the call.
    let mut more = unsafe { Process32FirstW(snapshot.0, &mut entry) }.is_ok();
    while more {
        let pid = entry.th32ProcessID;
        if pid != 0 {
            let len = entry
                .szExeFile
                .iter()
                .position(|c| *c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            // ERROR_INVALID_PARAMETER from OpenProcess means the pid no longer exists.
            const ERROR_INVALID_PARAMETER: u32 = 0x8007_0057;
            // SAFETY: opens a limited query handle on a pid from the snapshot.
            match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
                Err(e) if e.code().0 as u32 == ERROR_INVALID_PARAMETER => sample.exited += 1,
                Err(_) => sample.denied += 1,
                Ok(handle) => {
                    let process = Handle(handle);
                    let mut times = [FILETIME::default(); 4];
                    let mut memory = PROCESS_MEMORY_COUNTERS_EX {
                        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
                        ..Default::default()
                    };
                    let mut io = IO_COUNTERS::default();
                    // SAFETY: `process` is open and every out-pointer is a valid local of the right type.
                    let read = unsafe {
                        let [created, exit, kernel, user] = &mut times;
                        GetProcessTimes(process.0, created, exit, kernel, user)
                            .and_then(|()| {
                                GetProcessMemoryInfo(
                                    process.0,
                                    std::ptr::from_mut(&mut memory)
                                        .cast::<PROCESS_MEMORY_COUNTERS>(),
                                    memory.cb,
                                )
                            })
                            .and_then(|()| GetProcessIoCounters(process.0, &mut io))
                    };
                    let [created, exit, kernel, user] = times;
                    match read {
                        // A non-zero exit time means it ended after the snapshot was listed.
                        Ok(()) if ticks(exit) != 0 => sample.exited += 1,
                        Ok(()) => sample.processes.push(ProcessEntry {
                            pid,
                            parent_pid: entry.th32ParentProcessID,
                            name,
                            created: ticks(created),
                            cpu_time: ticks(kernel) + ticks(user),
                            working_set_bytes: memory.WorkingSetSize as u64,
                            private_bytes: memory.PrivateUsage as u64,
                            io_read_bytes: io.ReadTransferCount,
                            io_write_bytes: io.WriteTransferCount,
                        }),
                        Err(_) => sample.denied += 1,
                    }
                }
            }
        }
        // SAFETY: as for Process32FirstW.
        more = unsafe { Process32NextW(snapshot.0, &mut entry) }.is_ok();
    }
    Sourced {
        source,
        access: Access::Ok,
        data: vec![sample],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: i64 = 1_793_692_800; // 2026-11-03T08:00:00Z
    const UNIX_TO_FILETIME: u64 = 116_444_736_000_000_000;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_second(START + secs).unwrap()
    }

    fn filetime(secs: i64) -> u64 {
        ((START + secs) as u64) * 10_000_000 + UNIX_TO_FILETIME
    }

    /// An entry created at `created` seconds (relative to START), with its counters.
    fn proc(
        pid: u32,
        name: &str,
        created: i64,
        cpu_secs: f64,
        ws_mb: u64,
        read: u64,
        write: u64,
    ) -> ProcessEntry {
        ProcessEntry {
            pid,
            parent_pid: 1,
            name: name.into(),
            created: filetime(created),
            cpu_time: (cpu_secs * 1e7) as u64,
            working_set_bytes: ws_mb << 20,
            private_bytes: ws_mb << 19,
            io_read_bytes: read,
            io_write_bytes: write,
        }
    }

    fn sample_of(secs: i64, cpus: u32, processes: Vec<ProcessEntry>) -> ProcessSample {
        ProcessSample {
            taken_at: at(secs),
            logical_cpus: cpus,
            processes,
            denied: 0,
            exited: 0,
        }
    }

    #[test]
    fn rates_over_two_seconds() {
        let prev = sample_of(
            100,
            8,
            vec![
                proc(10, "busy.exe", -500, 10.0, 200, 1_000, 0),
                proc(11, "idle.exe", -500, 5.0, 900, 0, 0),
                proc(12, "writer.exe", -500, 1.0, 50, 0, 100),
            ],
        );
        let next = sample_of(
            102,
            8,
            vec![
                proc(10, "busy.exe", -500, 13.0, 210, 5_000, 0),
                proc(11, "idle.exe", -500, 5.0, 900, 0, 0),
                proc(12, "writer.exe", -500, 1.5, 55, 0, 20_100),
            ],
        );
        let top = top(&prev, &next, 10);
        assert_eq!(top.interval, Duration::from_secs(2));

        // busy.exe: 3 s of CPU in 2 s is 1.5 cores, which is 18.75% of 8 logical processors.
        assert_eq!(top.by_cpu.len(), 2);
        assert_eq!(top.by_cpu[0].name, "busy.exe");
        assert!((top.by_cpu[0].cpu_cores - 1.5).abs() < 1e-9);
        assert!((top.by_cpu[0].cpu_percent - 18.75).abs() < 1e-9);
        assert_eq!(top.by_cpu[1].name, "writer.exe");
        assert!((top.by_cpu[1].cpu_cores - 0.25).abs() < 1e-9);

        assert_eq!(
            top.by_memory.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![11, 10, 12]
        );
        assert_eq!(top.by_memory[0].working_set_bytes, 900 << 20);

        assert_eq!(top.by_io.len(), 2);
        assert_eq!(top.by_io[0].name, "writer.exe");
        assert!((top.by_io[0].io_write_bytes_per_sec - 10_000.0).abs() < 1e-9);
        assert_eq!(top.by_io[1].name, "busy.exe");
        assert!((top.by_io[1].io_read_bytes_per_sec - 2_000.0).abs() < 1e-9);
    }

    #[test]
    fn n_limits_every_ranking() {
        let prev = sample_of(
            0,
            4,
            vec![
                proc(1, "a", -9, 0.0, 1, 0, 0),
                proc(2, "b", -9, 0.0, 2, 0, 0),
                proc(3, "c", -9, 0.0, 3, 0, 0),
            ],
        );
        let next = sample_of(
            1,
            4,
            vec![
                proc(1, "a", -9, 1.0, 1, 10, 0),
                proc(2, "b", -9, 2.0, 2, 20, 0),
                proc(3, "c", -9, 3.0, 3, 30, 0),
            ],
        );
        let top = top(&prev, &next, 2);
        assert_eq!(
            top.by_cpu.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(
            top.by_memory.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(
            top.by_io.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert!(super::top(&prev, &next, 0).by_cpu.is_empty());
    }

    #[test]
    fn a_process_started_between_samples_counts_from_zero() {
        let prev = sample_of(0, 2, vec![]);
        // Created 1 s into a 2 s interval and has used 1 s of CPU since.
        let next = sample_of(2, 2, vec![proc(7, "new.exe", 1, 1.0, 10, 4_000, 0)]);
        let top = top(&prev, &next, 5);
        assert!((top.by_cpu[0].cpu_cores - 0.5).abs() < 1e-9);
        assert!((top.by_io[0].io_read_bytes_per_sec - 2_000.0).abs() < 1e-9);
    }

    #[test]
    fn an_older_process_missing_from_the_first_sample_has_no_rate() {
        // It existed before `prev` but could not be read then, so its totals are not a rate.
        let prev = sample_of(100, 2, vec![]);
        let next = sample_of(
            101,
            2,
            vec![proc(7, "old.exe", -9_000, 4_000.0, 300, 99, 99)],
        );
        let top = top(&prev, &next, 5);
        assert!(top.by_cpu.is_empty());
        assert!(top.by_io.is_empty());
        assert_eq!(top.by_memory.len(), 1);
        assert_eq!(top.by_memory[0].name, "old.exe");
    }

    #[test]
    fn a_reused_pid_is_a_different_process() {
        let prev = sample_of(
            100,
            1,
            vec![proc(5, "old.exe", -9_000, 50.0, 10, 1_000_000, 0)],
        );
        // Same pid, created after `prev`: the old totals must not be subtracted from it.
        let next = sample_of(101, 1, vec![proc(5, "other.exe", 100, 0.2, 10, 100, 0)]);
        let top = top(&prev, &next, 5);
        assert_eq!(top.by_cpu.len(), 1);
        assert!((top.by_cpu[0].cpu_cores - 0.2).abs() < 1e-9);
        assert!((top.by_io[0].io_read_bytes_per_sec - 100.0).abs() < 1e-9);
    }

    #[test]
    fn counters_that_go_backwards_do_not_underflow() {
        let prev = sample_of(0, 1, vec![proc(1, "a", -9, 5.0, 1, 500, 500)]);
        let next = sample_of(1, 1, vec![proc(1, "a", -9, 4.0, 1, 100, 100)]);
        let top = top(&prev, &next, 5);
        assert!(top.by_cpu.is_empty() && top.by_io.is_empty());
    }

    #[test]
    fn samples_out_of_order_or_at_the_same_instant_give_nothing() {
        let a = sample_of(10, 1, vec![proc(1, "a", -9, 1.0, 1, 0, 0)]);
        let b = sample_of(10, 1, vec![proc(1, "a", -9, 2.0, 1, 0, 0)]);
        assert_eq!(top(&a, &b, 5), Top::default());
        let later = sample_of(20, 1, vec![]);
        assert_eq!(top(&later, &a, 5), Top::default());
    }

    #[test]
    fn zero_logical_cpus_does_not_divide_by_zero() {
        let prev = sample_of(0, 0, vec![proc(1, "a", -9, 0.0, 1, 0, 0)]);
        let next = sample_of(1, 0, vec![proc(1, "a", -9, 1.0, 1, 0, 0)]);
        let top = top(&prev, &next, 5);
        assert!((top.by_cpu[0].cpu_percent - 100.0).abs() < 1e-9);
    }

    #[cfg(windows)]
    #[test]
    fn live_sample_reads_this_process_and_counts_what_it_cannot_open() {
        let read = sample();
        assert_eq!(read.access, Access::Ok);
        let s = &read.data[0];
        assert!(s.processes.len() > 10, "{}", s.processes.len());
        assert!(s.logical_cpus >= 1);
        let me = s
            .processes
            .iter()
            .find(|p| p.pid == std::process::id())
            .expect("this test process is in its own sample");
        assert!(me.working_set_bytes > 0 && me.cpu_time > 0 && me.created > 0);
        assert!(me.name.to_ascii_lowercase().ends_with(".exe"));
        // The System process and other protected ones cannot be opened unelevated.
        assert!(
            s.denied > 0,
            "expected some protected processes to be counted"
        );
        eprintln!(
            "processes: {} read, {} denied, {} exited, {} logical cpus",
            s.processes.len(),
            s.denied,
            s.exited,
            s.logical_cpus
        );
    }

    #[cfg(windows)]
    #[test]
    fn live_top_between_two_real_samples() {
        let first = sample().data.remove(0);
        // Burn some CPU here so there is something to see.
        let end = std::time::Instant::now() + Duration::from_millis(300);
        let mut x = 0u64;
        while std::time::Instant::now() < end {
            x = x.wrapping_mul(31).wrapping_add(7);
        }
        std::hint::black_box(x);
        let second = sample().data.remove(0);
        let top = top(&first, &second, 5);
        assert!(top.interval >= Duration::from_millis(300));
        assert!(top.by_memory.len() == 5);
        assert!(top.by_cpu.iter().all(|p| p.cpu_cores > 0.0));
        assert!(top.by_cpu.iter().any(|p| p.pid == std::process::id()));
        eprintln!(
            "top cpu: {:?}",
            top.by_cpu
                .iter()
                .map(|p| (&p.name, (p.cpu_percent * 10.0).round() / 10.0))
                .collect::<Vec<_>>()
        );
    }

    /// Prints how long a sample takes. Use `cargo test --release -p pcsleuth-sources
    /// live_sample_cost -- --nocapture`; a debug build is several times slower.
    #[cfg(windows)]
    #[test]
    fn live_sample_cost() {
        let mut times: Vec<Duration> = (0..30)
            .map(|_| {
                let start = std::time::Instant::now();
                let read = sample();
                let took = start.elapsed();
                assert_eq!(read.access, Access::Ok);
                took
            })
            .collect();
        times.sort();
        let median = times[times.len() / 2];
        eprintln!(
            "sample cost: min {:?}, median {:?}, max {:?}",
            times[0],
            median,
            times[times.len() - 1]
        );
        // Generous bound for slow CI and debug builds; the measured release figure goes in the PR.
        assert!(median < Duration::from_millis(250), "{median:?}");
    }
}
