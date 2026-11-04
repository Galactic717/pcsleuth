//! The sampling loop: wait, tick, write. It sleeps in a kernel wait between ticks, so an idle
//! recorder uses no CPU, and it neither changes the system timer resolution nor asks Windows to
//! stay awake: a machine that sleeps simply has no ticks while it sleeps.

use std::io;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use crate::ring::{RingWriter, Sample, Storage};

/// What one tick produced.
pub enum Tick {
    /// The first tick only takes the baseline the next one is compared with.
    Baseline,
    Row(Sample),
    /// The process list could not be read. The next tick compares against the last good one.
    Unreadable,
}

/// What the loop tells its caller about, in order.
pub enum Event<'a> {
    Baseline,
    Unreadable,
    Row(&'a Sample),
    WriteFailed(&'a io::Error),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopStats {
    pub ticks: u32,
    pub rows_written: u32,
    pub unreadable: u32,
    pub write_failures: u32,
    /// Wall time spent inside ticks, reading and writing.
    pub busy: Duration,
    pub slowest_tick: Duration,
}

/// Run until `stop` fires (or its sender is gone) or `until` passes, ticking every `interval`.
///
/// Ticks fall on a fixed grid from the start, so a slow tick does not push the later ones back. A
/// loop that has fallen behind, after a long tick or a resume from sleep, skips the ticks it
/// missed instead of running them in a burst. A tick that is due at exactly `until` still runs.
pub fn run<S: Storage>(
    ring: &mut RingWriter<S>,
    interval: Duration,
    stop: &Receiver<()>,
    until: Option<Instant>,
    mut tick: impl FnMut() -> Tick,
    mut observe: impl FnMut(Event<'_>),
) -> LoopStats {
    let mut stats = LoopStats::default();
    let mut deadline = Instant::now() + interval;
    loop {
        let wake = until.map_or(deadline, |u| deadline.min(u));
        match stop.recv_timeout(wake.saturating_duration_since(Instant::now())) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
        }
        if Instant::now() >= deadline {
            let started = Instant::now();
            stats.ticks += 1;
            match tick() {
                Tick::Baseline => observe(Event::Baseline),
                Tick::Unreadable => {
                    stats.unreadable += 1;
                    observe(Event::Unreadable);
                }
                Tick::Row(sample) => match ring.append(&sample) {
                    Ok(()) => {
                        stats.rows_written += 1;
                        observe(Event::Row(&sample));
                    }
                    Err(e) => {
                        stats.write_failures += 1;
                        observe(Event::WriteFailed(&e));
                    }
                },
            }
            let took = started.elapsed();
            stats.busy += took;
            stats.slowest_tick = stats.slowest_tick.max(took);
            deadline += interval;
            let now = Instant::now();
            if deadline <= now {
                deadline = now + interval;
            }
        }
        if until.is_some_and(|u| Instant::now() >= u) {
            break;
        }
    }
    stats
}

/// The live source of ticks: process samples from ToolHelp and power requests from Windows.
#[cfg(windows)]
pub struct Live {
    prev: Option<pcsleuth_sources::processes::ProcessSample>,
}

#[cfg(windows)]
impl Live {
    /// Take the baseline sample now, so the first tick after one interval already has a row.
    pub fn start() -> Live {
        Live {
            prev: pcsleuth_sources::processes::sample().data.pop(),
        }
    }

    /// Read processes and power requests once. Without admin the power read says so
    /// ([`Sample::requests_visible`] is false) and the row is still recorded.
    pub fn tick(&mut self) -> Tick {
        use pcsleuth_sources::{power, processes};

        let Some(next) = processes::sample().data.pop() else {
            return Tick::Unreadable;
        };
        let requests = power::power_requests();
        let tick = match self.prev.take() {
            None => Tick::Baseline,
            Some(prev) => {
                let top = processes::top(&prev, &next, crate::ring::MAX_PER_LIST);
                if top.interval.is_zero() {
                    // The clock went backwards or stood still: start over from this sample.
                    Tick::Baseline
                } else {
                    Tick::Row(crate::sample::build_sample(next.taken_at, &top, &requests))
                }
            }
        };
        self.prev = Some(next);
        tick
    }
}

/// The one sender that Ctrl+C and the service control handler use to end the loop.
static STOP: Mutex<Option<Sender<()>>> = Mutex::new(None);

/// A receiver that [`request_stop`] will signal. Call once, before the loop starts.
pub fn stop_channel() -> Receiver<()> {
    let (tx, rx) = mpsc::channel();
    *STOP.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);
    rx
}

/// Ask the loop made with [`stop_channel`] to finish. Safe to call from any thread, any number of
/// times, also before there is a loop.
pub fn request_stop() {
    if let Some(tx) = STOP.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
        let _ = tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::thread;

    use jiff::Timestamp;
    use pcsleuth_core::RecorderRow;

    use super::*;
    use crate::ring::{BLOCK, scan};

    fn sample(n: i64) -> Sample {
        Sample {
            row: RecorderRow {
                at: Timestamp::from_second(1_793_692_800 + n).unwrap(),
                interval_secs: 1,
                top_cpu: vec![],
                top_io: vec![],
                power_requests: vec![],
            },
            requests_visible: true,
            truncated: false,
        }
    }

    fn ring() -> RingWriter<Cursor<Vec<u8>>> {
        RingWriter::start(
            Cursor::new(Vec::new()),
            16 * BLOCK as u64,
            1,
            Timestamp::from_second(1_793_692_800).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn ticks_on_the_grid_until_the_deadline_and_writes_each_row() {
        let mut ring = ring();
        let (_keep, rx) = mpsc::channel::<()>();
        let mut n = 0;
        let mut seen = 0;
        let started = Instant::now();
        let stats = run(
            &mut ring,
            Duration::from_millis(30),
            &rx,
            Some(started + Duration::from_millis(200)),
            || {
                n += 1;
                if n == 1 {
                    Tick::Baseline
                } else {
                    Tick::Row(sample(n))
                }
            },
            |e| {
                if matches!(e, Event::Row(_)) {
                    seen += 1;
                }
            },
        );
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!((5..=7).contains(&stats.ticks), "{stats:?}");
        assert_eq!(stats.rows_written, stats.ticks - 1);
        assert_eq!(seen, stats.rows_written);
        assert_eq!(stats.write_failures, 0);
        let got = scan(&mut Cursor::new(ring_bytes(ring))).unwrap();
        assert_eq!(got.samples.len() as u32, stats.rows_written);
    }

    fn ring_bytes(w: RingWriter<Cursor<Vec<u8>>>) -> Vec<u8> {
        // The writer owns the cursor; tests read it back through a fresh scan of its bytes.
        w.into_storage().into_inner()
    }

    #[test]
    fn a_stop_ends_a_long_wait_at_once() {
        let mut ring = ring();
        let (tx, rx) = mpsc::channel();
        let stopper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(60));
            tx.send(()).unwrap();
        });
        let started = Instant::now();
        let stats = run(
            &mut ring,
            Duration::from_secs(3_600),
            &rx,
            None,
            || Tick::Baseline,
            |_| {},
        );
        stopper.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(stats.ticks, 0);
    }

    #[test]
    fn a_slow_tick_makes_the_loop_skip_ticks_not_run_them_in_a_burst() {
        let mut ring = ring();
        let (_keep, rx) = mpsc::channel::<()>();
        let stats = run(
            &mut ring,
            Duration::from_millis(20),
            &rx,
            Some(Instant::now() + Duration::from_millis(400)),
            || {
                thread::sleep(Duration::from_millis(70));
                Tick::Baseline
            },
            |_| {},
        );
        // Each tick takes 70 ms and the next waits a full interval, so about 4 or 5 fit; a burst
        // of catch-up ticks would give 20.
        assert!(stats.ticks <= 7, "{stats:?}");
        assert!(stats.slowest_tick >= Duration::from_millis(70));
    }

    #[test]
    fn unreadable_ticks_and_failed_writes_are_counted_not_fatal() {
        let mut ring = ring();
        let (_keep, rx) = mpsc::channel::<()>();
        let mut n = 0;
        let mut failures = 0;
        let stats = run(
            &mut ring,
            Duration::from_millis(10),
            &rx,
            Some(Instant::now() + Duration::from_millis(80)),
            || {
                n += 1;
                if n % 2 == 0 {
                    Tick::Unreadable
                } else {
                    Tick::Row(sample(n))
                }
            },
            |e| {
                if matches!(e, Event::WriteFailed(_)) {
                    failures += 1;
                }
            },
        );
        assert!(stats.unreadable >= 2, "{stats:?}");
        assert_eq!(failures, stats.write_failures);
    }

    #[test]
    fn request_stop_without_a_loop_is_harmless_and_with_one_ends_it() {
        request_stop();
        let rx = stop_channel();
        let mut ring = ring();
        request_stop();
        let stats = run(
            &mut ring,
            Duration::from_secs(3_600),
            &rx,
            None,
            || Tick::Baseline,
            |_| {},
        );
        assert_eq!(stats.ticks, 0);
    }
}
