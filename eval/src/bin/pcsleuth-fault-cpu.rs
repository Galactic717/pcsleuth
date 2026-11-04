//! Fault: burns CPU. `--secs N` (default 20, at most 600) and `--threads N` (default 4, never
//! more than half the logical cores, at least 1). Needs no admin and touches no file.

use std::hint::black_box;
use std::process::ExitCode;

use pcsleuth_eval::fault;

fn main() -> ExitCode {
    let run = fault::start(20);
    let half = std::thread::available_parallelism().map_or(1, |n| n.get() as u64 / 2);
    let cap = half.max(1);
    let threads = fault::number("--threads", cap.min(4), 1, cap);

    let workers: Vec<_> = (0..threads)
        .map(|_| {
            std::thread::spawn(move || {
                let mut x = 1u64;
                while !run.expired() {
                    for _ in 0..100_000 {
                        x = black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
                    }
                }
                x
            })
        })
        .collect();
    fault::ready();
    for worker in workers {
        let _ = worker.join();
    }
    ExitCode::SUCCESS
}
