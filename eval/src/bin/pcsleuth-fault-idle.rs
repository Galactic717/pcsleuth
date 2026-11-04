//! Fault: nothing. A process that stays alive and does no work, so it can run beside a hog as a
//! decoy: an answer that names it first has blamed a process that was doing nothing.
//! `--secs N` (default 30, at most 600). Needs no admin and changes no setting.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use pcsleuth_eval::fault;

    let run = fault::start(30);
    fault::ready();
    run.hold();
    std::process::ExitCode::SUCCESS
}

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    pcsleuth_eval::fault::unsupported()
}
