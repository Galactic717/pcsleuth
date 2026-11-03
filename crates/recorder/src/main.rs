//! The opt-in recorder (ADR 0006). OS calls live here, so this crate does not forbid `unsafe_code`.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("pcsleuth-recorder is not implemented yet");
    ExitCode::FAILURE
}
