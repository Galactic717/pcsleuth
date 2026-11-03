//! The `pcsleuth` command line.
//!
//! Exit codes: 0 when an answer was produced, even an "unknown" one; 1 on internal failure;
//! 2 on bad usage (clap).
#![forbid(unsafe_code)]

mod render;
mod since;

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use pcsleuth_core::Answer;
use pcsleuth_engine::Options;

#[derive(Debug, Parser)]
#[command(
    name = "pcsleuth",
    version,
    about = "Ask your Windows PC why it did that."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Print the answer as JSON on stdout, and nothing else.
    #[arg(long, global = true)]
    json: bool,

    /// Only use evidence since then: 90m, 24h, 7d, 2w, a date such as 2026-11-01, or an RFC 3339 time.
    #[arg(long, global = true, value_name = "WHEN", value_parser = since::parse)]
    since: Option<Timestamp>,

    /// Show at most this many findings, keeping the most recent.
    #[arg(
        long,
        global = true,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    limit: Option<u32>,

    /// Re-run elevated through UAC to read the sources that need admin (not implemented yet).
    #[arg(long, global = true)]
    elevate: bool,
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum Command {
    /// Why did the PC wake up?
    Wake,
    /// Why will it not stay asleep?
    Nosleep,
    /// What drained the battery?
    Battery,
    /// What was it doing when it crashed or froze?
    Crash,
    /// Why is it slow?
    Slow,
    /// What is it doing right now?
    Now,
    /// Everything above, merged and sorted by time.
    Timeline,
    /// Which sources can be read, and what elevation would add.
    Doctor,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(error) => {
            // Not eprintln!, which panics if stderr is closed.
            let _ = writeln!(io::stderr(), "pcsleuth: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    if cli.elevate {
        let _ = writeln!(io::stderr(), "pcsleuth: --elevate is not implemented yet");
        return Ok(ExitCode::FAILURE);
    }

    let mut options = Options::default();
    options.since = cli.since;
    options.limit = cli.limit.map(|limit| limit as usize);

    let answer = ask(cli.command, &options);
    let text = if cli.json {
        render::json(&answer)?
    } else {
        render::human(&answer, &TimeZone::system())
    };
    write_stdout(&text)?;
    Ok(ExitCode::SUCCESS)
}

fn ask(command: Command, options: &Options) -> Answer {
    match command {
        Command::Wake => pcsleuth_engine::wake(options),
        Command::Nosleep => pcsleuth_engine::nosleep(options),
        Command::Battery => pcsleuth_engine::battery(options),
        Command::Crash => pcsleuth_engine::crash(options),
        Command::Slow => pcsleuth_engine::slow(options),
        Command::Now => pcsleuth_engine::now(options),
        Command::Timeline => pcsleuth_engine::timeline(options),
        Command::Doctor => pcsleuth_engine::doctor(options),
    }
}

/// Write without `println!`, which panics when the pipe closes early (`pcsleuth wake | head`).
fn write_stdout(text: &str) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result.context("could not write to stdout"),
    }
}
