//! The `pcsleuth` command line.
//!
//! Exit codes: 0 when an answer was produced, even an "unknown" one; 1 on internal failure;
//! 2 on bad usage (clap).
#![forbid(unsafe_code)]

mod elevate;
mod render;
mod since;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use pcsleuth_core::{Answer, Question};
use pcsleuth_engine::{Options, resolve};

#[derive(Debug, Parser)]
#[command(
    name = "pcsleuth",
    version,
    about = "Ask your Windows PC why it did that.",
    after_help = "Without --since, wake, nosleep, battery, slow and timeline look back 7 days and \
                  crash looks back 30. Without --limit, 20 dated findings are shown (timeline 50)."
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

    /// Show at most this many dated findings, keeping the most recent. Notes with no date are
    /// always shown.
    #[arg(
        long,
        global = true,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    limit: Option<u32>,

    /// Run again elevated through the Windows permission prompt, to read what needs admin.
    #[arg(long, global = true)]
    elevate: bool,

    /// Where the elevated copy writes its JSON answer. Only `--elevate` uses this, and it only
    /// accepts a file inside a folder the first run made for it.
    #[arg(long = "out-file", global = true, hide = true, value_name = "PATH")]
    out_file: Option<PathBuf>,
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
    /// Everything above that the logs hold, merged and sorted by time.
    Timeline,
    /// Which sources can be read, and what elevation would add.
    Doctor,
}

impl Command {
    fn question(self) -> Question {
        match self {
            Command::Wake => Question::Wake,
            Command::Nosleep => Question::NoSleep,
            Command::Battery => Question::Battery,
            Command::Crash => Question::Crash,
            Command::Slow => Question::Slow,
            Command::Now => Question::Now,
            Command::Timeline => Question::Timeline,
            Command::Doctor => Question::Doctor,
        }
    }
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
    let mut options = Options::default();
    options.since = cli.since;
    options.limit = cli.limit.map(|limit| limit as usize);
    let question = cli.command.question();

    // The elevated copy: answer in JSON into the file the first run made, and print nothing.
    if let Some(path) = &cli.out_file {
        return write_answer_file(&ask(cli.command, &options), path);
    }

    let answer = if cli.elevate && !elevate::already_elevated() {
        let args = elevate::child_args(question.as_str(), cli.since, cli.limit);
        match elevate::fetch(&args) {
            Ok(answer) => answer,
            Err(why) => {
                let _ = writeln!(
                    io::stderr(),
                    "pcsleuth: could not run elevated ({why}); showing the answer without admin"
                );
                ask(cli.command, &options)
            }
        }
    } else {
        ask(cli.command, &options)
    };

    let text = if cli.json {
        render::json(&answer)?
    } else {
        let scope = resolve(question, &options, answer.generated_at);
        render::human(&answer, &TimeZone::system(), Some(&scope))
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

/// Write the answer as JSON to `path`, a new file inside a folder the first run made. Anything
/// else is refused, so an elevated write can only land where the first run chose.
fn write_answer_file(answer: &Answer, path: &Path) -> anyhow::Result<ExitCode> {
    if !pcsleuth_sources::power::is_output_path(path) {
        anyhow::bail!(
            "--out-file must be a file inside a folder named pcsleuth- and 32 hex digits"
        );
    }
    let text = render::json(answer)?;
    let mut file = pcsleuth_sources::power::open_output_file(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.flush())
        .context("could not write the answer")?;
    Ok(ExitCode::SUCCESS)
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
