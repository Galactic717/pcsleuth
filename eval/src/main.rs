//! `pcsleuth-eval run` reproduces the published evaluation. Method and numbers: docs/EVAL.md.
#![deny(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pcsleuth_eval::report;
use pcsleuth_eval::runner::{self, Options};
use pcsleuth_eval::scenario::SCENARIOS;

#[derive(Debug, Parser)]
#[command(name = "pcsleuth-eval", about = "Fault injection and scoring for pcsleuth")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inject each fault, ask pcsleuth, score the answers, print a table and write JSON.
    Run {
        /// The pcsleuth binary to score. Default: build it with cargo.
        #[arg(long, value_name = "PATH")]
        pcsleuth: Option<PathBuf>,
        /// Run only this scenario; repeat for several. Default: all.
        #[arg(long = "scenario", value_name = "NAME")]
        scenarios: Vec<String>,
        /// Also run the scenarios that put this PC to sleep. Asks for a typed confirmation, and
        /// is refused on CI. Never run by default.
        #[arg(long)]
        sleep: bool,
        /// Where to write the results file. Default: eval/results.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
    },
    /// List the scenarios.
    List,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            // Not eprintln!, which panics if stderr is closed.
            let _ = writeln!(std::io::stderr(), "pcsleuth-eval: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Run {
            pcsleuth,
            scenarios,
            sleep,
            out,
        } => runner::run(Options {
            pcsleuth,
            scenarios,
            sleep,
            out,
        }),
        Command::List => {
            for s in SCENARIOS {
                let unelevated = s.needs.observable(false);
                let elevated = s.needs.observable(true);
                let observable = if unelevated == elevated {
                    report::observable_text(&unelevated)
                } else {
                    format!(
                        "{} (unelevated); {} (elevated)",
                        report::observable_text(&unelevated),
                        report::observable_text(&elevated)
                    )
                };
                let sleeps = if s.sleeps() { " [needs --sleep]" } else { "" };
                println!("{} ({}){sleeps}\n    {}\n    observable: {observable}", s.name, s.question, s.summary);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
