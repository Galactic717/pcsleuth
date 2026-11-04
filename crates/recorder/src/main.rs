//! `pcsleuth-recorder`: the opt-in recorder (ADR 0006). See `docs/RECORDER.md`.
//!
//! ```text
//! pcsleuth-recorder --foreground [--interval SECS] [--ring PATH]   record in this terminal, no admin
//! pcsleuth-recorder --measure SECS [--interval SECS]               run real ticks, report own overhead
//! pcsleuth-recorder status [--ring PATH]                           what the ring holds
//! pcsleuth-recorder install [--auto-start] [--interval SECS]       register the service (elevated)
//! pcsleuth-recorder uninstall                                      remove it and its ring (elevated)
//! pcsleuth-recorder run-service                                    the entry point the service manager starts
//! ```

use std::process::ExitCode;

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("pcsleuth-recorder runs on Windows only");
    ExitCode::FAILURE
}

#[cfg(windows)]
fn main() -> ExitCode {
    app::run()
}

#[cfg(windows)]
mod app {
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::time::Duration;

    use clap::{CommandFactory, Parser, Subcommand};
    use jiff::Timestamp;
    use pcsleuth_core::Access;
    use pcsleuth_recorder::ring::{DEFAULT_BYTES, RingWriter};
    use pcsleuth_recorder::runner::{self, Event, Live};
    use pcsleuth_recorder::service::{self, StartType};
    use pcsleuth_recorder::{
        APP_DIR, DEFAULT_INTERVAL_SECS, default_ring_path, measure, service_ring_path, status,
        user_ring_path, winapi,
    };
    use pcsleuth_sources::power::is_elevated;

    /// Exit code when a command needs an elevated prompt and this one is not.
    const NEEDS_ELEVATION: u8 = 5;
    /// Exit code when `install` runs from a place other than Program Files.
    const BAD_LOCATION: u8 = 6;

    #[derive(Parser)]
    #[command(
        name = "pcsleuth-recorder",
        version,
        about = "Optional pcsleuth recorder: keeps past power requests and CPU and disk hogs in a fixed-size ring file"
    )]
    struct Cli {
        /// Record in this terminal until Ctrl+C. Needs no admin, but power request owners are then
        /// not visible. The ring goes under %LOCALAPPDATA%\pcsleuth.
        #[arg(long, conflicts_with = "measure")]
        foreground: bool,

        /// Run real ticks for SECS seconds and report the recorder's own CPU, memory and bytes written.
        #[arg(long, value_name = "SECS", value_parser = clap::value_parser!(u64).range(1..))]
        measure: Option<u64>,

        /// Seconds between samples.
        #[arg(long, global = true, default_value_t = DEFAULT_INTERVAL_SECS,
              value_parser = clap::value_parser!(u32).range(1..=86_400))]
        interval: u32,

        /// Ring file to use instead of the default for the command.
        #[arg(long, global = true, value_name = "PATH")]
        ring: Option<PathBuf>,

        #[command(subcommand)]
        command: Option<Command>,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Entry point the Service Control Manager starts. Not for use from a terminal.
        RunService,
        /// Register the Windows service. Needs an elevated prompt. Does not start it.
        Install {
            /// Start the service at boot instead of only when started by hand.
            #[arg(long)]
            auto_start: bool,
        },
        /// Stop and remove the service and delete its ring. Needs an elevated prompt.
        Uninstall,
        /// Show what the ring file holds.
        Status,
        /// Throw away a damaged ring's history and start a new empty one. Only for a file that is a
        /// ring of this program; stop the recorder first. The service's ring needs an elevated prompt.
        Reset,
    }

    /// What to do about a ring the recorder refused to open, when there is something to do.
    fn ring_hint(e: &pcsleuth_recorder::RingError, path: &std::path::Path) -> String {
        use pcsleuth_recorder::RingError;
        match e {
            RingError::HeaderCorrupt | RingError::WrongLength { .. } => format!(
                "\nIts history is kept as it is. To throw it away and start a new ring, run:\n    \
                 pcsleuth-recorder reset --ring \"{}\"",
                path.display()
            ),
            RingError::Io(io) if io.raw_os_error() == Some(32) => {
                "\nAnother program has it open for writing, probably another recorder.".into()
            }
            _ => String::new(),
        }
    }

    pub fn run() -> ExitCode {
        let cli = Cli::parse();
        let interval = Duration::from_secs(u64::from(cli.interval));
        match (cli.command, cli.foreground, cli.measure) {
            (Some(Command::RunService), false, None) => {
                let ring = cli.ring.unwrap_or_else(service_ring_path);
                finish(service::run(interval, ring).map_err(|e| e.to_string()))
            }
            (Some(Command::Install { auto_start }), false, None) => {
                install(auto_start, cli.interval)
            }
            (Some(Command::Uninstall), false, None) => uninstall(),
            (Some(Command::Status), false, None) => {
                show_status(&cli.ring.unwrap_or_else(default_ring_path))
            }
            (Some(Command::Reset), false, None) => {
                reset(&cli.ring.unwrap_or_else(default_ring_path), cli.interval)
            }
            (None, true, None) => foreground(cli.ring.unwrap_or_else(user_ring_path), interval),
            (None, false, Some(secs)) => {
                let ring = cli
                    .ring
                    .unwrap_or_else(|| user_ring_path().with_file_name("measure.ring"));
                measure_run(ring, Duration::from_secs(secs), interval)
            }
            _ => {
                let mut command = Cli::command();
                let error = command.error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "choose one of --foreground, --measure SECS, or a command (status, install, uninstall, run-service)",
                );
                error.exit()
            }
        }
    }

    fn finish(result: Result<(), String>) -> ExitCode {
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("pcsleuth-recorder: {message}");
                ExitCode::FAILURE
            }
        }
    }

    /// Refuse, naming what is needed, unless this prompt is elevated. Nothing has been changed yet.
    fn require_elevation(what: &str) -> Result<(), ExitCode> {
        if is_elevated() {
            return Ok(());
        }
        eprintln!(
            "pcsleuth-recorder {what} needs administrator rights, and this prompt is not elevated.\n\
             Open Terminal (or PowerShell) with \"Run as administrator\" and run it again.\n\
             Nothing was changed."
        );
        Err(ExitCode::from(NEEDS_ELEVATION))
    }

    fn install(auto_start: bool, interval_secs: u32) -> ExitCode {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => return finish(Err(format!("cannot find this executable: {e}"))),
        };
        // Both problems are reported at once, so the user does not fix one and then meet the other.
        let location = service::check_install_location(&exe);
        if let (Err(e), false) = (&location, is_elevated()) {
            eprintln!("pcsleuth-recorder: {e}\n");
        }
        if let Err(code) = require_elevation("install") {
            return code;
        }
        if let Err(e) = location {
            eprintln!("pcsleuth-recorder: {e}\nNothing was changed.");
            return ExitCode::from(BAD_LOCATION);
        }
        let start = if auto_start {
            StartType::Auto
        } else {
            StartType::Manual
        };
        match service::install(&exe, start, interval_secs) {
            Ok(done) => {
                println!(
                    "Installed the service {} ({}).",
                    service::SERVICE_NAME,
                    if auto_start {
                        "starts at boot"
                    } else {
                        "manual start"
                    }
                );
                println!(
                    "Data folder (SYSTEM, Administrators and your account only): {}",
                    done.folder.display()
                );
                println!(
                    "Sampling every {interval_secs} s into {}.",
                    done.ring.display()
                );
                println!(
                    "It is not running yet. Start it with: sc start {}",
                    service::SERVICE_NAME
                );
                println!("Remove it and its data with: pcsleuth-recorder uninstall");
                ExitCode::SUCCESS
            }
            Err(e) => finish(Err(e.to_string())),
        }
    }

    fn uninstall() -> ExitCode {
        if let Err(code) = require_elevation("uninstall") {
            return code;
        }
        match service::uninstall() {
            Ok(done) => {
                println!(
                    "Service {}: {}.",
                    service::SERVICE_NAME,
                    if done.service_removed {
                        "stopped and removed"
                    } else {
                        "was not installed"
                    }
                );
                println!(
                    "Ring file: {}.",
                    if done.ring_removed {
                        "deleted"
                    } else {
                        "was not there"
                    }
                );
                println!(
                    "Data folder: {}.",
                    if done.folder_removed {
                        "removed"
                    } else {
                        "left in place"
                    }
                );
                println!(
                    "A ring made by --foreground lives under %LOCALAPPDATA%\\{APP_DIR}; delete it by hand if you want it gone."
                );
                ExitCode::SUCCESS
            }
            Err(e) => finish(Err(e.to_string())),
        }
    }

    fn reset(path: &std::path::Path, interval_secs: u32) -> ExitCode {
        match RingWriter::open_reset(path, DEFAULT_BYTES, interval_secs) {
            Ok(ring) => {
                println!(
                    "Reset {}: a new empty ring of {} slots. The old history is gone.",
                    path.display(),
                    ring.header().slot_count
                );
                ExitCode::SUCCESS
            }
            Err(e) => finish(Err(format!("cannot reset {}: {e}", path.display()))),
        }
    }

    fn show_status(path: &std::path::Path) -> ExitCode {
        let read = status(path);
        let Some(st) = read.data.first() else {
            match read.access {
                Access::Missing => println!(
                    "No ring file at {}.\nThe recorder has not run here. Record with: pcsleuth-recorder --foreground",
                    path.display()
                ),
                other => println!("Cannot read {}: {other}", path.display()),
            }
            return ExitCode::FAILURE;
        };
        let mib = st.size_bytes as f64 / (1024.0 * 1024.0);
        println!("ring:        {}", st.path.display());
        println!(
            "size:        {} bytes ({mib:.1} MiB), {} slots",
            st.size_bytes, st.slot_count
        );
        println!(
            "interval:    {} s, so a full ring holds {:.1} days",
            st.interval_secs,
            st.capacity().as_secs_f64() / 86_400.0
        );
        if let Some(created) = st.created {
            println!("created:     {created}");
        }
        println!(
            "rows:        {} readable, {} skipped as torn or damaged",
            st.rows, st.skipped
        );
        if let (Some(oldest), Some(newest)) = (st.oldest, st.newest) {
            println!("oldest row:  {oldest}");
            println!("newest row:  {newest}");
        }
        println!(
            "power requests: visible in {} of {} rows{}",
            st.rows - st.rows_without_request_visibility.min(st.rows),
            st.rows,
            if st.rows_without_request_visibility > 0 {
                format!(
                    "; {} recorded without admin, where an empty list means not visible",
                    st.rows_without_request_visibility
                )
            } else {
                String::new()
            }
        );
        ExitCode::SUCCESS
    }

    /// Make sure the folder for a ring made by this process exists. It is per user, so the default
    /// permissions are private enough; the service folder is made by `install` with its own.
    fn ensure_parent(ring_path: &std::path::Path) -> Result<(), ExitCode> {
        match ring_path.parent().map(std::fs::create_dir_all) {
            Some(Err(e)) => Err(finish(Err(format!(
                "cannot create the folder for {}: {e}",
                ring_path.display()
            )))),
            _ => Ok(()),
        }
    }

    fn foreground(ring_path: PathBuf, interval: Duration) -> ExitCode {
        if let Err(code) = ensure_parent(&ring_path) {
            return code;
        }
        let secs = u32::try_from(interval.as_secs()).unwrap_or(u32::MAX);
        let mut ring = match RingWriter::open(&ring_path, DEFAULT_BYTES, secs) {
            Ok(ring) => ring,
            Err(e) => {
                return finish(Err(format!(
                    "cannot use {}: {e}{}",
                    ring_path.display(),
                    ring_hint(&e, &ring_path)
                )));
            }
        };
        let stop = runner::stop_channel();
        if let Err(e) = winapi::stop_on_ctrl_c() {
            eprintln!(
                "pcsleuth-recorder: Ctrl+C will not stop it cleanly ({e}); close the window instead"
            );
        }
        if let Err(e) = winapi::lower_thread_priority() {
            eprintln!(
                "pcsleuth-recorder: could not lower priority ({e}); continuing at normal priority"
            );
        }
        let days = f64::from(ring.header().slot_count) * interval.as_secs_f64() / 86_400.0;
        println!(
            "Recording every {} s into {} ({} slots, {days:.1} days when full). Ctrl+C stops it.",
            interval.as_secs(),
            ring_path.display(),
            ring.header().slot_count
        );
        if !is_elevated() {
            println!("Not elevated: power request owners will not be visible, and rows say so.");
        }
        let mut live = Live::start();
        let stats = runner::run(
            &mut ring,
            interval,
            &stop,
            None,
            || live.tick(),
            |event| match event {
                Event::Row(sample) => println!(
                    "{}  cpu: {}  io: {}  power requests: {}",
                    Timestamp::from_millisecond(sample.row.at.as_millisecond())
                        .unwrap_or(sample.row.at),
                    sample.row.top_cpu.first().map_or("-".into(), |p| format!(
                        "{} {:.1}%",
                        p.name,
                        f64::from(p.cpu_permille) / 10.0
                    )),
                    sample.row.top_io.first().map_or("-".into(), |p| format!(
                        "{} {} B/s",
                        p.name, p.io_bytes_per_sec
                    )),
                    if sample.requests_visible {
                        sample.row.power_requests.len().to_string()
                    } else {
                        "not visible".into()
                    },
                ),
                Event::Baseline => {}
                Event::Unreadable => {
                    eprintln!("could not read the process list this tick; skipped")
                }
                Event::WriteFailed(e) => eprintln!("could not write the ring: {e}"),
            },
        );
        println!(
            "Stopped. {} rows written, {} ticks skipped for unreadable process lists, {} write failures.",
            stats.rows_written, stats.unreadable, stats.write_failures
        );
        match stats.failed {
            None => ExitCode::SUCCESS,
            Some(code) => {
                eprintln!(
                    "pcsleuth-recorder: gave up after {} failed ticks in a row, last error code {code}; \
                     nothing was being recorded.",
                    runner::MAX_CONSECUTIVE_FAILURES
                );
                ExitCode::FAILURE
            }
        }
    }

    fn measure_run(ring_path: PathBuf, duration: Duration, interval: Duration) -> ExitCode {
        if let Err(code) = ensure_parent(&ring_path) {
            return code;
        }
        let stop = runner::stop_channel();
        let _ = winapi::stop_on_ctrl_c();
        println!(
            "Measuring for {} s at a {} s interval (real ticks, real ring writes). Do not trust a run during a build.",
            duration.as_secs(),
            interval.as_secs_f64()
        );
        // A ring that was already there (possibly the real one, given with --ring) is not ours to
        // delete: measuring adds its rows to it, which are real samples, and leaves it in place.
        let existed = ring_path.exists();
        let result = measure::measure(&ring_path, duration, interval, &stop);
        if !existed {
            let _ = std::fs::remove_file(&ring_path);
        }
        match result {
            Ok(report) => {
                println!("{report}");
                ExitCode::SUCCESS
            }
            Err(e) => finish(Err(format!("cannot use {}: {e}", ring_path.display()))),
        }
    }
}
