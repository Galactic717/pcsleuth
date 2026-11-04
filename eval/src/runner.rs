//! Runs the scenarios: builds or finds the tool, injects each fault, asks the question, scores.
//!
//! Cleanup has three layers. A guard kills each injector when its scenario ends or panics. Ctrl+C
//! sets a flag that every wait loop polls, so the guards run. And every injector sits in a job
//! object that kills it when the runner's handle closes, however the runner ends.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use pcsleuth_core::{Answer, Question};

use crate::fault::disk_dir;
use crate::host::{self, Env};
use crate::report::{self, RESULTS_SCHEMA, Results, Row, Summary};
use crate::scenario::{self, Fault, Inject, SCENARIOS, Scenario};
use crate::score::{self, Expect, Observable, Scored};
use crate::sys::{self, Job};

/// How long an injector gets to say `ready`.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// How long one `pcsleuth <question> --json` call gets.
const CLI_TIMEOUT: Duration = Duration::from_secs(60);
/// How long WER gets to write the event of a crash or hang.
const EVENT_TIMEOUT: Duration = Duration::from_secs(30);
/// A sleep scenario arms its timer this far ahead, then sleeps.
const WAKE_AFTER_SECS: u64 = 90;

/// What must be typed to allow the sleep scenarios.
pub const SLEEP_CONFIRMATION: &str = "sleep this pc";

pub struct Options {
    pub pcsleuth: Option<PathBuf>,
    pub scenarios: Vec<String>,
    pub sleep: bool,
    pub out: Option<PathBuf>,
}

/// The sleep scenarios stop the machine, so both the flag and the typed phrase are needed.
pub fn sleep_allowed(flag: bool, typed: &str) -> bool {
    flag && typed.trim().eq_ignore_ascii_case(SLEEP_CONFIRMATION)
}

/// The scenarios named, or all of them. An unknown name is an error, not a silent skip.
pub fn select(names: &[String]) -> Result<Vec<&'static Scenario>> {
    if names.is_empty() {
        return Ok(SCENARIOS.iter().collect());
    }
    names
        .iter()
        .map(|name| {
            scenario::find(name).with_context(|| {
                let known: Vec<_> = SCENARIOS.iter().map(|s| s.name).collect();
                format!("no scenario named {name:?}; known: {}", known.join(", "))
            })
        })
        .collect()
}

/// The executables cargo reports from `--message-format=json`, by target name.
pub fn executables(cargo_stdout: &str) -> HashMap<String, PathBuf> {
    cargo_stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter_map(|message| {
            let name = message["target"]["name"].as_str()?.to_owned();
            let path = message["executable"].as_str()?;
            Some((name, PathBuf::from(path)))
        })
        .collect()
}

/// Build the injectors, and the tool unless the caller named one. Always asking cargo means a
/// stale binary left in a shared target folder is never scored by mistake.
fn build(with_tool: bool) -> Result<HashMap<String, PathBuf>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["build", "--message-format=json-render-diagnostics"])
        .args(["-p", "pcsleuth-eval"]);
    for fault in Fault::ALL {
        command.args(["--bin", fault.exe()]);
    }
    if with_tool {
        command.args(["-p", "pcsleuth-cli", "--bin", "pcsleuth"]);
    }
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("could not run cargo to build the tool and the injectors")?;
    if !output.status.success() {
        bail!("cargo build failed ({})", output.status);
    }
    Ok(executables(&String::from_utf8_lossy(&output.stdout)))
}

fn note(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{text}");
}

/// Sleep, but give up at once on Ctrl+C.
fn nap(total: Duration) -> Result<()> {
    let end = Instant::now() + total;
    while Instant::now() < end {
        if sys::interrupted() {
            bail!("interrupted");
        }
        std::thread::sleep(
            end.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50)),
        );
    }
    Ok(())
}

/// A running injector. Dropping it kills it, waits for it, and removes the disk hog's scratch
/// directory, so a scenario that fails or panics leaves nothing behind.
pub struct Injected {
    child: Child,
    lines: Receiver<String>,
    fault: Fault,
}

impl Injected {
    pub fn spawn(job: &Job, exe: &Path, fault: Fault, args: &[String]) -> Result<Injected> {
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("could not start {}", fault.exe()))?;
        let stdout = child.stdout.take().context("the injector has no stdout")?;
        let (sender, lines) = mpsc::channel();
        let injected = Injected {
            child,
            lines,
            fault,
        };
        job.assign(&injected.child)
            .with_context(|| format!("could not place {} in the job object", fault.exe()))?;
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(|line| line.ok()) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(injected)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Wait for the `ready` line. An `error:` line, an early exit or a timeout are errors.
    pub fn wait_ready(&mut self) -> Result<()> {
        let end = Instant::now() + READY_TIMEOUT;
        loop {
            if sys::interrupted() {
                bail!("interrupted");
            }
            match self.lines.recv_timeout(Duration::from_millis(100)) {
                Ok(line) if line.trim() == "ready" => return Ok(()),
                Ok(line) if line.starts_with("error:") => {
                    bail!("{} reported {}", self.fault.exe(), line.trim())
                }
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    if Instant::now() >= end {
                        bail!(
                            "{} was not ready after {} s",
                            self.fault.exe(),
                            READY_TIMEOUT.as_secs()
                        );
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.child.wait().map(|s| s.to_string()).unwrap_or_default();
                    bail!("{} exited ({status}) before it was ready", self.fault.exe());
                }
            }
        }
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if sys::interrupted() {
                bail!("interrupted");
            }
            if Instant::now() >= end {
                bail!(
                    "{} did not exit within {} s",
                    self.fault.exe(),
                    timeout.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Injected {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.fault == Fault::Disk {
            let _ = std::fs::remove_dir_all(disk_dir(self.child.id()));
        }
    }
}

fn drain<R: Read + Send + 'static>(stream: Option<R>) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut stream) = stream {
            let _ = stream.read_to_end(&mut bytes);
        }
        bytes
    })
}

/// Run `tool <question> --json --since <since>` and parse what it prints. The error says why
/// there is no usable answer; the scorer treats that like an empty answer.
fn ask(job: &Job, tool: &Path, question: Question, since: Timestamp) -> Result<Answer, String> {
    let mut child = Command::new(tool)
        .arg(question.as_str())
        .args(["--json", "--since"])
        .arg(since.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start the tool: {error}"))?;
    let _ = job.assign(&child);
    let stdout = drain(child.stdout.take());
    let _stderr = drain(child.stderr.take());
    let end = Instant::now() + CLI_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => return Err(format!("could not wait for the tool: {error}")),
        }
        if sys::interrupted() || Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            return Err(if sys::interrupted() {
                "interrupted".to_owned()
            } else {
                format!("the tool did not answer within {} s", CLI_TIMEOUT.as_secs())
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let bytes = stdout.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("the tool exited with {status}"));
    }
    serde_json::from_slice::<Answer>(&bytes)
        .map_err(|error| format!("the tool printed something that is not an Answer: {error}"))
}

struct Ctx<'a> {
    env: &'a Env,
    job: &'a Job,
    tool: &'a Path,
    exes: &'a HashMap<String, PathBuf>,
}

impl Ctx<'_> {
    fn spawn(&self, fault: Fault, args: &[&str]) -> Result<Injected> {
        let exe = self
            .exes
            .get(fault.exe())
            .with_context(|| format!("cargo did not build {}", fault.exe()))?;
        let args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        Injected::spawn(self.job, exe, fault, &args)
    }

    /// Inject, ask, score. An `Err` means the scenario could not run: it is reported as not run.
    fn execute(
        &self,
        scenario: &Scenario,
        observable: &Observable,
    ) -> Result<(Scored, Vec<String>)> {
        // Two seconds of slack for the clocks of the harness and of the event log.
        let since = Timestamp::from_second(Timestamp::now().as_second() - 2)?;
        let fault = scenario.fault();
        let mut record_ids = Vec::new();
        // Kept alive until the question is answered, then dropped: that kills and cleans up.
        let _held = match scenario.inject {
            Inject::Live {
                secs, settle_secs, ..
            } => {
                let mut injected = self.spawn(fault, &["--secs", &secs.to_string()])?;
                injected.wait_ready()?;
                nap(Duration::from_secs(settle_secs))?;
                injected
            }
            Inject::Past { secs, .. } => {
                let mut injected = self.spawn(fault, &["--secs", &secs.to_string()])?;
                injected.wait_ready()?;
                injected.wait_exit(Duration::from_secs(secs + 20))?;
                injected
            }
            Inject::Event {
                provider, event_id, ..
            } => {
                let mut injected = self.spawn(fault, &[])?;
                injected.wait_ready()?;
                let exe = format!("{}.exe", fault.exe());
                let event =
                    host::wait_for_event(provider, event_id, &exe, injected.pid(), since, EVENT_TIMEOUT)?
                        .with_context(|| {
                            format!(
                                "{provider} {event_id} for {exe} did not appear in the Application log within {} s",
                                EVENT_TIMEOUT.as_secs()
                            )
                        })?;
                record_ids.push(event.record_id);
                injected
            }
            Inject::Sleep { hibernate, .. } => self.sleep_and_wake(fault, hibernate)?,
        };
        let answer = ask(self.job, self.tool, scenario.question, since);
        let expect = Expect {
            cause: fault.cause(),
            record_ids: record_ids.clone(),
            since: Some(since),
        };
        let mut scored = score::score(&expect, observable, answer.as_ref().ok());
        if let Err(why) = &answer {
            scored.detail = format!("{} ({why})", scored.detail);
        }
        Ok((scored, record_ids))
    }

    /// Arm a wake timer, sleep, and return the injector once the machine is back. Only reached
    /// through `--sleep` and the typed confirmation; the author has not run it.
    fn sleep_and_wake(&self, fault: Fault, hibernate: bool) -> Result<Injected> {
        let wake = WAKE_AFTER_SECS.to_string();
        let mut injected = self.spawn(fault, &["--secs", "600", "--fire-in", &wake])?;
        injected.wait_ready()?;
        note(&format!(
            "{} now; the timer should wake this PC in about {WAKE_AFTER_SECS} s",
            if hibernate { "hibernating" } else { "sleeping" }
        ));
        if !sys::suspend(hibernate) {
            bail!("Windows refused the sleep request");
        }
        // Back from sleep: give the logs and the sources a moment to settle.
        nap(Duration::from_secs(45))?;
        Ok(injected)
    }
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_owned())
}

/// Why the sleep scenarios may not run, or `None` when they may.
fn sleep_block(opts: &Options, env: &Env, wanted: bool) -> Option<&'static str> {
    if !wanted {
        return None;
    }
    if !opts.sleep {
        return Some("sleep scenario: skipped; pass --sleep and type the confirmation to run it");
    }
    if env.tag == "ci" {
        return Some("sleep scenario: skipped; CI runners cannot sleep");
    }
    note(&format!(
        "\nThe sleep scenarios put THIS PC to sleep or hibernate it, and a timer must wake it.\n\
         If wake timers are disabled in the power plan, it stays asleep until you wake it.\n\
         Save your work and plug in the charger. Type {SLEEP_CONFIRMATION:?} to go on:"
    ));
    let mut typed = String::new();
    let _ = std::io::stdin().read_line(&mut typed);
    if sleep_allowed(opts.sleep, &typed) {
        None
    } else {
        Some("sleep scenario: skipped; the confirmation was not typed")
    }
}

pub fn run(opts: Options) -> Result<ExitCode> {
    if !cfg!(windows) {
        bail!("the evaluation harness runs on Windows only");
    }
    sys::install_ctrl_handler();
    let selected = select(&opts.scenarios)?;
    let env = Env::detect();
    let job = Job::new().context("could not create the job object that cleans up injectors")?;
    note("building the tool and the injectors ...");
    let exes = build(opts.pcsleuth.is_none())?;
    let tool = match &opts.pcsleuth {
        Some(path) => path.clone(),
        None => exes
            .get("pcsleuth")
            .cloned()
            .context("cargo did not report a pcsleuth binary")?,
    };
    if !tool.is_file() {
        bail!("the tool {} does not exist", tool.display());
    }

    let sleep_block = sleep_block(&opts, &env, selected.iter().any(|s| s.sleeps()));
    let secrets = host::secrets();
    let ctx = Ctx {
        env: &env,
        job: &job,
        tool: &tool,
        exes: &exes,
    };
    let mut rows = Vec::new();
    for scenario in selected {
        note(&format!("running {} ...", scenario.name));
        let observable = scenario.needs.observable(ctx.env.elevated);
        let not_run =
            |reason: String| Row::not_run(scenario.name, scenario.question, &observable, reason);
        let mut row = if sys::interrupted() {
            not_run("interrupted".to_owned())
        } else if let (true, Some(why)) = (scenario.sleeps(), sleep_block) {
            not_run(why.to_owned())
        } else {
            match catch_unwind(AssertUnwindSafe(|| ctx.execute(scenario, &observable))) {
                Ok(Ok((scored, ids))) => {
                    Row::scored(scenario.name, scenario.question, &observable, scored, ids)
                }
                Ok(Err(error)) => not_run(format!("{error:#}")),
                Err(payload) => not_run(format!("the harness panicked: {}", panic_text(&*payload))),
            }
        };
        // Free text can carry a path or a name from an OS error. Nothing personal may reach disk.
        row.detail = host::scrub(&row.detail, &secrets);
        row.why = row.why.map(|why| host::scrub(&why, &secrets));
        row.named = row
            .named
            .iter()
            .map(|name| host::scrub(name, &secrets))
            .collect();
        rows.push(row);
    }

    print!("{}", report::table(&rows));
    let summary = Summary::of(&rows);
    let dir = opts
        .out
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("results"));
    std::fs::create_dir_all(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    let path = dir.join(report::file_name(&env));
    let results = Results {
        schema: RESULTS_SCHEMA,
        env: &env,
        summary: &summary,
        scenarios: &rows,
    };
    std::fs::write(&path, serde_json::to_string_pretty(&results)? + "\n")
        .with_context(|| format!("could not write {}", path.display()))?;
    println!("results: {}", path.display());
    Ok(if sys::interrupted() {
        ExitCode::from(130)
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleeping_needs_the_flag_and_the_exact_phrase() {
        assert!(sleep_allowed(true, "sleep this pc"));
        assert!(sleep_allowed(true, "  Sleep This PC \r\n"));
        assert!(!sleep_allowed(false, "sleep this pc"));
        for typed in [
            "",
            "yes",
            "y",
            "sleep",
            "sleep this pc now",
            "sleep this pc please",
        ] {
            assert!(!sleep_allowed(true, typed), "{typed:?}");
        }
    }

    #[test]
    fn select_defaults_to_all_and_rejects_unknown_names() {
        assert_eq!(select(&[]).unwrap().len(), SCENARIOS.len());
        let one = select(&["cpu-hog-live".to_owned()]).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "cpu-hog-live");
        let error = select(&["nope".to_owned()]).unwrap_err().to_string();
        assert!(
            error.contains("nope") && error.contains("crash-app-error"),
            "{error}"
        );
    }

    #[test]
    fn executables_come_from_cargo_artifact_messages_only() {
        let stdout = r#"{"reason":"compiler-message","message":{}}
{"reason":"compiler-artifact","target":{"name":"pcsleuth","kind":["bin"]},"executable":"C:\\t\\debug\\pcsleuth.exe","fresh":true}
{"reason":"compiler-artifact","target":{"name":"pcsleuth_core","kind":["lib"]},"executable":null}
not json at all
{"reason":"build-finished","success":true}"#;
        let exes = executables(stdout);
        assert_eq!(exes.len(), 1);
        assert_eq!(exes["pcsleuth"], PathBuf::from(r"C:\t\debug\pcsleuth.exe"));
        assert!(executables("").is_empty());
    }

    #[test]
    fn panic_payloads_become_text() {
        let from_str = catch_unwind(|| panic!("plain")).unwrap_err();
        assert_eq!(panic_text(&*from_str), "plain");
        let from_string = catch_unwind(|| panic!("{}", String::from("formatted"))).unwrap_err();
        assert_eq!(panic_text(&*from_string), "formatted");
    }
}
