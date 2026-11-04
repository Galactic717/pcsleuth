//! Runs the real binary, unelevated, against this machine's real logs.
//!
//! The elevated path (`--elevate`, which shows a UAC prompt) is never run here. Its argument
//! building is tested in `src/elevate.rs`, and the file the elevated copy writes is tested below
//! through the hidden `--out-file` flag, which needs no elevation.

use std::path::PathBuf;
use std::process::{Command, Output};

use pcsleuth_core::{Answer, Question, SCHEMA_VERSION, SourceId};

fn pcsleuth(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pcsleuth"))
        .args(args)
        .output()
        .expect("the pcsleuth binary starts")
}

fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

#[test]
fn doctor_json_is_one_parseable_answer_with_a_finding_per_source() {
    let output = pcsleuth(&["doctor", "--json"]);
    assert_eq!(
        code(&output),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // serde_json::from_slice fails on any stray byte before or after the document.
    let answer: Answer = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(answer.schema_version, SCHEMA_VERSION);
    assert_eq!(answer.question, Question::Doctor);
    assert_eq!(answer.findings.len(), SourceId::ALL.len());
    for (finding, source) in answer.findings.iter().zip(SourceId::ALL) {
        assert_eq!(finding.id(), format!("doctor.{source}"));
    }
    assert!(output.stdout.is_ascii());
    assert!(output.stderr.is_empty());
}

#[test]
fn every_question_answers_in_json() {
    for name in [
        "wake", "nosleep", "battery", "crash", "slow", "now", "timeline", "doctor",
    ] {
        let output = pcsleuth(&[name, "--json"]);
        assert_eq!(code(&output), Some(0), "{name}");
        let answer: Answer = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(answer.question.as_str(), name);
        assert!(output.stdout.is_ascii(), "{name}");
    }
}

#[test]
fn global_flags_work_before_and_after_the_subcommand() {
    for args in [
        ["--json", "--since", "7d", "--limit", "5", "wake"],
        ["wake", "--json", "--since", "7d", "--limit", "5"],
    ] {
        let output = pcsleuth(&args);
        assert_eq!(code(&output), Some(0), "{args:?}");
        serde_json::from_slice::<Answer>(&output.stdout).unwrap();
    }
}

#[test]
fn human_output_shows_the_default_window_and_confidence() {
    let output = pcsleuth(&["wake"]);
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("pcsleuth wake - generated "), "{text}");
    assert!(text.contains("(the default, 7 days)"), "{text}");
    assert!(text.contains("dated findings (the default)"), "{text}");
    assert!(text.contains("Confidence: "), "{text}");
}

#[test]
fn a_window_the_user_chose_is_not_called_a_default() {
    let output = pcsleuth(&["crash", "--since", "2026-01-01", "--limit", "3"]);
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("(as you asked). Showing at most 3 dated findings (as you asked)"),
        "{text}"
    );
}

#[test]
fn now_and_doctor_do_not_claim_a_lookback() {
    for name in ["now", "doctor"] {
        let output = pcsleuth(&[name]);
        assert_eq!(code(&output), Some(0), "{name}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("Looked back"), "{name}");
    }
}

#[test]
fn bad_usage_exits_2() {
    for args in [
        &["bogus"][..],
        &[],
        &["wake", "--limit", "0"],
        &["wake", "--limit", "many"],
        &["wake", "--since", "yesterday"],
        &["wake", "--no-such-flag"],
    ] {
        let output = pcsleuth(args);
        assert_eq!(code(&output), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn help_and_version_succeed_and_help_hides_the_internal_flag() {
    for flag in ["--help", "--version"] {
        assert_eq!(code(&pcsleuth(&[flag])), Some(0), "{flag}");
    }
    let help = String::from_utf8(pcsleuth(&["--help"]).stdout).unwrap();
    assert!(help.contains("--elevate"));
    assert!(help.contains("look back 7 days"));
    assert!(!help.contains("out-file"));
}

/// A folder shaped like the ones `--elevate` makes: `pcsleuth-` and 32 hex digits.
fn output_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "pcsleuth-{:032x}",
        nanos ^ u128::from(std::process::id())
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn the_out_file_receives_the_json_answer_and_stdout_stays_empty() {
    let dir = output_dir();
    let file = dir.join("answer.json");
    let output = pcsleuth(&["timeline", "--json", "--out-file", file.to_str().unwrap()]);
    let written = std::fs::read(&file);
    // A second run must not overwrite it: the file is created new.
    let again = pcsleuth(&["timeline", "--json", "--out-file", file.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let answer: Answer = serde_json::from_slice(&written.unwrap()).unwrap();
    assert_eq!(answer.question, Question::Timeline);
    assert_eq!(code(&again), Some(1));
    assert!(again.stdout.is_empty());
}

#[test]
fn an_out_file_outside_a_folder_made_for_it_is_refused_and_nothing_is_written() {
    let stray = std::env::temp_dir().join("pcsleuth-stray-answer.json");
    let _ = std::fs::remove_file(&stray);
    let output = pcsleuth(&["timeline", "--json", "--out-file", stray.to_str().unwrap()]);
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--out-file must be"));
    assert!(!stray.exists());
}
