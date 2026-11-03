//! Runs the real binary.

use std::process::{Command, Output};

use pcsleuth_core::{Answer, Confidence, Question, SCHEMA_VERSION};

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
fn doctor_json_is_one_parseable_answer_and_nothing_else() {
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
    assert_eq!(answer.findings.len(), 1);
    assert_eq!(answer.findings[0].confidence(), Confidence::NotRecorded);
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
fn human_output_is_text_with_confidence() {
    let output = pcsleuth(&["wake"]);
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("pcsleuth wake (generated "), "{text}");
    assert!(text.contains("Confidence: not recorded"), "{text}");
}

#[test]
fn elevate_is_not_implemented_and_prints_nothing_on_stdout() {
    let output = pcsleuth(&["wake", "--elevate", "--json"]);
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented yet"));
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
fn help_and_version_succeed() {
    for flag in ["--help", "--version"] {
        assert_eq!(code(&pcsleuth(&[flag])), Some(0), "{flag}");
    }
}
