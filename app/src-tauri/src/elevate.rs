//! "See more with admin": run the shipped command line with its own `--elevate` path.
//!
//! The app never asks Windows for elevation itself. It starts `pcsleuth.exe <question> --json
//! --elevate`, which shows the Windows permission prompt, and reads the JSON answer back. Nothing
//! here runs in a test: the prompt needs a person. The command building, the lookup of the program
//! and the reading of its output are pure and tested.

use std::path::{Path, PathBuf};

use pcsleuth_core::{Answer, Question};

/// The command line program, shipped in the same folder as the app.
pub const CLI_NAME: &str = "pcsleuth.exe";

/// The program beside `app_exe`, or why there is none.
pub fn cli_beside(app_exe: &Path) -> Result<PathBuf, String> {
    let dir = app_exe
        .parent()
        .ok_or_else(|| "could not tell which folder the app is in".to_owned())?;
    let cli = dir.join(CLI_NAME);
    if cli.is_file() {
        Ok(cli)
    } else {
        Err(format!(
            "{CLI_NAME} was not found next to the app ({}). It is needed to ask Windows for admin \
             rights; the app does not do that itself.",
            dir.display()
        ))
    }
}

/// Arguments for the command line: the same question as JSON, elevated. Only a limit the user
/// chose is passed, so a default stays the default.
pub fn args(question: Question, limit: Option<usize>) -> Vec<String> {
    let mut args = vec![
        question.as_str().to_owned(),
        "--json".to_owned(),
        "--elevate".to_owned(),
    ];
    if let Some(limit) = limit.filter(|limit| *limit > 0) {
        args.push("--limit".to_owned());
        args.push(limit.to_string());
    }
    args
}

/// What came back from the command line.
#[derive(Debug, PartialEq)]
pub struct Outcome {
    pub answer: Answer,
    /// What the program said on stderr. When the prompt was declined or failed it says so here
    /// and the answer is the one without admin.
    pub notice: Option<String>,
}

/// Read the output of a finished run. A non-zero exit is an error with the program's own words.
pub fn read_output(success: bool, stdout: &[u8], stderr: &[u8]) -> Result<Outcome, String> {
    let said = String::from_utf8_lossy(stderr).trim().to_owned();
    if !success {
        return Err(if said.is_empty() {
            format!("{CLI_NAME} stopped without an answer")
        } else {
            said
        });
    }
    let answer: Answer = serde_json::from_slice(stdout)
        .map_err(|error| format!("{CLI_NAME} did not return an answer: {error}"))?;
    Ok(Outcome {
        answer,
        notice: (!said.is_empty()).then_some(said),
    })
}

/// Run `cli` and read its answer. Blocks until the person answers the Windows prompt.
pub fn run(cli: &Path, question: Question, limit: Option<usize>) -> Result<Outcome, String> {
    use std::process::{Command, Stdio};

    let mut command = Command::new(cli);
    command
        .args(args(question, limit))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window flashing up beside the permission prompt.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not start {CLI_NAME}: {error}"))?;
    read_output(output.status.success(), &output.stdout, &output.stderr)
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::Timestamp;

    use super::*;

    #[test]
    fn the_program_is_asked_for_json_and_elevation_and_nothing_it_would_misread() {
        assert_eq!(
            args(Question::NoSleep, None),
            ["nosleep", "--json", "--elevate"]
        );
        assert_eq!(
            args(Question::Timeline, Some(500)),
            ["timeline", "--json", "--elevate", "--limit", "500"]
        );
        // A limit of zero would be refused by the program; the default applies instead.
        assert_eq!(args(Question::Wake, Some(0)).len(), 3);
    }

    #[test]
    fn a_missing_program_is_an_explained_error_and_a_present_one_is_found() {
        let dir = std::env::temp_dir().join(format!("pcsleuth-app-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = dir.join("pcsleuth-app.exe");
        let error = cli_beside(&app).unwrap_err();
        assert!(error.contains(CLI_NAME), "{error}");

        std::fs::write(dir.join(CLI_NAME), b"").unwrap();
        assert_eq!(cli_beside(&app), Ok(dir.join(CLI_NAME)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn answer_json() -> Vec<u8> {
        let answer = Answer::new(Question::Wake, Timestamp::UNIX_EPOCH, vec![], vec![]);
        serde_json::to_vec(&answer).unwrap()
    }

    #[test]
    fn an_answer_is_read_and_what_the_program_said_is_kept_as_a_notice() {
        let clean = read_output(true, &answer_json(), b"").unwrap();
        assert_eq!(clean.notice, None);

        let declined = read_output(
            true,
            &answer_json(),
            b"pcsleuth: could not run elevated (cancelled); showing the answer without admin\r\n",
        )
        .unwrap();
        assert!(declined.notice.unwrap().contains("could not run elevated"));
    }

    #[test]
    fn a_failure_or_garbage_is_an_error_not_a_panic() {
        assert!(read_output(false, b"", b"pcsleuth: boom").unwrap_err() == "pcsleuth: boom");
        assert!(
            read_output(false, b"", b"")
                .unwrap_err()
                .contains("stopped")
        );
        assert!(read_output(true, b"", b"").is_err());
        assert!(read_output(true, b"{\"nonsense\":1}", b"").is_err());
        assert!(read_output(true, &[0xff, 0xfe], b"").is_err());
    }
}
