//! `--elevate` (ADR 0003): run the same question again, elevated, through UAC.
//!
//! The elevated copy writes its answer as JSON to a file in a directory only this run can name
//! (`pcsleuth_sources::power::create_output_dir`), and this run reads the file, deletes the
//! directory and shows the answer. Nothing here is called from a test: the UAC prompt needs a
//! person. The argument building and the parsing of the answer are pure and tested.

use jiff::Timestamp;
use pcsleuth_core::Answer;

/// The most the elevated copy's answer may weigh. A real answer is a few kilobytes.
#[cfg(windows)]
const MAX_ANSWER_BYTES: u64 = 16 * 1024 * 1024;

/// The arguments for the elevated copy: the same question as JSON with the same window. It is
/// never given `--elevate`, so it cannot ask again, and `relaunch_elevated` appends
/// `--out-file <path>`. Only a window the user chose is passed, so a default stays the default.
pub fn child_args(command: &str, since: Option<Timestamp>, limit: Option<u32>) -> Vec<String> {
    let mut args = vec![command.to_owned(), "--json".to_owned()];
    if let Some(since) = since {
        args.push("--since".to_owned());
        args.push(since.to_string());
    }
    if let Some(limit) = limit {
        args.push("--limit".to_owned());
        args.push(limit.to_string());
    }
    args
}

/// The answer the elevated copy wrote.
pub fn parse_answer(bytes: &[u8]) -> Result<Answer, String> {
    serde_json::from_slice(bytes).map_err(|error| {
        format!("the elevated copy wrote something that is not an answer: {error}")
    })
}

/// True when this process already has an elevated token, so there is nothing to ask for.
pub fn already_elevated() -> bool {
    #[cfg(windows)]
    {
        pcsleuth_sources::power::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Run `args` elevated and return the answer, or why that did not work.
#[cfg(windows)]
pub fn fetch(args: &[String]) -> Result<Answer, String> {
    use std::io::Read;

    use pcsleuth_sources::power::{create_output_dir, relaunch_elevated};

    /// Removes the output directory when dropped, whatever happened, so a late write has nowhere to go.
    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let dir =
        Dir(create_output_dir().map_err(|e| format!("could not make a temporary folder: {e}"))?);
    let out_file = dir.0.join("answer.json");
    match relaunch_elevated(args, &out_file) {
        Ok(0) => {}
        Ok(code) => return Err(format!("the elevated copy failed (exit code {code})")),
        Err(error) => return Err(error.to_string()),
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&out_file)
        .and_then(|file| file.take(MAX_ANSWER_BYTES).read_to_end(&mut bytes))
        .map_err(|e| format!("could not read the elevated copy's answer: {e}"))?;
    parse_answer(&bytes)
}

#[cfg(not(windows))]
pub fn fetch(_args: &[String]) -> Result<Answer, String> {
    Err("elevation is only supported on Windows".to_owned())
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::Question;

    use super::*;

    #[test]
    fn the_child_gets_the_question_json_and_only_the_window_the_user_chose() {
        assert_eq!(child_args("wake", None, None), ["wake", "--json"]);
        let since: Timestamp = "2026-11-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            child_args("slow", Some(since), Some(5)),
            [
                "slow",
                "--json",
                "--since",
                "2026-11-01T00:00:00Z",
                "--limit",
                "5"
            ]
        );
    }

    #[test]
    fn the_child_never_gets_elevate_or_the_out_file_flag() {
        let since: Timestamp = "2026-11-01T00:00:00Z".parse().unwrap();
        let args = child_args("nosleep", Some(since), Some(1));
        assert!(!args.iter().any(|a| a == "--elevate" || a == "--out-file"));
    }

    #[test]
    fn the_flag_the_child_is_given_is_the_one_the_command_line_accepts() {
        assert_eq!(pcsleuth_sources::power::OUT_FILE_ARG, "--out-file");
    }

    #[test]
    fn the_since_the_child_is_given_parses_back_to_the_same_time() {
        let since: Timestamp = "2026-11-04T08:59:03.123456789Z".parse().unwrap();
        let args = child_args("wake", Some(since), None);
        let text = &args[3];
        assert_eq!(crate::since::parse(text), Ok(since));
    }

    #[test]
    fn an_answer_round_trips_and_garbage_is_an_error_not_a_panic() {
        let answer = Answer::new(Question::Wake, Timestamp::UNIX_EPOCH, vec![], vec![]);
        let json = serde_json::to_vec(&answer).unwrap();
        assert_eq!(parse_answer(&json), Ok(answer));
        assert!(parse_answer(b"").is_err());
        assert!(parse_answer(b"{\"nonsense\":1}").is_err());
        assert!(parse_answer(&[0xff, 0xfe, 0x00]).is_err());
    }
}
