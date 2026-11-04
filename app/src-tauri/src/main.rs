//! The pcsleuth desktop app: the Tauri side.
//!
//! One command per question, each calling `pcsleuth_engine` in this process, on a worker thread so
//! the window never waits for the event logs. No network code, no updater, no shell plugin: the
//! only program this app ever starts is the shipped command line, and only when the person clicks
//! "See more with admin".
#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod elevate;
mod reply;

use pcsleuth_core::{Answer, Question};
use pcsleuth_engine::Options;
use reply::Reply;

/// Run one question off the UI thread. `limit` is how many dated findings to keep; `None` is the
/// engine's default for that question.
async fn ask(limit: Option<usize>, question: fn(&Options) -> Answer) -> Result<Reply, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut options = Options::default();
        options.limit = limit.filter(|limit| *limit > 0);
        let answer = question(&options);
        Reply::new(&answer, &options, None)
    })
    .await
    .map_err(|error| format!("reading the logs stopped unexpectedly: {error}"))
}

macro_rules! questions {
    ($($name:ident),* $(,)?) => {$(
        #[tauri::command]
        async fn $name(limit: Option<usize>) -> Result<Reply, String> {
            ask(limit, pcsleuth_engine::$name).await
        }
    )*};
}

questions!(timeline, wake, nosleep, battery, crash, slow, now, doctor);

/// Run the shipped command line elevated and return its answer. The Windows permission prompt
/// appears only because this command was called, which only happens on the person's click.
#[tauri::command]
async fn elevated(question: Question, limit: Option<usize>) -> Result<Reply, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let app = std::env::current_exe()
            .map_err(|error| format!("could not find the app's own folder: {error}"))?;
        let cli = elevate::cli_beside(&app)?;
        let limit = limit.filter(|limit| *limit > 0);
        let outcome = elevate::run(&cli, question, limit)?;
        let mut options = Options::default();
        options.limit = limit;
        Ok(Reply::new(
            &outcome.answer,
            &options,
            outcome.notice.as_deref(),
        ))
    })
    .await
    .map_err(|error| format!("the elevated read stopped unexpectedly: {error}"))?
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            timeline, wake, nosleep, battery, crash, slow, now, doctor, elevated
        ])
        .run(tauri::generate_context!())
        .expect("the window could not start");
}
