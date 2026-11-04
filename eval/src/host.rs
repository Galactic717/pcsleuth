//! Facts about where a run happened, and ground truth read from the Application event log.
//!
//! The ground truth comes from `wevtutil` on purpose: it is a different path from the engine's
//! `EvtQuery`, so the scorer's record ids do not depend on the code being scored.

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde::Serialize;

use crate::sys;

/// Where and when a run happened. Holds no machine name and no user name.
#[derive(Debug, Clone, Serialize)]
pub struct Env {
    /// `ci` or `laptop`: results from the two are never mixed up.
    pub tag: &'static str,
    pub elevated: bool,
    pub os_build: String,
    pub git_commit: String,
    pub git_dirty: bool,
    pub date: Timestamp,
}

impl Env {
    pub fn detect() -> Env {
        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        };
        let git_commit = git(&["rev-parse", "--short=12", "HEAD"])
            .filter(|commit| !commit.is_empty())
            .or_else(|| {
                std::env::var("GITHUB_SHA")
                    .ok()
                    .map(|sha| sha.chars().take(12).collect())
            })
            .unwrap_or_else(|| "unknown".to_owned());
        Env {
            tag: tag(
                std::env::var("PCSLEUTH_EVAL_WHERE").ok().as_deref(),
                std::env::var("CI").ok().as_deref(),
            ),
            elevated: sys::is_elevated(),
            os_build: sys::os_build(),
            git_commit,
            git_dirty: git(&["status", "--porcelain"]).is_some_and(|status| !status.is_empty()),
            date: Timestamp::now(),
        }
    }
}

/// `PCSLEUTH_EVAL_WHERE=ci|laptop` decides; without it, the `CI` variable that CI systems set
/// means `ci`, and anything else means `laptop`.
pub fn tag(explicit: Option<&str>, ci: Option<&str>) -> &'static str {
    match explicit {
        Some("ci") => "ci",
        Some("laptop") => "laptop",
        _ if ci.is_some_and(|value| !value.is_empty()) => "ci",
        _ => "laptop",
    }
}

/// Values that must never reach a results file, with what replaces them.
pub fn secrets() -> Vec<(String, &'static str)> {
    let mut secrets: Vec<(String, &'static str)> = [
        ("USERPROFILE", "<home>"),
        ("USERNAME", "<user>"),
        ("COMPUTERNAME", "<host>"),
        ("USERDOMAIN", "<domain>"),
    ]
    .into_iter()
    .filter_map(|(name, mask)| std::env::var(name).ok().map(|value| (value, mask)))
    .filter(|(value, _)| !value.trim().is_empty())
    .collect();
    // Longest first, so the profile path is masked before the user name inside it.
    secrets.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
    secrets
}

/// Replace every secret, ignoring ASCII case. Used on every free-text field of a results file.
pub fn scrub(text: &str, secrets: &[(String, &str)]) -> String {
    let mut out = text.to_owned();
    for (secret, mask) in secrets {
        // ASCII lowercasing keeps byte lengths, so indexes in `lower` are valid in `out`.
        let needle = secret.to_ascii_lowercase();
        let mut from = 0;
        while let Some(found) = out.to_ascii_lowercase()[from..].find(&needle) {
            let start = from + found;
            out.replace_range(start..start + needle.len(), mask);
            from = start + mask.len();
        }
    }
    out
}

/// One Application Error or Application Hang event, reduced to what matching needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEvent {
    pub record_id: String,
    pub app: String,
    pub pid: u32,
    pub time: Timestamp,
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = text.find(start)? + start.len();
    let len = text[from..].find(end)?;
    Some(&text[from..from + len])
}

/// The `Name='x'` or `Name="x"` data element, whichever quote the writer used.
fn data<'a>(event: &'a str, name: &str) -> Option<&'a str> {
    [('\'', "'"), ('"', "\"")]
        .iter()
        .find_map(|(quote, _)| between(event, &format!("Name={quote}{name}{quote}>"), "</Data>"))
}

/// Events of one provider from `wevtutil qe ... /f:xml` output. Other providers that reuse the
/// same event id are skipped: on this laptop an unrelated service also writes id 1000.
pub fn parse_app_events(xml: &str, provider: &str) -> Vec<AppEvent> {
    xml.split("<Event ")
        .skip(1)
        .filter(|event| {
            between(event, "<Provider Name=", "Guid")
                .or_else(|| between(event, "<Provider Name=", "/>"))
                .is_some_and(|name| name.trim().trim_matches(['\'', '"']) == provider)
        })
        .filter_map(|event| {
            let time = between(event, "SystemTime='", "'")
                .or_else(|| between(event, "SystemTime=\"", "\""))?;
            let pid = data(event, "ProcessId")?;
            Some(AppEvent {
                record_id: between(event, "<EventRecordID>", "</EventRecordID>")?.to_owned(),
                app: data(event, "AppName")?.to_owned(),
                pid: u32::from_str_radix(pid.trim_start_matches("0x"), 16).ok()?,
                time: time.parse().ok()?,
            })
        })
        .collect()
}

/// The newest events with this provider and id in the Application log. Readable without admin.
pub fn app_events(provider: &str, event_id: u32) -> Result<Vec<AppEvent>> {
    let query = format!("*[System[Provider[@Name='{provider}'] and (EventID={event_id})]]");
    let output = Command::new("wevtutil")
        .args(["qe", "Application"])
        .arg(format!("/q:{query}"))
        .args(["/c:200", "/rd:true", "/f:xml"])
        .output()
        .context("could not run wevtutil")?;
    if !output.status.success() {
        bail!("wevtutil failed with {}", output.status);
    }
    Ok(parse_app_events(
        &String::from_utf8_lossy(&output.stdout),
        provider,
    ))
}

/// Wait for the event this very process produced: same exe name, same process id, not older than
/// `since`. An earlier run of the same exe has a different id, so it cannot be picked up.
pub fn wait_for_event(
    provider: &str,
    event_id: u32,
    exe: &str,
    pid: u32,
    since: Timestamp,
    timeout: Duration,
) -> Result<Option<AppEvent>> {
    let deadline = Instant::now() + timeout;
    loop {
        let found = app_events(provider, event_id)?.into_iter().find(|event| {
            event.app.eq_ignore_ascii_case(exe) && event.pid == pid && event.time >= since
        });
        if found.is_some() || Instant::now() >= deadline || sys::interrupted() {
            return Ok(found);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERRORS: &str = include_str!("../../fixtures/eventlog/application-error-1000.xml");
    const HANGS: &str = include_str!("../../fixtures/eventlog/application-hang-1002.xml");

    #[test]
    fn parses_real_application_error_events_by_name() {
        let events = parse_app_events(ERRORS, "Application Error");
        assert_eq!(events.len(), 6);
        assert_eq!(events[0].record_id, "170177");
        assert_eq!(events[0].app, "RedactedApp.exe");
        assert_eq!(events[0].pid, 0x6838);
        assert_eq!(
            events[0].time,
            "2026-11-01T16:34:36.9392248Z".parse().unwrap()
        );
        assert_eq!(events[3].pid, 0x13f8);
    }

    #[test]
    fn parses_real_application_hang_events() {
        let events = parse_app_events(HANGS, "Application Hang");
        assert_eq!(events.len(), 6);
        assert_eq!(events[0].app, "dllhost.exe");
        assert_eq!(events[0].pid, 0x2e80);
        assert_eq!(events[5].record_id, "150268");
    }

    #[test]
    fn another_provider_with_the_same_event_id_is_skipped() {
        let xml = "<Event xmlns='x'><System><Provider Name='CodexSandboxService.OpenAI.Codex'/>\
                   <EventID Qualifiers='0'>1000</EventID>\
                   <TimeCreated SystemTime='2026-11-03T16:31:25.2548864Z'/>\
                   <EventRecordID>172266</EventRecordID></System>\
                   <EventData><Data>The service is running.</Data></EventData></Event>";
        assert!(parse_app_events(xml, "Application Error").is_empty());
    }

    #[test]
    fn single_quoted_wevtutil_output_parses_like_the_fixtures() {
        let xml = "<Event xmlns='x'><System><Provider Name='Application Error' Guid='{a}'/>\
                   <EventID>1000</EventID>\
                   <TimeCreated SystemTime='2026-11-03T18:36:59.2308942Z'/>\
                   <EventRecordID>172833</EventRecordID></System><EventData>\
                   <Data Name='AppName'>pcsleuth-fault-crash.exe</Data>\
                   <Data Name='ProcessId'>0x63ac</Data></EventData></Event>";
        let events = parse_app_events(xml, "Application Error");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].record_id, "172833");
        assert_eq!(events[0].app, "pcsleuth-fault-crash.exe");
        assert_eq!(events[0].pid, 0x63ac);
    }

    #[test]
    fn garbage_yields_no_events_and_does_not_panic() {
        for xml in [
            "",
            "<Event ",
            "<Event <Event >",
            "not xml at all",
            "<Event x></Event>",
        ] {
            assert!(
                parse_app_events(xml, "Application Error").is_empty(),
                "{xml:?}"
            );
        }
    }

    #[test]
    fn tag_prefers_the_explicit_setting_then_ci_then_laptop() {
        assert_eq!(tag(Some("ci"), None), "ci");
        assert_eq!(tag(Some("laptop"), Some("true")), "laptop");
        assert_eq!(tag(None, Some("true")), "ci");
        assert_eq!(tag(None, Some("")), "laptop");
        assert_eq!(tag(None, None), "laptop");
        assert_eq!(tag(Some("whatever"), None), "laptop");
        assert_eq!(tag(Some("whatever"), Some("1")), "ci");
    }

    #[test]
    fn scrub_masks_names_and_paths_in_any_case() {
        let secrets = vec![
            (r"C:\Users\Alex!".to_owned(), "<home>"),
            ("Alex!".to_owned(), "<user>"),
            ("WORKBOX".to_owned(), "<host>"),
        ];
        assert_eq!(
            scrub(
                r"cannot open c:\users\alex!\x on workbox as ALEX!",
                &secrets
            ),
            r"cannot open <home>\x on <host> as <user>"
        );
        assert_eq!(scrub("nothing here", &secrets), "nothing here");
        assert_eq!(scrub("", &secrets), "");
        assert_eq!(scrub("WORKBOXWORKBOX", &secrets), "<host><host>");
    }

    #[test]
    fn scrub_keeps_non_ascii_text_intact() {
        let secrets = vec![("Олег".to_owned(), "<user>")];
        assert_eq!(scrub("Привіт, Олег!", &secrets), "Привіт, <user>!");
        assert_eq!(scrub("Привіт", &[]), "Привіт");
    }

    #[test]
    fn secrets_never_include_blank_values() {
        for (value, _) in secrets() {
            assert!(!value.trim().is_empty());
        }
    }
}
