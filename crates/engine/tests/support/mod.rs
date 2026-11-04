//! Loads `fixtures/` for the tests. Fixtures are real captures except files named `synthetic-*`,
//! which were built by hand from provider manifests and are never counted as real validation.

#![allow(dead_code)]

use std::path::PathBuf;

use pcsleuth_core::{Finding, SourceId, Sourced, Timestamp};
use pcsleuth_engine::Window;
use pcsleuth_sources::eventlog::{RawEvent, parse_event};

pub fn fixture_path(dir: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(dir)
        .join(name)
}

/// The events of an event log fixture. A few real events hold newlines, so split on `</Event>`.
pub fn raw_events(name: &str) -> Vec<RawEvent> {
    let text = std::fs::read_to_string(fixture_path("eventlog", name))
        .unwrap_or_else(|e| panic!("cannot read fixture {name}: {e}"));
    text.split_inclusive("</Event>")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|xml| parse_event(xml).unwrap_or_else(|e| panic!("{name}: {e}")))
        .collect()
}

/// Typed events of a fixture, read fully (access Ok).
pub fn events<T>(
    name: &str,
    source: SourceId,
    convert: impl Fn(&RawEvent) -> Result<T, pcsleuth_sources::eventlog::FromRawError>,
) -> Sourced<T> {
    Sourced::ok(
        source,
        raw_events(name)
            .iter()
            .map(|raw| convert(raw).unwrap_or_else(|e| panic!("{name}: {e}")))
            .collect(),
    )
}

pub fn ts(text: &str) -> Timestamp {
    text.parse().unwrap()
}

/// A window ending after every fixture, starting at `since`.
pub fn window(since: &str) -> Window {
    Window {
        now: ts("2026-11-04T09:00:00Z"),
        since: ts(since),
        limit: 100,
    }
}

pub fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(Finding::id).collect()
}

pub fn by_id<'a>(findings: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.id() == id).collect()
}

/// The finding that cites this event record id.
pub fn citing<'a>(findings: &'a [Finding], record_id: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| {
            f.evidence()
                .iter()
                .any(|e| e.record_id.as_deref() == Some(record_id))
        })
        .unwrap_or_else(|| panic!("no finding cites record {record_id}"))
}
