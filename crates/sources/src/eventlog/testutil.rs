//! Test helpers: read events from `fixtures/eventlog/`.

use std::path::PathBuf;

use super::raw::{RawEvent, parse_event};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/eventlog")
        .join(name)
}

/// The events of a fixture file as XML text. Files hold one event per line, but a few real
/// events (Windows Error Reporting) contain newlines in their data, so this splits on `</Event>`.
pub fn fixture_lines(name: &str) -> Vec<String> {
    let text = std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("cannot read fixture {name}: {e}"));
    text.split_inclusive("</Event>")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn fixture_events(name: &str) -> Vec<RawEvent> {
    fixture_lines(name)
        .iter()
        .map(|xml| parse_event(xml).unwrap_or_else(|e| panic!("{name}: {e}")))
        .collect()
}

/// The fixture event with this record id.
pub fn record(name: &str, record_id: u64) -> RawEvent {
    fixture_events(name)
        .into_iter()
        .find(|e| e.record_id == Some(record_id))
        .unwrap_or_else(|| panic!("record {record_id} is not in {name}"))
}

/// The first fixture event with this event id.
pub fn first_with_id(name: &str, event_id: u32) -> RawEvent {
    fixture_events(name)
        .into_iter()
        .find(|e| e.event_id == Some(event_id))
        .unwrap_or_else(|| panic!("event {event_id} is not in {name}"))
}
