//! Pure parser for the XML that `EvtRender` produces (`EvtRenderEventXml`).
//!
//! Reads the `System` header, `EventData` (named `Data`, positional `Data`, `Binary`) and `UserData`.
//! It never looks at `RenderingInfo` or `Message`, which are localized (ADR 0002). Absent fields,
//! unknown versions and unreadable values become `None`; only XML that is not an event at all is an
//! error. It never panics.

use std::fmt;

use jiff::Timestamp;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

/// One `Data` element of `EventData`, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datum {
    /// The `Name` attribute, or `None` for positional data such as EventLog 6009.
    pub name: Option<String>,
    pub value: String,
}

/// One event as `EvtRender` wrote it, with every field optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawEvent {
    pub provider: Option<String>,
    pub event_id: Option<u32>,
    pub version: Option<u32>,
    pub record_id: Option<u64>,
    pub time_created: Option<Timestamp>,
    pub channel: Option<String>,
    pub data: Vec<Datum>,
    /// Decoded `EventData/Binary` (a hex string in the XML), when present and valid.
    pub binary: Option<Vec<u8>>,
    /// Elements under `UserData` as (path, text) for leaves, plus (`path@attribute`, value) for
    /// every attribute. Nested element names are joined with `/`.
    pub user_data: Vec<(String, String)>,
}

/// Why XML could not be read as an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Well-formed or empty input whose root element is not `Event`.
    NotAnEvent,
    /// The XML is malformed. The text is the parser's message, for display only.
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::NotAnEvent => f.write_str("the XML is not an event"),
            ParseError::Malformed(why) => write!(f, "malformed event XML: {why}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// 1601-01-01 as Unix seconds. A FILETIME of zero means "not set" in event data.
const FILETIME_EPOCH_UNIX: i64 = -11_644_473_600;

impl RawEvent {
    /// First `Data` element with this name, exactly as written (may be empty).
    pub fn field(&self, name: &str) -> Option<&str> {
        self.data
            .iter()
            .find(|d| d.name.as_deref() == Some(name))
            .map(|d| d.value.as_str())
    }

    /// Values of the `Data` elements without a name, in order.
    pub fn positional(&self) -> impl Iterator<Item = &str> {
        self.data
            .iter()
            .filter(|d| d.name.is_none())
            .map(|d| d.value.as_str())
    }

    /// The `index`th positional `Data` value.
    pub fn positional_at(&self, index: usize) -> Option<&str> {
        self.positional().nth(index)
    }

    /// A `UserData` leaf by path such as `MemoryExhaustionInfo/SystemInfo/Processes`.
    pub fn user_field(&self, path: &str) -> Option<&str> {
        self.user_data
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, v)| v.as_str())
    }

    /// A named field as text, `None` when absent or blank.
    pub fn text(&self, name: &str) -> Option<String> {
        self.field(name)
            .filter(|v| !v.trim().is_empty())
            .map(str::to_owned)
    }

    /// A named field as a number, decimal or `0x` hex. `None` when absent or unreadable.
    pub fn u64(&self, name: &str) -> Option<u64> {
        self.field(name).and_then(parse_number)
    }

    pub fn u32(&self, name: &str) -> Option<u32> {
        self.u64(name).and_then(|n| u32::try_from(n).ok())
    }

    /// A named field of hex digits with no `0x` prefix, such as Application Error `ExceptionCode`.
    pub fn bare_hex(&self, name: &str) -> Option<u64> {
        let v = self.field(name)?.trim();
        let v = v.strip_prefix("0x").unwrap_or(v);
        u64::from_str_radix(v, 16).ok()
    }

    /// `true`/`false`, also `1`/`0`. Version 2 of Kernel-Power 41 wrote a boolean where later
    /// versions write a number, so callers use [`RawEvent::u32`] first and this as a fallback.
    pub fn bool(&self, name: &str) -> Option<bool> {
        match self.field(name)?.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        }
    }

    /// An ISO 8601 UTC time. A FILETIME of zero (1601-01-01) means "not set" and gives `None`.
    pub fn timestamp(&self, name: &str) -> Option<Timestamp> {
        let ts: Timestamp = self.field(name)?.trim().parse().ok()?;
        (ts.as_second() > FILETIME_EPOCH_UNIX).then_some(ts)
    }

    /// A FILETIME written as a decimal count of 100 ns ticks since 1601. Zero gives `None`.
    pub fn filetime(&self, name: &str) -> Option<Timestamp> {
        filetime_to_timestamp(self.u64(name)?)
    }
}

/// Decimal or `0x` hex, surrounding blanks ignored.
pub(crate) fn parse_number(text: &str) -> Option<u64> {
    let t = text.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse().ok(),
    }
}

pub(crate) fn filetime_to_timestamp(ticks: u64) -> Option<Timestamp> {
    if ticks == 0 {
        return None;
    }
    let secs = i64::try_from(ticks / 10_000_000).ok()? + FILETIME_EPOCH_UNIX;
    let nanos = i32::try_from((ticks % 10_000_000) * 100).ok()?;
    Timestamp::new(secs, nanos).ok()
}

/// What the parser keeps about one open element.
#[derive(Default)]
struct Frame {
    name: String,
    text: String,
    has_child: bool,
    /// `Name` attribute of a `Data` element.
    data_name: Option<String>,
    /// Attributes of an element under `UserData`.
    attrs: Vec<(String, String)>,
}

fn attr_value(a: &quick_xml::events::attributes::Attribute<'_>) -> Option<String> {
    a.normalized_value(XmlVersion::Implicit1_0)
        .ok()
        .map(|v| v.into_owned())
}

fn attr(start: &BytesStart<'_>, key: &str) -> Option<String> {
    start.attributes().flatten().find_map(|a| {
        let name = a.key.local_name();
        if AsRef::<str>::as_ref(&name) == key {
            attr_value(&a)
        } else {
            None
        }
    })
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if !t.len().is_multiple_of(2) || !t.is_ascii() {
        return None;
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
        .collect()
}

/// Parse one event. See the module documentation for what is and is not tolerated.
pub fn parse_event(xml: &str) -> Result<RawEvent, ParseError> {
    let mut reader = Reader::from_str(xml);
    let mut ev = RawEvent::default();
    let mut stack: Vec<Frame> = Vec::new();
    let mut seen_root = false;

    loop {
        match reader.read_event() {
            Err(e) => return Err(ParseError::Malformed(e.to_string())),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => open(&mut stack, &mut ev, &e, &mut seen_root)?,
            Ok(Event::Empty(e)) => {
                open(&mut stack, &mut ev, &e, &mut seen_root)?;
                close(&mut stack, &mut ev);
            }
            Ok(Event::End(_)) => close(&mut stack, &mut ev),
            Ok(Event::Text(t)) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&t.xml10_content());
                }
            }
            Ok(Event::CData(c)) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&c);
                }
            }
            Ok(Event::GeneralRef(r)) => {
                if let Some(top) = stack.last_mut() {
                    match &*r {
                        "lt" => top.text.push('<'),
                        "gt" => top.text.push('>'),
                        "amp" => top.text.push('&'),
                        "apos" => top.text.push('\''),
                        "quot" => top.text.push('"'),
                        _ => {
                            if let Ok(Some(c)) = r.resolve_char_ref() {
                                top.text.push(c);
                            }
                        }
                    }
                }
            }
            Ok(_) => {}
        }
    }
    if seen_root {
        Ok(ev)
    } else {
        Err(ParseError::NotAnEvent)
    }
}

fn open(
    stack: &mut Vec<Frame>,
    ev: &mut RawEvent,
    start: &BytesStart<'_>,
    seen_root: &mut bool,
) -> Result<(), ParseError> {
    let name = AsRef::<str>::as_ref(&start.local_name()).to_owned();
    if stack.is_empty() {
        if *seen_root || name != "Event" {
            return Err(ParseError::NotAnEvent);
        }
        *seen_root = true;
    }
    if let Some(parent) = stack.last_mut() {
        parent.has_child = true;
    }
    let section = stack.get(1).map(|f| f.name.as_str());
    let mut frame = Frame {
        name,
        ..Frame::default()
    };
    match (stack.len(), section, frame.name.as_str()) {
        (2, Some("System"), "Provider") => ev.provider = attr(start, "Name"),
        (2, Some("System"), "TimeCreated") => {
            ev.time_created = attr(start, "SystemTime").and_then(|t| t.trim().parse().ok());
        }
        (2, Some("EventData"), "Data") => frame.data_name = attr(start, "Name"),
        (depth, Some("UserData"), _) if depth >= 2 => {
            frame.attrs = start
                .attributes()
                .flatten()
                .filter_map(|a| {
                    let key = AsRef::<str>::as_ref(&a.key.local_name()).to_owned();
                    let value = attr_value(&a)?;
                    (key != "xmlns").then_some((key, value))
                })
                .collect();
        }
        _ => {}
    }
    stack.push(frame);
    Ok(())
}

fn close(stack: &mut Vec<Frame>, ev: &mut RawEvent) {
    let Some(frame) = stack.pop() else { return };
    let section = stack.get(1).map(|f| f.name.as_str());
    let depth = stack.len();
    let text = frame.text.trim();
    match (depth, section, frame.name.as_str()) {
        (2, Some("System"), "EventID") => {
            ev.event_id = parse_number(text).and_then(|n| n.try_into().ok())
        }
        (2, Some("System"), "Version") => {
            ev.version = parse_number(text).and_then(|n| n.try_into().ok())
        }
        (2, Some("System"), "EventRecordID") => ev.record_id = parse_number(text),
        (2, Some("System"), "Channel") => ev.channel = (!text.is_empty()).then(|| text.to_owned()),
        (2, Some("EventData"), "Data") => ev.data.push(Datum {
            name: frame.data_name,
            value: frame.text,
        }),
        (2, Some("EventData"), "Binary") => ev.binary = decode_hex(text),
        (depth, Some("UserData"), _) if depth >= 2 => {
            let path: Vec<&str> = stack[2..]
                .iter()
                .map(|f| f.name.as_str())
                .chain([frame.name.as_str()])
                .collect();
            let path = path.join("/");
            for (key, value) in &frame.attrs {
                ev.user_data.push((format!("{path}@{key}"), value.clone()));
            }
            if !frame.has_child {
                ev.user_data.push((path, text.to_owned()));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::fixture_lines;

    const HEAD: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="P" /><EventID>7</EventID><Version>2</Version><TimeCreated SystemTime="2026-11-03T12:33:08.9843714Z" /><EventRecordID>9</EventRecordID><Channel>System</Channel><Computer>SECRET-PC</Computer></System>"#;

    fn event(tail: &str) -> RawEvent {
        parse_event(&format!("{HEAD}{tail}</Event>")).unwrap()
    }

    #[test]
    fn reads_the_system_header() {
        let ev = event("");
        assert_eq!(ev.provider.as_deref(), Some("P"));
        assert_eq!(ev.event_id, Some(7));
        assert_eq!(ev.version, Some(2));
        assert_eq!(ev.record_id, Some(9));
        assert_eq!(ev.channel.as_deref(), Some("System"));
        assert_eq!(
            ev.time_created,
            Some("2026-11-03T12:33:08.9843714Z".parse().unwrap())
        );
        assert!(
            !format!("{ev:?}").contains("SECRET-PC"),
            "computer name is not kept"
        );
    }

    #[test]
    fn reads_named_positional_binary_and_user_data() {
        let ev = event(
            r#"<EventData><Data Name="A">1</Data><Data>pos0</Data><Data Name="A">dup</Data><Data></Data><Binary>0aFF</Binary></EventData>
               <UserData><Info xmlns="urn:x" kind="k"><Sys><Limit>5</Limit></Sys><Sys><Limit>6</Limit></Sys></Info></UserData>"#,
        );
        assert_eq!(ev.field("A"), Some("1"));
        assert_eq!(ev.positional().collect::<Vec<_>>(), ["pos0", ""]);
        assert_eq!(ev.positional_at(0), Some("pos0"));
        assert_eq!(
            ev.data
                .iter()
                .filter(|d| d.name.as_deref() == Some("A"))
                .count(),
            2
        );
        assert_eq!(ev.binary, Some(vec![0x0a, 0xff]));
        assert_eq!(ev.user_field("Info@kind"), Some("k"));
        assert_eq!(ev.user_field("Info/Sys/Limit"), Some("5"));
        assert_eq!(
            ev.user_data
                .iter()
                .filter(|(p, _)| p == "Info/Sys/Limit")
                .count(),
            2
        );
    }

    #[test]
    fn decodes_entities_and_keeps_text_exactly() {
        let ev = event(
            r#"<EventData><Data Name="X"> a &amp; b &lt;c&gt; &#x41;&#66; </Data></EventData>"#,
        );
        assert_eq!(ev.field("X"), Some(" a & b <c> AB "));
    }

    #[test]
    fn never_reads_rendering_info_or_message() {
        let ev = event(
            r#"<EventData><Data Name="Real">v</Data></EventData><RenderingInfo Culture="uk-UA"><Message>ЛОКАЛІЗОВАНИЙ ТЕКСТ</Message><Level>Відомості</Level></RenderingInfo>"#,
        );
        assert_eq!(ev.data.len(), 1);
        assert!(!format!("{ev:?}").contains("ЛОКАЛІЗОВАНИЙ"));
    }

    #[test]
    fn absent_unknown_and_bad_values_are_none() {
        let ev = parse_event(
            r#"<Event><System><EventID>abc</EventID><Version>99999999999</Version><TimeCreated SystemTime="yesterday"/><EventRecordID>-4</EventRecordID></System><EventData><Data Name="N">zz</Data><Binary>xyz</Binary></EventData></Event>"#,
        )
        .unwrap();
        assert_eq!(ev.event_id, None);
        assert_eq!(ev.version, None);
        assert_eq!(ev.time_created, None);
        assert_eq!(ev.record_id, None);
        assert_eq!(ev.provider, None);
        assert_eq!(ev.u32("N"), None);
        assert_eq!(ev.u32("Missing"), None);
        assert_eq!(ev.binary, None);
        assert_eq!(parse_event("<Event/>").unwrap(), RawEvent::default());
    }

    #[test]
    fn numbers_booleans_and_times() {
        let ev = event(
            r#"<EventData><Data Name="d">12</Data><Data Name="h">0x1F</Data><Data Name="b">True</Data><Data Name="e">c0000005</Data><Data Name="z">1601-01-01T00:00:00.0000000Z</Data><Data Name="t">2026-10-28T14:30:32.4608457Z</Data><Data Name="f">134379578418214252</Data></EventData>"#,
        );
        assert_eq!((ev.u32("d"), ev.u32("h")), (Some(12), Some(31)));
        assert_eq!(ev.bool("b"), Some(true));
        assert_eq!(ev.bare_hex("e"), Some(0xc000_0005));
        assert_eq!(ev.timestamp("z"), None, "FILETIME zero is not a time");
        assert_eq!(
            ev.timestamp("t").unwrap().to_string(),
            "2026-10-28T14:30:32.4608457Z"
        );
        assert_eq!(
            ev.filetime("f").unwrap().to_string(),
            "2026-10-31T22:04:01.8214252Z"
        );
    }

    #[test]
    fn rejects_what_is_not_an_event() {
        assert_eq!(parse_event(""), Err(ParseError::NotAnEvent));
        assert_eq!(parse_event("<Other/>"), Err(ParseError::NotAnEvent));
        assert!(matches!(
            parse_event("<Event></Wrong>"),
            Err(ParseError::Malformed(_))
        ));
    }

    #[test]
    fn every_fixture_event_parses_and_has_its_header() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/eventlog");
        let mut files = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "xml") {
                files += 1;
                let name = path.file_name().unwrap().to_str().unwrap().to_owned();
                let events = fixture_lines(&name);
                assert!(!events.is_empty(), "{name} has no events");
                for xml in events {
                    let ev = parse_event(&xml).unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert!(ev.provider.is_some() && ev.event_id.is_some(), "{name}");
                    assert!(
                        ev.record_id.is_some() && ev.time_created.is_some(),
                        "{name}"
                    );
                }
            }
        }
        assert!(files >= 12);
    }

    #[test]
    fn truncated_input_never_panics() {
        let xml = fixture_lines("power-troubleshooter-1.xml").remove(0);
        for (i, _) in xml.char_indices() {
            let _ = parse_event(&xml[..i]);
        }
        let _ = parse_event(&xml.replace("</EventData>", ""));
    }
}
