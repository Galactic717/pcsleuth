//! Pieces every typed event shares: header data, errors, code enums and evidence building.

use std::fmt::{self, Display};

use jiff::Timestamp;
use pcsleuth_core::{Evidence, SourceId};

use super::raw::RawEvent;

/// Header data every typed event keeps from its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub record_id: Option<u64>,
    /// `TimeCreated`: when Windows wrote the record, not always when the thing happened.
    pub time: Option<Timestamp>,
    pub version: Option<u32>,
}

/// Why a raw event could not become a typed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromRawError {
    /// The provider or event id is not the one this type reads.
    WrongEvent {
        expected: &'static str,
        provider: Option<String>,
        event_id: Option<u32>,
    },
    /// A field the type cannot do without is absent or unreadable.
    MissingField(&'static str),
}

impl Display for FromRawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FromRawError::WrongEvent {
                expected,
                provider,
                event_id,
            } => write!(
                f,
                "not a {expected} event (provider {provider:?}, event id {event_id:?})"
            ),
            FromRawError::MissingField(name) => write!(f, "field {name} is missing or unreadable"),
        }
    }
}

impl std::error::Error for FromRawError {}

impl Meta {
    /// Check that `raw` is one of `ids` from one of `providers` and keep its header.
    pub(crate) fn expect(
        raw: &RawEvent,
        expected: &'static str,
        providers: &[&str],
        ids: &[u32],
    ) -> Result<Meta, FromRawError> {
        let right_provider = raw
            .provider
            .as_deref()
            .is_some_and(|p| providers.contains(&p));
        let right_id = raw.event_id.is_some_and(|id| ids.contains(&id));
        if !(right_provider && right_id) {
            return Err(FromRawError::WrongEvent {
                expected,
                provider: raw.provider.clone(),
                event_id: raw.event_id,
            });
        }
        Ok(Meta {
            record_id: raw.record_id,
            time: raw.time_created,
            version: raw.version,
        })
    }

    /// Evidence for this record. Its timestamp is `TimeCreated`; times from inside the event
    /// data are added as fields.
    pub(crate) fn evidence(&self, source: SourceId, event_id: u32) -> Evidence {
        let mut e = Evidence::new(source).with_field("event_id", event_id.to_string());
        if let Some(id) = self.record_id {
            e = e.with_record_id(id.to_string());
        }
        if let Some(t) = self.time {
            e = e.at(t);
        }
        e.opt("version", self.version)
    }
}

/// `Option`-aware field adding for [`Evidence`], so absent values leave no field behind.
pub(crate) trait EvidenceExt {
    fn opt<V: Display>(self, name: &str, value: Option<V>) -> Self;
    /// A code with a label, as `name` (the label) and `name_code` (the number).
    fn code<C: Coded>(self, name: &str, code: C) -> Self;
}

impl EvidenceExt for Evidence {
    fn opt<V: Display>(self, name: &str, value: Option<V>) -> Self {
        match value {
            Some(v) => self.with_field(name, v.to_string()),
            None => self,
        }
    }

    fn code<C: Coded>(self, name: &str, code: C) -> Self {
        self.with_field(name, code.to_string())
            .with_field(format!("{name}_code"), code.number().to_string())
    }
}

/// A numeric code with named values only where they are proven.
pub trait Coded: Display + Copy {
    fn number(self) -> u32;
}

/// Declares an enum of proven numeric codes. Any other number becomes `Other(n)` and displays as
/// `type N`, so unproven values are never given a meaning.
macro_rules! coded_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $var:ident = $code:literal => $label:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $var,)*
            /// A value nobody has proven a meaning for.
            Other(u32),
        }

        impl $name {
            pub fn from_code(code: u32) -> Self {
                match code {
                    $($code => Self::$var,)*
                    n => Self::Other(n),
                }
            }
        }

        impl $crate::eventlog::common::Coded for $name {
            fn number(self) -> u32 {
                match self {
                    $(Self::$var => $code,)*
                    Self::Other(n) => n,
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$var => f.write_str($label),)*
                    Self::Other(n) => write!(f, "type {n}"),
                }
            }
        }
    };
}
pub(crate) use coded_enum;

/// A required numeric field.
pub(crate) fn req_u32(raw: &RawEvent, name: &'static str) -> Result<u32, FromRawError> {
    raw.u32(name).ok_or(FromRawError::MissingField(name))
}

/// A number the log wrote as a number in newer event versions and as a boolean in older ones.
pub(crate) fn number_or_bool(raw: &RawEvent, name: &str) -> Option<u32> {
    raw.u32(name).or_else(|| raw.bool(name).map(u32::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    coded_enum!(Sample {
        One = 1 => "one",
    });

    #[test]
    fn unproven_codes_stay_numbers() {
        assert_eq!(Sample::from_code(1), Sample::One);
        assert_eq!(Sample::from_code(9), Sample::Other(9));
        assert_eq!(Sample::from_code(9).to_string(), "type 9");
        assert_eq!(Sample::One.number(), 1);
    }

    #[test]
    fn evidence_skips_absent_values_and_labels_codes() {
        let e = Evidence::new(SourceId::EventLogSystem)
            .opt("a", Some(5))
            .opt::<u8>("b", None)
            .code("c", Sample::from_code(7));
        assert_eq!(e.fields["a"], "5");
        assert!(!e.fields.contains_key("b"));
        assert_eq!(e.fields["c"], "type 7");
        assert_eq!(e.fields["c_code"], "7");
    }

    #[test]
    fn wrong_event_is_reported_with_what_was_found() {
        let raw = RawEvent {
            provider: Some("X".into()),
            event_id: Some(3),
            ..RawEvent::default()
        };
        let err = Meta::expect(&raw, "Y 4", &["Y"], &[4]).unwrap_err();
        assert!(err.to_string().contains("not a Y 4 event"));
        assert!(Meta::expect(&raw, "X 3", &["X"], &[3]).is_ok());
    }
}
