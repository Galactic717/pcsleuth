//! Pure decoding of what ESE hands back: column values, OLE dates and the id-map blobs.

use jiff::Timestamp;

/// ESE column types (`JET_coltyp*`), repeated here so this file builds on every platform.
pub(crate) mod coltyp {
    pub const BIT: u32 = 1;
    pub const UNSIGNED_BYTE: u32 = 2;
    pub const SHORT: u32 = 3;
    pub const LONG: u32 = 4;
    pub const CURRENCY: u32 = 5;
    pub const IEEE_SINGLE: u32 = 6;
    pub const IEEE_DOUBLE: u32 = 7;
    pub const DATE_TIME: u32 = 8;
    #[cfg(test)]
    pub const BINARY: u32 = 9;
    #[cfg(test)]
    pub const LONG_BINARY: u32 = 11;
    pub const UNSIGNED_LONG: u32 = 14;
    pub const LONG_LONG: u32 = 15;
    pub const UNSIGNED_SHORT: u32 = 17;
    pub const UNSIGNED_LONG_LONG: u32 = 18;
}

/// One column value, widened so the caller does not care whether a Windows version stores a
/// counter as 32 or 64 bits.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Int(i64),
    Uint(u64),
    Float(f64),
    /// An OLE Automation date: days since 1899-12-30, UTC.
    Date(f64),
    Bytes(Vec<u8>),
}

impl Value {
    /// Interpret the raw bytes ESE returned for a column of type `coltyp`. A length that does not
    /// fit the type falls back to [`Value::Bytes`] instead of guessing.
    pub(crate) fn from_raw(coltyp: u32, raw: &[u8]) -> Value {
        fn fixed<const N: usize>(raw: &[u8]) -> Option<[u8; N]> {
            raw.try_into().ok()
        }
        let decoded = match coltyp {
            coltyp::BIT | coltyp::UNSIGNED_BYTE => {
                fixed::<1>(raw).map(|b| Value::Uint(b[0].into()))
            }
            coltyp::SHORT => fixed::<2>(raw).map(|b| Value::Int(i16::from_le_bytes(b).into())),
            coltyp::UNSIGNED_SHORT => {
                fixed::<2>(raw).map(|b| Value::Uint(u16::from_le_bytes(b).into()))
            }
            coltyp::LONG => fixed::<4>(raw).map(|b| Value::Int(i32::from_le_bytes(b).into())),
            coltyp::UNSIGNED_LONG => {
                fixed::<4>(raw).map(|b| Value::Uint(u32::from_le_bytes(b).into()))
            }
            coltyp::CURRENCY | coltyp::LONG_LONG => {
                fixed::<8>(raw).map(|b| Value::Int(i64::from_le_bytes(b)))
            }
            coltyp::UNSIGNED_LONG_LONG => {
                fixed::<8>(raw).map(|b| Value::Uint(u64::from_le_bytes(b)))
            }
            coltyp::IEEE_SINGLE => {
                fixed::<4>(raw).map(|b| Value::Float(f32::from_le_bytes(b).into()))
            }
            coltyp::IEEE_DOUBLE => fixed::<8>(raw).map(|b| Value::Float(f64::from_le_bytes(b))),
            coltyp::DATE_TIME => fixed::<8>(raw).map(|b| Value::Date(f64::from_le_bytes(b))),
            _ => None,
        };
        decoded.unwrap_or_else(|| Value::Bytes(raw.to_vec()))
    }

    /// A non-negative whole number, or `None` for null, negative, fractional or non-numeric values.
    pub(crate) fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::Uint(v) => Some(v),
            Value::Int(v) => u64::try_from(v).ok(),
            Value::Float(v) if v >= 0.0 && v.fract() == 0.0 && v < 1.8e19 => Some(v as u64),
            _ => None,
        }
    }

    /// A whole number that fits `i64`, or `None` for null, fractional or non-numeric values.
    pub(crate) fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Int(v) => Some(v),
            Value::Uint(v) => i64::try_from(v).ok(),
            _ => None,
        }
    }

    /// The raw column bytes for this value, for the tests that write a database.
    #[cfg(test)]
    pub(crate) fn to_raw(&self, coltyp: u32) -> Vec<u8> {
        let int = |value: &Value| value.as_i64().unwrap_or_default();
        match coltyp {
            coltyp::BIT | coltyp::UNSIGNED_BYTE => vec![int(self) as u8],
            coltyp::SHORT | coltyp::UNSIGNED_SHORT => (int(self) as u16).to_le_bytes().to_vec(),
            coltyp::LONG | coltyp::UNSIGNED_LONG => (int(self) as u32).to_le_bytes().to_vec(),
            coltyp::CURRENCY | coltyp::LONG_LONG | coltyp::UNSIGNED_LONG_LONG => {
                int(self).to_le_bytes().to_vec()
            }
            coltyp::IEEE_DOUBLE | coltyp::DATE_TIME => {
                self.as_f64().unwrap_or_default().to_le_bytes().to_vec()
            }
            _ => match self {
                Value::Bytes(bytes) => bytes.clone(),
                _ => Vec::new(),
            },
        }
    }

    /// Any number as a float, or `None` for null and byte values.
    #[cfg(test)]
    pub(crate) fn as_f64(&self) -> Option<f64> {
        match *self {
            Value::Uint(v) => Some(v as f64),
            Value::Int(v) => Some(v as f64),
            Value::Float(v) | Value::Date(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn as_timestamp(&self) -> Option<Timestamp> {
        match *self {
            Value::Date(v) => ole_to_timestamp(v),
            _ => None,
        }
    }
}

/// Days from 1899-12-30 (the OLE date epoch) to 1970-01-01.
const OLE_UNIX_EPOCH_DAYS: f64 = 25_569.0;

/// Convert an OLE Automation date to a timestamp, rounded to the nearest second so the float
/// noise in a stored date (an exact hour is rarely exact in binary) cannot push it into the
/// previous hour. `None` for non-finite or out-of-range values.
pub(crate) fn ole_to_timestamp(days: f64) -> Option<Timestamp> {
    if !days.is_finite() {
        return None;
    }
    let seconds = ((days - OLE_UNIX_EPOCH_DAYS) * 86_400.0).round();
    if !(-62_135_596_800.0..=253_402_300_799.0).contains(&seconds) {
        return None;
    }
    Timestamp::from_second(seconds as i64).ok()
}

/// What an `SruDbIdMapTable` blob names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdName {
    /// An application: an executable path, a service name or a package family name, as stored.
    Text(String),
    /// A user, as a SID string such as `S-1-5-18`.
    Sid(String),
    /// A blob that is neither text nor a SID, kept as hex so nothing is lost.
    Opaque(String),
}

impl IdName {
    /// The name or SID to show.
    pub fn as_str(&self) -> &str {
        match self {
            IdName::Text(s) | IdName::Sid(s) | IdName::Opaque(s) => s,
        }
    }
}

/// Decode an id-map blob. SRUM stores applications as NUL-terminated UTF-16 and users as binary
/// SIDs; the shape of the bytes decides, not the `IdType`, which differs between Windows builds.
pub fn decode_id_blob(blob: &[u8]) -> IdName {
    if let Some(sid) = sid_string(blob) {
        return IdName::Sid(sid);
    }
    if let Some(text) = utf16_text(blob) {
        return IdName::Text(text);
    }
    IdName::Opaque(blob.iter().map(|b| format!("{b:02x}")).collect())
}

/// `S-1-<authority>-<sub>...` for a well-formed binary SID that fills the blob exactly.
fn sid_string(blob: &[u8]) -> Option<String> {
    let (&revision, rest) = blob.split_first()?;
    let (&sub_count, rest) = rest.split_first()?;
    let sub_count = usize::from(sub_count);
    if revision != 1 || sub_count == 0 || sub_count > 15 || blob.len() != 8 + 4 * sub_count {
        return None;
    }
    let authority = rest[..6]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let mut sid = format!("S-1-{authority}");
    for index in 0..sub_count {
        let at = 8 + 4 * index;
        let sub = u32::from_le_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]);
        sid.push('-');
        sid.push_str(&sub.to_string());
    }
    Some(sid)
}

/// Little-endian UTF-16 code units of `bytes`; a trailing odd byte is ignored.
pub(crate) fn utf16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect()
}

/// UTF-16LE text up to the first NUL, with nothing but NULs after it. `None` when the bytes are
/// not valid, printable UTF-16.
fn utf16_text(blob: &[u8]) -> Option<String> {
    if blob.is_empty() || !blob.len().is_multiple_of(2) {
        return None;
    }
    let all = utf16_units(blob);
    let end = all.iter().position(|&u| u == 0).unwrap_or(all.len());
    let (units, tail) = all.split_at(end);
    if units.is_empty() || tail.iter().any(|&u| u != 0) {
        return None;
    }
    let text = String::from_utf16(units).ok()?;
    (!text.chars().any(char::is_control)).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16z(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn from_raw_widens_integers_by_column_type() {
        assert_eq!(
            Value::from_raw(coltyp::LONG, &(-5i32).to_le_bytes()),
            Value::Int(-5)
        );
        assert_eq!(
            Value::from_raw(coltyp::UNSIGNED_LONG, &7u32.to_le_bytes()),
            Value::Uint(7)
        );
        assert_eq!(
            Value::from_raw(coltyp::LONG_LONG, &i64::MAX.to_le_bytes()),
            Value::Int(i64::MAX)
        );
        assert_eq!(
            Value::from_raw(coltyp::UNSIGNED_BYTE, &[200]),
            Value::Uint(200)
        );
        assert_eq!(Value::from_raw(coltyp::BIT, &[1]), Value::Uint(1));
        assert_eq!(
            Value::from_raw(coltyp::IEEE_SINGLE, &1.5f32.to_le_bytes()),
            Value::Float(1.5)
        );
    }

    #[test]
    fn from_raw_keeps_bytes_when_the_length_does_not_fit() {
        assert_eq!(
            Value::from_raw(coltyp::LONG, &[1, 2, 3]),
            Value::Bytes(vec![1, 2, 3])
        );
        assert_eq!(
            Value::from_raw(coltyp::LONG_BINARY, &[9, 9]),
            Value::Bytes(vec![9, 9])
        );
    }

    #[test]
    fn as_u64_rejects_negative_fractional_and_non_numbers() {
        assert_eq!(Value::Int(-1).as_u64(), None);
        assert_eq!(Value::Int(9).as_u64(), Some(9));
        assert_eq!(Value::Float(3.0).as_u64(), Some(3));
        assert_eq!(Value::Float(3.5).as_u64(), None);
        assert_eq!(Value::Bytes(vec![1]).as_u64(), None);
        assert_eq!(Value::Null.as_u64(), None);
    }

    #[test]
    fn ole_date_converts_to_utc_and_survives_float_noise() {
        // 2026-11-03T12:00:00Z is 46329.5 days after 1899-12-30.
        let noon: Timestamp = "2026-11-03T12:00:00Z".parse().unwrap();
        assert_eq!(ole_to_timestamp(46_329.5), Some(noon));
        // The nearest representable value below an exact hour still lands on that hour.
        let noise = 46_329.5 - 1e-10;
        assert_eq!(ole_to_timestamp(noise), Some(noon));
        assert_eq!(ole_to_timestamp(f64::NAN), None);
        assert_eq!(ole_to_timestamp(f64::INFINITY), None);
        assert_eq!(ole_to_timestamp(-1.0e9), None);
    }

    #[test]
    fn id_blob_decodes_utf16_text_with_and_without_terminator() {
        assert_eq!(
            decode_id_blob(&utf16z(r"\Device\HarddiskVolume3\Tools\app.exe")),
            IdName::Text(r"\Device\HarddiskVolume3\Tools\app.exe".into())
        );
        let bare: Vec<u8> = "Pkg_1.0_x64__abc"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            decode_id_blob(&bare),
            IdName::Text("Pkg_1.0_x64__abc".into())
        );
        assert_eq!(decode_id_blob(&utf16z("Ünïcode")).as_str(), "Ünïcode");
    }

    #[test]
    fn id_blob_decodes_a_binary_sid() {
        // S-1-5-21-1-2-3-1001: revision 1, five sub-authorities, authority 5.
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, 1001] {
            sid.extend(sub.to_le_bytes());
        }
        assert_eq!(
            decode_id_blob(&sid),
            IdName::Sid("S-1-5-21-1-2-3-1001".into())
        );
        // S-1-5-18, the local system account.
        let system = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(decode_id_blob(&system), IdName::Sid("S-1-5-18".into()));
    }

    #[test]
    fn id_blob_that_is_neither_keeps_its_bytes_as_hex() {
        assert_eq!(
            decode_id_blob(&[0xff, 0xfe, 0x01]),
            IdName::Opaque("fffe01".into())
        );
        assert_eq!(decode_id_blob(&[]), IdName::Opaque(String::new()));
        // Valid UTF-16 length but control characters: not an app name.
        assert!(matches!(decode_id_blob(&[1, 0, 2, 0]), IdName::Opaque(_)));
        // A SID with the wrong length is not a SID.
        assert!(matches!(
            decode_id_blob(&[1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]),
            IdName::Opaque(_)
        ));
    }
}
