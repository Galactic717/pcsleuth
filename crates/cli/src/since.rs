//! Parsing `--since <when>`.

use jiff::civil::Date;
use jiff::tz::TimeZone;
use jiff::{SignedDuration, Timestamp};

/// For clap: relative to now, in the system time zone.
pub fn parse(input: &str) -> Result<Timestamp, String> {
    parse_at(input, Timestamp::now(), &TimeZone::system())
}

/// A span back from `now` (`90m`, `24h`, `7d`, `2w`), an RFC 3339 time, or a date meaning
/// midnight at the start of that day in `zone`.
fn parse_at(input: &str, now: Timestamp, zone: &TimeZone) -> Result<Timestamp, String> {
    let input = input.trim();
    if let Some(span) = span(input) {
        return now
            .checked_sub(span)
            .map_err(|error| format!("{input:?} reaches too far back: {error}"));
    }
    if let Ok(time) = input.parse::<Timestamp>() {
        return Ok(time);
    }
    if let Ok(date) = input.parse::<Date>() {
        return date
            .to_zoned(zone.clone())
            .map(|start| start.timestamp())
            .map_err(|error| format!("{input:?} is not a valid date here: {error}"));
    }
    Err(format!(
        "expected a span such as 24h or 7d, a date such as 2026-11-01, or an RFC 3339 time, got {input:?}"
    ))
}

fn span(input: &str) -> Option<SignedDuration> {
    const UNITS: [(&str, i64); 5] = [
        ("s", 1),
        ("m", 60),
        ("h", 3600),
        ("d", 86_400),
        ("w", 604_800),
    ];
    let (count, seconds) = UNITS
        .iter()
        .find_map(|(unit, seconds)| input.strip_suffix(unit).map(|count| (count, seconds)))?;
    let count: u32 = count.trim().parse().ok()?;
    Some(SignedDuration::from_secs(i64::from(count) * seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn parse_in_kyiv_winter(input: &str) -> Result<Timestamp, String> {
        let zone = TimeZone::fixed(jiff::tz::offset(2));
        parse_at(input, at("2026-11-03T12:00:00Z"), &zone)
    }

    #[test]
    fn spans_count_back_from_now() {
        assert_eq!(parse_in_kyiv_winter("90m"), Ok(at("2026-11-03T10:30:00Z")));
        assert_eq!(parse_in_kyiv_winter("24h"), Ok(at("2026-11-02T12:00:00Z")));
        assert_eq!(parse_in_kyiv_winter(" 7d "), Ok(at("2026-10-27T12:00:00Z")));
        assert_eq!(parse_in_kyiv_winter("2w"), Ok(at("2026-10-20T12:00:00Z")));
    }

    #[test]
    fn rfc3339_and_dates() {
        assert_eq!(
            parse_in_kyiv_winter("2026-10-28T14:30:33Z"),
            Ok(at("2026-10-28T14:30:33Z"))
        );
        assert_eq!(
            parse_in_kyiv_winter("2026-10-28T16:30:33+02:00"),
            Ok(at("2026-10-28T14:30:33Z"))
        );
        // Midnight local time (+02:00) is 22:00 UTC the evening before.
        assert_eq!(
            parse_in_kyiv_winter("2026-11-01"),
            Ok(at("2026-10-31T22:00:00Z"))
        );
    }

    #[test]
    fn nonsense_is_an_error_not_a_panic() {
        for input in [
            "",
            "h",
            "-5h",
            "5 hours",
            "yesterday",
            "2026-13-40",
            "\u{43f}\u{44f}\u{442}\u{44c}\u{433}",
        ] {
            assert!(parse_in_kyiv_winter(input).is_err(), "{input:?}");
        }
    }
}
