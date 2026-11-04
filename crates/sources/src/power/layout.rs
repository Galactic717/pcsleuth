//! Byte layouts returned by `NtPowerInformation` levels that have no public header, and the pure
//! functions that read them. No OS calls: the tests run over hand-built buffers on any platform.
//!
//! Sources, both read on 2026-11-03:
//!
//! - `GetPowerRequestList` (45): `diversenok/Powercfg`, `Sources/EnumerateRequests.c` (how the
//!   list is walked and displayed) and `diversenok/phnt` `ntpoapi.h` at commit 7c1adb8 (the structs
//!   `POWER_REQUEST_LIST`, `POWER_REQUEST`, `DIAGNOSTIC_BUFFER`, `COUNTED_REASON_CONTEXT_RELATIVE`).
//! - `WakeTimerList` (50): `WAKE_TIMER_INFO` in `winsiderss/systeminformer` `phnt/include/ntpoapi.h`.
//!   `diversenok/Powercfg` does not cover wake timers.
//!
//! All offsets below are for 64-bit Windows, where `ULONG_PTR` and `SIZE_T` are 8 bytes. Every
//! offset stored in a buffer is relative to the start of the structure that holds it, so a bad
//! offset is checked against the buffer and reported as [`LayoutError`], never followed blindly.
//!
//! Nothing here was checked against a live elevated read: both levels return access denied without
//! admin. The `elevated_*` ignored tests in `power::os` are the check, and the shape of the
//! wake timer entry in particular (the empty-list answer and the due time format) is an assumption
//! until one runs.

use std::fmt;

use jiff::Timestamp;

/// The six request kinds on Windows 10 1607 and later (`POWER_REQUEST_SUPPORTED_TYPES_V4`).
pub const REQUEST_TYPES_V4: usize = 6;

/// What a power request asks Windows to do. Names follow `powercfg /requests` sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestType {
    /// `DISPLAY`: keep the display on.
    Display,
    /// `SYSTEM`: keep the system awake.
    System,
    /// `AWAYMODE`: keep awake for background work while appearing to sleep.
    AwayMode,
    /// `EXECUTION`: override process lifetime management.
    Execution,
    /// `PERFBOOST`.
    PerfBoost,
    /// `ACTIVELOCKSCREEN`.
    ActiveLockScreen,
}

impl RequestType {
    const ALL: [RequestType; REQUEST_TYPES_V4] = [
        RequestType::Display,
        RequestType::System,
        RequestType::AwayMode,
        RequestType::Execution,
        RequestType::PerfBoost,
        RequestType::ActiveLockScreen,
    ];
}

/// Who made a power request or set a wake timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    /// A user-mode process. `image` is the native NT path, such as
    /// `\Device\HarddiskVolume3\Program Files\App\app.exe`.
    Process { pid: u32, image: Option<String> },
    /// A process acting for a shared service (`svchost.exe`). `tag` identifies the service inside
    /// the process; it is not resolved to a name here.
    Service {
        pid: u32,
        image: Option<String>,
        tag: u32,
    },
    /// A kernel driver, with the device description and path it gave.
    Driver {
        description: Option<String>,
        device_path: Option<String>,
    },
    /// A requester type this code does not know. The raw value is kept.
    Unknown(u32),
}

/// The reason text the requester supplied. The text is the requester's own, opaque and possibly
/// localized: show it, never branch on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Text(String),
    /// The reason is a string resource in a DLL, which this code does not load.
    Resource {
        file: String,
        id: u16,
    },
}

/// One outstanding power request that is holding a mode on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerRequest {
    pub requester: Requester,
    /// The modes this request holds, each with how many times it was set. Never empty.
    pub active: Vec<(RequestType, u32)>,
    pub reason: Option<Reason>,
}

/// One pending wake timer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeTimer {
    /// When it fires, read as a `FILETIME`. `None` when the value is not a plausible absolute time.
    pub due: Option<Timestamp>,
    /// The due time exactly as Windows returned it.
    pub due_raw: i64,
    /// Repeat period in milliseconds, 0 for a one-shot timer.
    pub period_ms: u32,
    pub owner: Requester,
    pub reason: Option<Reason>,
}

/// A buffer that does not fit the layout this code expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// A read went past the end of the buffer, or a string was not terminated.
    Truncated { what: &'static str, offset: u64 },
    /// A count or link that cannot be right.
    Inconsistent(&'static str),
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutError::Truncated { what, offset } => {
                write!(f, "unexpected end of buffer reading {what} at {offset}")
            }
            LayoutError::Inconsistent(what) => write!(f, "inconsistent layout: {what}"),
        }
    }
}

impl std::error::Error for LayoutError {}

type Result<T> = std::result::Result<T, LayoutError>;

/// `base + rel`, refusing to wrap around on a hostile offset.
fn at(base: u64, rel: u64) -> Result<u64> {
    base.checked_add(rel)
        .ok_or(LayoutError::Inconsistent("offset overflows"))
}

/// Bounds-checked little-endian reads.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn slice(&self, what: &'static str, offset: u64, len: usize) -> Result<&[u8]> {
        let err = LayoutError::Truncated { what, offset };
        let start = usize::try_from(offset).map_err(|_| err.clone())?;
        let end = start.checked_add(len).ok_or(err.clone())?;
        self.0.get(start..end).ok_or(err)
    }

    fn u16(&self, what: &'static str, offset: u64) -> Result<u16> {
        let b = self.slice(what, offset, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&self, what: &'static str, offset: u64) -> Result<u32> {
        let b = self.slice(what, offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&self, what: &'static str, offset: u64) -> Result<u64> {
        let b = self.slice(what, offset, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A NUL-terminated UTF-16 string at `base + rel`. `rel == 0` means "no string".
    fn wstr(&self, what: &'static str, base: u64, rel: u64) -> Result<Option<String>> {
        if rel == 0 {
            return Ok(None);
        }
        let start = at(base, rel)?;
        let start_idx = usize::try_from(start).map_err(|_| LayoutError::Truncated {
            what,
            offset: start,
        })?;
        let rest = self.0.get(start_idx..).ok_or(LayoutError::Truncated {
            what,
            offset: start,
        })?;
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|u| *u != 0)
            .collect();
        // Terminated means a zero unit follows the text inside the buffer.
        if (units.len() + 1) * 2 > rest.len() {
            return Err(LayoutError::Truncated {
                what,
                offset: start,
            });
        }
        Ok(Some(String::from_utf16_lossy(&units)))
    }
}

/// `DIAGNOSTIC_BUFFER`: size 8, caller type 4 (+4 padding), a union of two 16-byte shapes, then the
/// reason offset. 40 bytes.
const DIAGNOSTIC_LEN: u64 = 40;

const POWER_REQUEST_CONTEXT_SIMPLE_STRING: u32 = 0x1;
const POWER_REQUEST_CONTEXT_DETAILED_STRING: u32 = 0x2;

/// Read a `DIAGNOSTIC_BUFFER` at `base`. Returns the requester and the reason, if any.
fn diagnostic(b: &Bytes<'_>, base: u64) -> Result<(Requester, Option<Reason>)> {
    b.slice("diagnostic buffer", base, DIAGNOSTIC_LEN as usize)?;
    let caller_type = b.u32("caller type", at(base, 8)?)?;
    let first = b.u64("diagnostic offset 1", at(base, 16)?)?;
    let requester = match caller_type {
        0 => {
            let second = b.u64("diagnostic offset 2", at(base, 24)?)?;
            Requester::Driver {
                description: b.wstr("device description", base, first)?,
                device_path: b.wstr("device path", base, second)?,
            }
        }
        1 | 2 => {
            let pid = b.u32("process id", at(base, 24)?)?;
            let image = b.wstr("process image", base, first)?;
            if caller_type == 1 {
                Requester::Process { pid, image }
            } else {
                Requester::Service {
                    pid,
                    image,
                    tag: b.u32("service tag", at(base, 28)?)?,
                }
            }
        }
        other => Requester::Unknown(other),
    };
    let reason_rel = b.u64("reason offset", at(base, 32)?)?;
    let reason = if reason_rel == 0 {
        None
    } else {
        let reason_at = at(base, reason_rel)?;
        let flags = b.u32("reason flags", reason_at)?;
        let first = b.u64("reason offset 1", at(reason_at, 8)?)?;
        if flags & POWER_REQUEST_CONTEXT_SIMPLE_STRING != 0 {
            b.wstr("reason text", reason_at, first)?.map(Reason::Text)
        } else if flags & POWER_REQUEST_CONTEXT_DETAILED_STRING != 0 {
            let id = b.u16("reason resource id", at(reason_at, 16)?)?;
            b.wstr("reason resource file", reason_at, first)?
                .map(|file| Reason::Resource { file, id })
        } else {
            None
        }
    };
    Ok((requester, reason))
}

/// Parse the buffer `GetPowerRequestList` filled. `type_count` is the number of request kinds the
/// running Windows supports, [`REQUEST_TYPES_V4`] on Windows 10 1607 and later.
///
/// Requests that hold no mode are left out; `powercfg /requests` does not list them either.
pub fn parse_power_requests(buf: &[u8], type_count: usize) -> Result<Vec<PowerRequest>> {
    if type_count == 0 || type_count > 16 {
        return Err(LayoutError::Inconsistent("request type count"));
    }
    let b = Bytes(buf);
    let count = b.u64("request count", 0)?;
    // Every request needs its own 8-byte offset slot, so the count cannot exceed what fits.
    if count > (buf.len() as u64) / 8 {
        return Err(LayoutError::Inconsistent("request count exceeds buffer"));
    }
    // POWER_REQUEST: mask (4), counts (4 each), then the 8-aligned diagnostic buffer.
    let diagnostic_rel = (4 + 4 * type_count as u64).next_multiple_of(8);
    let mut requests = Vec::new();
    for i in 0..count {
        let base = b.u64("request offset", 8 + 8 * i)?;
        let mut active = Vec::new();
        for (k, kind) in RequestType::ALL.iter().enumerate().take(type_count) {
            let n = b.u32("request count slot", at(base, 4 + 4 * k as u64)?)?;
            if n > 0 {
                active.push((*kind, n));
            }
        }
        if active.is_empty() {
            continue;
        }
        let (requester, reason) = diagnostic(&b, at(base, diagnostic_rel)?)?;
        requests.push(PowerRequest {
            requester,
            active,
            reason,
        });
    }
    Ok(requests)
}

/// `WAKE_TIMER_INFO`: next offset 8, due time 8, period 4 (+4 padding), then a diagnostic buffer.
const WAKE_TIMER_LEN: u64 = 24 + DIAGNOSTIC_LEN;

/// Parse the buffer `WakeTimerList` filled: entries linked by `OffsetToNext`, 0 on the last.
///
/// An all-zero first entry (no next link, no due time, empty diagnostic buffer) is how this code
/// reads "no timers". That reading is unconfirmed; see the module note.
pub fn parse_wake_timers(buf: &[u8]) -> Result<Vec<WakeTimer>> {
    let b = Bytes(buf);
    let mut timers = Vec::new();
    let mut entry = 0u64;
    // Each entry is at least WAKE_TIMER_LEN bytes, which bounds the walk.
    for _ in 0..=(buf.len() as u64 / WAKE_TIMER_LEN) {
        if buf.is_empty() {
            break;
        }
        let next = b.u64("wake timer next", entry)?;
        let due_raw = b.u64("wake timer due", at(entry, 8)?)? as i64;
        let period_ms = b.u32("wake timer period", at(entry, 16)?)?;
        let diag = at(entry, 24)?;
        let diag_size = b.u64("wake timer diagnostic size", diag)?;
        if next == 0 && due_raw == 0 && diag_size == 0 {
            break;
        }
        let (owner, reason) = diagnostic(&b, diag)?;
        timers.push(WakeTimer {
            due: filetime_to_timestamp(due_raw),
            due_raw,
            period_ms,
            owner,
            reason,
        });
        if next == 0 {
            return Ok(timers);
        }
        if next < WAKE_TIMER_LEN {
            return Err(LayoutError::Inconsistent(
                "wake timer link does not advance",
            ));
        }
        entry = at(entry, next)?;
    }
    if timers.is_empty() {
        return Ok(timers);
    }
    Err(LayoutError::Inconsistent("wake timer list does not end"))
}

/// A `FILETIME` (100 ns ticks since 1601-01-01 UTC) as a timestamp. Zero and negative values are
/// not absolute times and give `None`.
pub fn filetime_to_timestamp(ticks: i64) -> Option<Timestamp> {
    const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    if ticks <= 0 {
        return None;
    }
    let micros = (ticks - UNIX_EPOCH_TICKS) / 10;
    Timestamp::from_microsecond(micros).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds buffers with the layout the module documents.
    #[derive(Default)]
    struct Buf(Vec<u8>);

    impl Buf {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn u16(&mut self, v: u16) {
            self.0.extend(v.to_le_bytes());
        }
        fn u32(&mut self, v: u32) {
            self.0.extend(v.to_le_bytes());
        }
        fn u64(&mut self, v: u64) {
            self.0.extend(v.to_le_bytes());
        }
        fn align8(&mut self) {
            while !self.0.len().is_multiple_of(8) {
                self.0.push(0);
            }
        }
        fn wstr(&mut self, s: &str) -> u64 {
            let at = self.len();
            for u in s.encode_utf16() {
                self.u16(u);
            }
            self.u16(0);
            at
        }
        fn patch_u64(&mut self, at: u64, v: u64) {
            self.0[at as usize..at as usize + 8].copy_from_slice(&v.to_le_bytes());
        }
    }

    enum Who<'a> {
        Process(u32, &'a str),
        Service(u32, &'a str, u32),
        Driver(Option<&'a str>, Option<&'a str>),
        Other(u32),
    }

    enum Why<'a> {
        Nothing,
        Text(&'a str),
        Resource(&'a str, u16),
    }

    /// Append a `DIAGNOSTIC_BUFFER` plus its strings; return where it starts.
    fn diagnostic_at(buf: &mut Buf, who: &Who<'_>, why: &Why<'_>) -> u64 {
        buf.align8();
        let base = buf.len();
        buf.u64(0); // Size, patched below
        let (caller, off1, off2_or_pid_tag): (u32, u64, (u64, u32, u32));
        // Header first, strings after it; offsets are patched once the strings have a position.
        let header_len = DIAGNOSTIC_LEN;
        let strings_start = base + header_len;
        let mut strings = Buf::default();
        let placed = |strings: &mut Buf, s: &str| strings_start + strings.wstr(s) - base;
        match who {
            Who::Process(pid, image) => {
                caller = 1;
                off1 = placed(&mut strings, image);
                off2_or_pid_tag = (0, *pid, 0);
            }
            Who::Service(pid, image, tag) => {
                caller = 2;
                off1 = placed(&mut strings, image);
                off2_or_pid_tag = (0, *pid, *tag);
            }
            Who::Driver(desc, path) => {
                caller = 0;
                off1 = desc.map_or(0, |d| placed(&mut strings, d));
                let off2 = path.map_or(0, |p| placed(&mut strings, p));
                off2_or_pid_tag = (off2, 0, 0);
            }
            Who::Other(n) => {
                caller = *n;
                off1 = 0;
                off2_or_pid_tag = (0, 0, 0);
            }
        }
        buf.u32(caller);
        buf.u32(0);
        buf.u64(off1);
        if matches!(who, Who::Driver(..)) {
            buf.u64(off2_or_pid_tag.0);
        } else {
            buf.u32(off2_or_pid_tag.1);
            buf.u32(off2_or_pid_tag.2);
        }
        let reason_rel_at = buf.len();
        buf.u64(0); // ReasonOffset, patched below
        assert_eq!(buf.len() - base, header_len);
        buf.0.extend(strings.0);
        buf.align8();
        match why {
            Why::Nothing => {}
            Why::Text(text) => {
                let reason = buf.len();
                buf.u32(POWER_REQUEST_CONTEXT_SIMPLE_STRING);
                buf.u32(0);
                let string_rel_at = buf.len();
                buf.u64(0);
                let at = buf.wstr(text);
                buf.patch_u64(string_rel_at, at - reason);
                buf.patch_u64(reason_rel_at, reason - base);
            }
            Why::Resource(file, id) => {
                let reason = buf.len();
                buf.u32(POWER_REQUEST_CONTEXT_DETAILED_STRING);
                buf.u32(0);
                let file_rel_at = buf.len();
                buf.u64(0);
                buf.u16(*id);
                buf.u16(0);
                buf.u32(0); // StringCount
                buf.u64(0); // SubstitutionStringsOffset
                let at = buf.wstr(file);
                buf.patch_u64(file_rel_at, at - reason);
                buf.patch_u64(reason_rel_at, reason - base);
            }
        }
        buf.patch_u64(base, buf.len() - base);
        base
    }

    /// A `POWER_REQUEST` (V4): mask, six counts, padding, diagnostic buffer.
    fn request_at(buf: &mut Buf, counts: [u32; 6], who: &Who<'_>, why: &Why<'_>) -> u64 {
        buf.align8();
        let start = buf.len();
        buf.u32(0x3f);
        for c in counts {
            buf.u32(c);
        }
        buf.u32(0); // padding to the 8-aligned diagnostic buffer
        assert_eq!(buf.len() - start, 32);
        diagnostic_at(buf, who, why);
        start
    }

    fn request_list(requests: &[([u32; 6], Who<'_>, Why<'_>)]) -> Vec<u8> {
        let mut buf = Buf::default();
        buf.u64(requests.len() as u64);
        let slots = buf.len();
        for _ in requests {
            buf.u64(0);
        }
        for (i, (counts, who, why)) in requests.iter().enumerate() {
            let at = request_at(&mut buf, *counts, who, why);
            buf.patch_u64(slots + 8 * i as u64, at);
        }
        buf.0
    }

    #[test]
    fn process_request_with_a_reason_reads_like_powercfg_requests() {
        // The shape `powercfg /requests` shows on this laptop under EXECUTION.
        let image = r"\Device\HarddiskVolume3\Users\someone\.local\bin\example.exe";
        let buf = request_list(&[(
            [0, 0, 0, 1, 0, 0],
            Who::Process(4242, image),
            Why::Text("Example app is working"),
        )]);
        let requests = parse_power_requests(&buf, REQUEST_TYPES_V4).unwrap();
        assert_eq!(
            requests,
            vec![PowerRequest {
                requester: Requester::Process {
                    pid: 4242,
                    image: Some(image.into())
                },
                active: vec![(RequestType::Execution, 1)],
                reason: Some(Reason::Text("Example app is working".into())),
            }]
        );
    }

    #[test]
    fn service_driver_and_unknown_requesters() {
        let buf = request_list(&[
            (
                [1, 2, 0, 0, 0, 0],
                Who::Service(
                    900,
                    r"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
                    7,
                ),
                Why::Nothing,
            ),
            (
                [0, 1, 0, 0, 0, 3],
                Who::Driver(Some("Realtek Audio"), Some(r"HDAUDIO\FUNC_01")),
                Why::Resource(r"C:\Windows\System32\drv.dll", 211),
            ),
            ([0, 0, 1, 0, 0, 0], Who::Driver(None, None), Why::Nothing),
            ([0, 0, 0, 0, 1, 0], Who::Other(9), Why::Nothing),
        ]);
        let requests = parse_power_requests(&buf, REQUEST_TYPES_V4).unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests[0].requester,
            Requester::Service {
                pid: 900,
                image: Some(r"\Device\HarddiskVolume3\Windows\System32\svchost.exe".into()),
                tag: 7
            }
        );
        assert_eq!(
            requests[0].active,
            vec![(RequestType::Display, 1), (RequestType::System, 2)]
        );
        assert_eq!(requests[0].reason, None);
        assert_eq!(
            requests[1].requester,
            Requester::Driver {
                description: Some("Realtek Audio".into()),
                device_path: Some(r"HDAUDIO\FUNC_01".into())
            }
        );
        assert_eq!(
            requests[1].active,
            vec![(RequestType::System, 1), (RequestType::ActiveLockScreen, 3)]
        );
        assert_eq!(
            requests[1].reason,
            Some(Reason::Resource {
                file: r"C:\Windows\System32\drv.dll".into(),
                id: 211
            })
        );
        assert_eq!(
            requests[2].requester,
            Requester::Driver {
                description: None,
                device_path: None
            }
        );
        assert_eq!(requests[3].requester, Requester::Unknown(9));
        assert_eq!(requests[3].active, vec![(RequestType::PerfBoost, 1)]);
    }

    #[test]
    fn requests_that_hold_no_mode_are_left_out() {
        let buf = request_list(&[
            ([0; 6], Who::Process(1, "a"), Why::Nothing),
            ([1, 0, 0, 0, 0, 0], Who::Process(2, "b"), Why::Nothing),
        ]);
        let requests = parse_power_requests(&buf, REQUEST_TYPES_V4).unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].requester,
            Requester::Process {
                pid: 2,
                image: Some("b".into())
            }
        );
    }

    #[test]
    fn empty_list_is_ok_and_short_input_is_an_error() {
        let mut buf = Buf::default();
        buf.u64(0);
        assert_eq!(parse_power_requests(&buf.0, REQUEST_TYPES_V4), Ok(vec![]));
        assert!(matches!(
            parse_power_requests(&[], REQUEST_TYPES_V4),
            Err(LayoutError::Truncated { .. })
        ));
        assert!(matches!(
            parse_power_requests(&[1, 0, 0], REQUEST_TYPES_V4),
            Err(LayoutError::Truncated { .. })
        ));
        assert!(parse_power_requests(&buf.0, 0).is_err());
    }

    #[test]
    fn hostile_counts_offsets_and_strings_are_errors_not_panics() {
        let good = request_list(&[(
            [1, 0, 0, 0, 0, 0],
            Who::Process(1, "image"),
            Why::Text("why"),
        )]);
        // A count far larger than the buffer.
        let mut huge = good.clone();
        huge[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_power_requests(&huge, REQUEST_TYPES_V4).is_err());
        // A request offset past the end, and one that overflows.
        for bad in [u64::MAX, good.len() as u64 + 100, u64::MAX - 3] {
            let mut b = good.clone();
            b[8..16].copy_from_slice(&bad.to_le_bytes());
            assert!(parse_power_requests(&b, REQUEST_TYPES_V4).is_err(), "{bad}");
        }
        // Every truncation of a good buffer is an error or a shorter valid parse, never a panic.
        for cut in 0..good.len() {
            let _ = parse_power_requests(&good[..cut], REQUEST_TYPES_V4);
        }
        // A string with no terminator inside the buffer.
        let mut cut = good.clone();
        cut.truncate(good.len() - 2);
        assert!(matches!(
            parse_power_requests(&cut, REQUEST_TYPES_V4),
            Err(LayoutError::Truncated { .. })
        ));
        // Random bytes.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..200 {
            let noise: Vec<u8> = (0..256)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            let _ = parse_power_requests(&noise, REQUEST_TYPES_V4);
            let _ = parse_wake_timers(&noise);
        }
    }

    /// FILETIME for 2026-11-03T08:00:00Z.
    const DUE: i64 = (1_793_692_800 * 10_000_000) + 116_444_736_000_000_000;

    fn timer_list(entries: &[(i64, u32, Who<'_>, Why<'_>)]) -> Vec<u8> {
        let mut buf = Buf::default();
        for (i, (due, period, who, why)) in entries.iter().enumerate() {
            buf.align8();
            let start = buf.len();
            let next_at = buf.len();
            buf.u64(0);
            buf.u64(*due as u64);
            buf.u32(*period);
            buf.u32(0);
            diagnostic_at(&mut buf, who, why);
            if i + 1 < entries.len() {
                buf.align8();
                let next = buf.len() - start;
                buf.patch_u64(next_at, next);
            }
        }
        buf.0
    }

    #[test]
    fn wake_timers_are_walked_through_their_links() {
        let buf = timer_list(&[
            (
                DUE,
                0,
                Who::Service(
                    1200,
                    r"\Device\HarddiskVolume3\Windows\System32\svchost.exe",
                    3,
                ),
                Why::Text(
                    "Windows will execute a scheduled task that requested waking the computer.",
                ),
            ),
            (
                DUE + 600_000_000,
                3_600_000,
                Who::Process(77, "x.exe"),
                Why::Nothing,
            ),
        ]);
        let timers = parse_wake_timers(&buf).unwrap();
        assert_eq!(timers.len(), 2);
        assert_eq!(timers[0].due_raw, DUE);
        assert_eq!(
            timers[0].due,
            Some("2026-11-03T08:00:00Z".parse::<Timestamp>().unwrap())
        );
        assert_eq!(timers[0].period_ms, 0);
        assert!(matches!(
            timers[0].owner,
            Requester::Service {
                pid: 1200,
                tag: 3,
                ..
            }
        ));
        assert!(matches!(timers[0].reason, Some(Reason::Text(_))));
        assert_eq!(timers[1].period_ms, 3_600_000);
        assert_eq!(
            timers[1].due,
            Some("2026-11-03T08:01:00Z".parse::<Timestamp>().unwrap())
        );
        assert_eq!(
            timers[1].owner,
            Requester::Process {
                pid: 77,
                image: Some("x.exe".into())
            }
        );
    }

    #[test]
    fn no_wake_timers_reads_as_empty() {
        assert_eq!(parse_wake_timers(&[]), Ok(vec![]));
        assert_eq!(parse_wake_timers(&[0u8; 128]), Ok(vec![]));
    }

    #[test]
    fn broken_wake_timer_links_are_errors() {
        let mut buf = timer_list(&[
            (DUE, 0, Who::Process(1, "a"), Why::Nothing),
            (DUE, 0, Who::Process(2, "b"), Why::Nothing),
        ]);
        // A link that points back at the entry itself would loop forever.
        buf[..8].copy_from_slice(&8u64.to_le_bytes());
        assert!(matches!(
            parse_wake_timers(&buf),
            Err(LayoutError::Inconsistent(_))
        ));
        // A link past the end of the buffer.
        let beyond = buf.len() as u64 + 64;
        buf[..8].copy_from_slice(&beyond.to_le_bytes());
        assert!(matches!(
            parse_wake_timers(&buf),
            Err(LayoutError::Truncated { .. })
        ));
    }

    #[test]
    fn filetime_conversion() {
        assert_eq!(filetime_to_timestamp(0), None);
        assert_eq!(filetime_to_timestamp(-5), None);
        assert_eq!(
            filetime_to_timestamp(116_444_736_000_000_000),
            Some(Timestamp::UNIX_EPOCH)
        );
        assert_eq!(
            filetime_to_timestamp(DUE),
            Some("2026-11-03T08:00:00Z".parse().unwrap())
        );
        assert_eq!(filetime_to_timestamp(i64::MAX), None);
    }
}
