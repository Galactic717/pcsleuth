//! The ring file (ADR 0006): one preallocated file of a fixed size, a header, then fixed-size slots.
//!
//! ```text
//! block 0      header   magic, version, slot size, slot count, interval, created, next_seq, crc32
//! block 1..=N  slots    crc32, payload len, flags, seq, payload, zero padding
//! ```
//!
//! Every block is [`BLOCK`] bytes, so the file is exactly `(slot_count + 1) * BLOCK` bytes from
//! creation until it is deleted. Sample number `seq` (counting from 1) lives in slot
//! `(seq - 1) % slot_count`, so a write never moves the file end and an old sample is overwritten
//! only after a whole ring of newer ones.
//!
//! Encoding and decoding are pure functions over byte slices. A slot that fails its checksum, its
//! position check or its bounds-checked decode is [`Slot::Corrupt`]: it is skipped and counted,
//! never fatal, and nothing here can panic on bytes read from disk.
//!
//! The header's `next_seq` is only a hint, rewritten after every slot (48 bytes inside one sector).
//! The slots are the truth: a writer that opens an existing ring scans them for the highest valid
//! `seq`, so a crash between the slot write and the header write loses nothing.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use jiff::Timestamp;
use pcsleuth_core::{RecordedProcess, RecordedRequest, RecorderRow};

/// Size of the header block and of every slot, in bytes.
pub const BLOCK: usize = 1024;
/// Default ring file size: 16 MiB, which is 16 383 slots.
pub const DEFAULT_BYTES: u64 = 16 << 20;
/// Entries kept per process ranking. The writer drops extra ones and marks the slot truncated.
pub const MAX_PER_LIST: usize = 5;
/// Longest stored process name, owner, kind and reason, in bytes. Longer text is cut at a character
/// boundary and ends with `…`.
pub const NAME_MAX: usize = 32;
pub const OWNER_MAX: usize = 40;
pub const KIND_MAX: usize = 20;
pub const REASON_MAX: usize = 80;

const MAGIC: [u8; 8] = *b"PCSLRING";
/// The only format version this build reads and writes.
pub const VERSION: u32 = 1;
const HEADER_LEN: usize = 48;
const SLOT_HEAD: usize = 16;
const MAX_PAYLOAD: usize = BLOCK - SLOT_HEAD;
/// Fixed part of a payload: time, interval and the three counts.
const PAYLOAD_FIXED: usize = 16;
/// A string whose length byte is this means `None`.
const NO_STRING: u8 = 255;
const FLAG_REQUESTS_VISIBLE: u16 = 1;
const FLAG_TRUNCATED: u16 = 2;
const ELLIPSIS: &str = "…";

// Both process rankings at their longest must always fit, so only power requests can be dropped.
const _: () = assert!(PAYLOAD_FIXED + 2 * MAX_PER_LIST * (1 + NAME_MAX + 4 + 8) <= MAX_PAYLOAD);
// REASON_MAX is the longest string, and 255 is the "no string" marker.
const _: () = assert!(REASON_MAX < NO_STRING as usize);

/// One sample as stored: the contract row plus what the row type cannot say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub row: RecorderRow,
    /// False when power requests could not be read (no admin), so an empty
    /// `row.power_requests` means "not visible", never "none held".
    pub requests_visible: bool,
    /// Set by the writer when a name was cut or an entry did not fit. Ignored when writing.
    pub truncated: bool,
}

/// Why a ring file could not be used. Anything the OS or the file contents can cause lands here.
#[derive(Debug, thiserror::Error)]
pub enum RingError {
    #[error("not a pcsleuth ring file (wrong magic)")]
    BadMagic,
    #[error("ring file version {0} is not supported (this build reads version {VERSION})")]
    BadVersion(u32),
    #[error("ring header is damaged")]
    HeaderCorrupt,
    #[error("ring file is {found} bytes but its header says {expected}")]
    WrongLength { expected: u64, found: u64 },
    #[error("file is too short to be a ring file")]
    TooShort,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The ring's fixed geometry and the write position hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Interval the last writer was started with.
    pub interval_secs: u32,
    pub slot_count: u32,
    pub created_ms: i64,
    /// The sequence number the next write will use. A hint; see the module notes.
    pub next_seq: u64,
}

impl Header {
    /// File size implied by the geometry.
    pub fn file_bytes(&self) -> u64 {
        (u64::from(self.slot_count) + 1) * BLOCK as u64
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        b[16..20].copy_from_slice(&self.slot_count.to_le_bytes());
        b[20..24].copy_from_slice(&self.interval_secs.to_le_bytes());
        b[24..32].copy_from_slice(&self.created_ms.to_le_bytes());
        b[32..40].copy_from_slice(&self.next_seq.to_le_bytes());
        let crc = crc32(&b[..40]);
        b[40..44].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Decode and check a header. Magic and version are judged first, so a file that is not ours
    /// or is from another version is reported as such rather than as damage.
    pub fn decode(b: &[u8]) -> Result<Header, RingError> {
        if b.len() < HEADER_LEN {
            return Err(RingError::TooShort);
        }
        if b[0..8] != MAGIC {
            return Err(RingError::BadMagic);
        }
        let version = u32_at(b, 8);
        if version != VERSION {
            return Err(RingError::BadVersion(version));
        }
        if crc32(&b[..40]) != u32_at(b, 40) || u32_at(b, 12) != BLOCK as u32 {
            return Err(RingError::HeaderCorrupt);
        }
        let slot_count = u32_at(b, 16);
        if slot_count == 0 {
            return Err(RingError::HeaderCorrupt);
        }
        Ok(Header {
            interval_secs: u32_at(b, 20),
            slot_count,
            created_ms: i64::from_le_bytes(array_at(b, 24)),
            next_seq: u64::from_le_bytes(array_at(b, 32)),
        })
    }
}

// The callers check lengths before these, so the slices are always in range.
fn array_at<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[at..at + N]);
    a
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(array_at(b, at))
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// CRC-32 (IEEE, the zlib one).
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |c, &b| {
        CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8)
    })
}

/// Write `s` with a length byte. Text longer than `max` bytes is cut at a character boundary and
/// ends with `…`, still within `max`, and `truncated` is set.
fn put_str(out: &mut Vec<u8>, s: &str, max: usize, truncated: &mut bool) {
    if s.len() <= max {
        out.push(s.len() as u8);
        out.extend_from_slice(s.as_bytes());
        return;
    }
    *truncated = true;
    let mut end = max - ELLIPSIS.len();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    out.push((end + ELLIPSIS.len()) as u8);
    out.extend_from_slice(&s.as_bytes()[..end]);
    out.extend_from_slice(ELLIPSIS.as_bytes());
}

fn put_processes(out: &mut Vec<u8>, list: &[RecordedProcess], truncated: &mut bool) -> u8 {
    *truncated |= list.len() > MAX_PER_LIST;
    let kept = &list[..list.len().min(MAX_PER_LIST)];
    for p in kept {
        put_str(out, &p.name, NAME_MAX, truncated);
        out.extend_from_slice(&p.cpu_permille.to_le_bytes());
        out.extend_from_slice(&p.io_bytes_per_sec.to_le_bytes());
    }
    kept.len() as u8
}

/// Encode a slot block for sample number `seq`. Power requests that do not fit in the payload are
/// dropped from the end and the slot is marked truncated; nothing else can fail.
pub fn encode_slot(seq: u64, sample: &Sample) -> [u8; BLOCK] {
    let row = &sample.row;
    let mut truncated = false;
    let mut p = Vec::with_capacity(MAX_PAYLOAD);
    p.extend_from_slice(&row.at.as_millisecond().to_le_bytes());
    p.extend_from_slice(&row.interval_secs.to_le_bytes());
    p.extend_from_slice(&[0; 4]); // counts, filled in below
    let n_cpu = put_processes(&mut p, &row.top_cpu, &mut truncated);
    let n_io = put_processes(&mut p, &row.top_io, &mut truncated);
    let mut n_req = 0u8;
    for r in &row.power_requests {
        let mut e = Vec::new();
        put_str(&mut e, &r.owner, OWNER_MAX, &mut truncated);
        put_str(&mut e, &r.kind, KIND_MAX, &mut truncated);
        match &r.reason {
            Some(reason) => put_str(&mut e, reason, REASON_MAX, &mut truncated),
            None => e.push(NO_STRING),
        }
        if p.len() + e.len() > MAX_PAYLOAD || n_req == u8::MAX {
            truncated = true;
            break;
        }
        p.extend_from_slice(&e);
        n_req += 1;
    }
    p[12..15].copy_from_slice(&[n_cpu, n_io, n_req]);

    let mut flags = 0u16;
    if sample.requests_visible {
        flags |= FLAG_REQUESTS_VISIBLE;
    }
    if truncated {
        flags |= FLAG_TRUNCATED;
    }
    let mut block = [0u8; BLOCK];
    block[4..6].copy_from_slice(&(p.len() as u16).to_le_bytes());
    block[6..8].copy_from_slice(&flags.to_le_bytes());
    block[8..16].copy_from_slice(&seq.to_le_bytes());
    block[SLOT_HEAD..SLOT_HEAD + p.len()].copy_from_slice(&p);
    let crc = crc32(&block[4..SLOT_HEAD + p.len()]);
    block[0..4].copy_from_slice(&crc.to_le_bytes());
    block
}

/// What a slot block holds, before its payload is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    Empty,
    Corrupt,
    Valid { seq: u64, len: usize, flags: u16 },
}

/// Never written: all zero. Anything else must pass the checksum, fit the block and sit in the
/// slot its sequence number belongs to.
fn check_slot(block: &[u8], index: u32, slot_count: u32) -> Check {
    if block.len() != BLOCK {
        return Check::Corrupt;
    }
    if block.iter().all(|&b| b == 0) {
        return Check::Empty;
    }
    let len = usize::from(u16::from_le_bytes(array_at(block, 4)));
    let flags = u16::from_le_bytes(array_at(block, 6));
    let seq = u64::from_le_bytes(array_at(block, 8));
    if len > MAX_PAYLOAD
        || seq == 0
        || (seq - 1) % u64::from(slot_count) != u64::from(index)
        || crc32(&block[4..SLOT_HEAD + len]) != u32_at(block, 0)
    {
        return Check::Corrupt;
    }
    Check::Valid { seq, len, flags }
}

/// A bounds-checked reader over a payload. Every read can fail; none can panic.
struct Payload<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Payload<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32_at(s, 0))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|s| u64::from_le_bytes(array_at(s, 0)))
    }
    fn string(&mut self) -> Option<String> {
        let n = usize::from(self.u8()?);
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    fn opt_string(&mut self) -> Option<Option<String>> {
        match self.b.get(self.at)? {
            &NO_STRING => {
                self.at += 1;
                Some(None)
            }
            _ => self.string().map(Some),
        }
    }
    fn processes(&mut self, n: u8) -> Option<Vec<RecordedProcess>> {
        (0..n)
            .map(|_| {
                Some(RecordedProcess {
                    name: self.string()?,
                    cpu_permille: self.u32()?,
                    io_bytes_per_sec: self.u64()?,
                })
            })
            .collect()
    }
}

fn decode_payload(p: &[u8], flags: u16) -> Option<Sample> {
    let mut c = Payload { b: p, at: 0 };
    let at = Timestamp::from_millisecond(i64::from_le_bytes(array_at(c.take(8)?, 0))).ok()?;
    let interval_secs = c.u32()?;
    let [n_cpu, n_io, n_req, _] = array_at::<4>(c.take(4)?, 0);
    let top_cpu = c.processes(n_cpu)?;
    let top_io = c.processes(n_io)?;
    let power_requests = (0..n_req)
        .map(|_| {
            Some(RecordedRequest {
                owner: c.string()?,
                kind: c.string()?,
                reason: c.opt_string()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    if c.at != p.len() {
        return None;
    }
    Some(Sample {
        row: RecorderRow {
            at,
            interval_secs,
            top_cpu,
            top_io,
            power_requests,
        },
        requests_visible: flags & FLAG_REQUESTS_VISIBLE != 0,
        truncated: flags & FLAG_TRUNCATED != 0,
    })
}

/// A slot block decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// Never written.
    Empty,
    /// Written but unreadable: a torn write, damage, or a block in the wrong place.
    Corrupt,
    Valid {
        seq: u64,
        sample: Sample,
    },
}

/// Decode the block that sits at slot `index` of a ring with `slot_count` slots.
pub fn decode_slot(block: &[u8], index: u32, slot_count: u32) -> Slot {
    match check_slot(block, index, slot_count) {
        Check::Empty => Slot::Empty,
        Check::Corrupt => Slot::Corrupt,
        Check::Valid { seq, len, flags } => {
            match decode_payload(&block[SLOT_HEAD..SLOT_HEAD + len], flags) {
                Some(sample) => Slot::Valid { seq, sample },
                None => Slot::Corrupt,
            }
        }
    }
}

/// Everything a reader found in a ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub header: Header,
    /// Valid samples, oldest first by sequence number.
    pub samples: Vec<(u64, Sample)>,
    /// Slots that were written but unreadable, plus slots missing because the file is short.
    pub skipped: u32,
}

/// Read the header and hand every slot block, with its index and the slot count, to `each`.
/// Returns the header and how many slots lie beyond the end of a file that is shorter than its
/// header says.
fn walk<R: Read + Seek>(
    r: &mut R,
    mut each: impl FnMut(u32, u32, &[u8]),
) -> Result<(Header, u32), RingError> {
    r.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; HEADER_LEN];
    let got = read_full(r, &mut head)?;
    let header = Header::decode(&head[..got])?;
    r.seek(SeekFrom::Start(BLOCK as u64))?;
    const CHUNK: usize = 64;
    let mut buf = vec![0u8; CHUNK * BLOCK];
    let mut index = 0u32;
    while index < header.slot_count {
        let want = (header.slot_count - index).min(CHUNK as u32) as usize;
        let got = read_full(r, &mut buf[..want * BLOCK])? / BLOCK;
        for (i, block) in buf.as_chunks::<BLOCK>().0.iter().take(got).enumerate() {
            each(index + i as u32, header.slot_count, block);
        }
        index += got as u32;
        if got < want {
            break;
        }
    }
    Ok((header, header.slot_count - index))
}

/// Fill `buf` as far as the reader allows. Returns the bytes read, short only at the end.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Read every readable sample from a ring. A bad header is an error; bad slots are only counted.
pub fn scan<R: Read + Seek>(r: &mut R) -> Result<Scan, RingError> {
    let mut samples = Vec::new();
    let mut skipped = 0u32;
    let (header, missing) = walk(r, |index, count, block| {
        match decode_slot(block, index, count) {
            Slot::Empty => {}
            Slot::Corrupt => skipped += 1,
            Slot::Valid { seq, sample } => samples.push((seq, sample)),
        }
    })?;
    samples.sort_by_key(|(seq, _)| *seq);
    Ok(Scan {
        header,
        samples,
        // Slots read plus slots not there: never more than `slot_count`, so it cannot overflow.
        skipped: skipped + missing,
    })
}

/// A file, or an in-memory stand-in for one, that can be cut to an exact length.
pub trait Storage: Read + Write + Seek {
    fn set_len(&mut self, len: u64) -> io::Result<()>;
}

impl Storage for File {
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        File::set_len(self, len)
    }
}

#[cfg(test)]
impl<T: Storage> Storage for &mut T {
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        (**self).set_len(len)
    }
}

#[cfg(test)]
impl Storage for std::io::Cursor<Vec<u8>> {
    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.get_mut().resize(len as usize, 0);
        Ok(())
    }
}

/// The only writer of a ring. It never changes the file's length after [`RingWriter::start`].
pub struct RingWriter<S: Storage> {
    file: S,
    header: Header,
    bytes_written: u64,
}

impl<S: Storage> RingWriter<S> {
    /// Use `file` as a ring. An empty file is formatted to `total_bytes` (rounded down to whole
    /// blocks, at least two). A valid ring keeps the size it was made with and carries on after its
    /// newest sample.
    ///
    /// Anything else is refused with the reason and left untouched: not a ring (wrong magic), another
    /// version, a damaged header, or a length that is not what the header says. History is never
    /// thrown away on the writer's own initiative; [`RingWriter::reset`] does that, by explicit
    /// choice.
    pub fn start(
        mut file: S,
        total_bytes: u64,
        interval_secs: u32,
        now: Timestamp,
    ) -> Result<Self, RingError> {
        let len = file.seek(SeekFrom::End(0))?;
        if len == 0 {
            return Ok(Self::format(file, total_bytes, interval_secs, now)?);
        }
        let header = read_header(&mut file)?;
        if header.file_bytes() != len {
            return Err(RingError::WrongLength {
                expected: header.file_bytes(),
                found: len,
            });
        }
        let mut newest = 0u64;
        walk(&mut file, |index, count, block| {
            if let Check::Valid { seq, .. } = check_slot(block, index, count) {
                newest = newest.max(seq);
            }
        })?;
        let mut writer = RingWriter {
            file,
            header: Header {
                interval_secs,
                next_seq: newest.saturating_add(1),
                ..header
            },
            bytes_written: 0,
        };
        writer.write_header()?;
        Ok(writer)
    }

    /// Throw away what `file` holds and make it a new empty ring of `total_bytes`. This loses the
    /// history, so it is only for a deliberate request. It still refuses a file that is not a ring
    /// of this program (wrong magic, another version, too short to tell), so it cannot be used to
    /// wipe an unrelated file. A damaged header or a wrong length, the cases [`RingWriter::start`]
    /// refuses, are what it is for.
    pub fn reset(
        mut file: S,
        total_bytes: u64,
        interval_secs: u32,
        now: Timestamp,
    ) -> Result<Self, RingError> {
        if file.seek(SeekFrom::End(0))? != 0 {
            match read_header(&mut file) {
                Ok(_) | Err(RingError::HeaderCorrupt) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Self::format(file, total_bytes, interval_secs, now)?)
    }

    fn format(
        mut file: S,
        total_bytes: u64,
        interval_secs: u32,
        now: Timestamp,
    ) -> io::Result<Self> {
        let blocks = (total_bytes / BLOCK as u64).max(2);
        let header = Header {
            interval_secs,
            slot_count: u32::try_from(blocks - 1).unwrap_or(u32::MAX),
            created_ms: now.as_millisecond(),
            next_seq: 1,
        };
        // Cut to nothing first so no old bytes survive, then to the exact size: the disk space is
        // reserved here, and every later write lands inside the file.
        file.set_len(0)?;
        file.set_len(header.file_bytes())?;
        let mut writer = RingWriter {
            file,
            header,
            bytes_written: 0,
        };
        writer.write_header()?;
        Ok(writer)
    }

    fn write_header(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.header.encode())?;
        self.bytes_written += HEADER_LEN as u64;
        Ok(())
    }

    /// Store `sample` as the next one, overwriting the oldest once the ring is full.
    pub fn append(&mut self, sample: &Sample) -> io::Result<()> {
        let seq = self.header.next_seq;
        // A damaged or hostile ring can hold the largest sequence number. Wrapping would put old
        // samples after new ones, so refuse and let the ring be reset instead.
        let next = seq.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the ring's sequence numbers are used up; reset the ring",
            )
        })?;
        let index = seq.saturating_sub(1) % u64::from(self.header.slot_count);
        let at = (index + 1) * BLOCK as u64;
        if at + BLOCK as u64 > self.header.file_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "slot lies outside the ring",
            ));
        }
        self.file.seek(SeekFrom::Start(at))?;
        self.file.write_all(&encode_slot(seq, sample))?;
        self.bytes_written += BLOCK as u64;
        self.header.next_seq = next;
        self.write_header()
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    #[cfg(test)]
    pub(crate) fn into_storage(self) -> S {
        self.file
    }

    /// Bytes this writer has written, header rewrites included.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl RingWriter<File> {
    /// Open or create the ring at `path` (see [`RingWriter::start`]). The folder must exist.
    pub fn open(path: &Path, total_bytes: u64, interval_secs: u32) -> Result<Self, RingError> {
        let file = open_for_writing(path)?;
        Self::start(file, total_bytes, interval_secs, Timestamp::now())
    }

    /// Like [`RingWriter::open`], but throws away a damaged ring's history and starts a new empty
    /// one (see [`RingWriter::reset`]). Only for a deliberate request.
    pub fn open_reset(
        path: &Path,
        total_bytes: u64,
        interval_secs: u32,
    ) -> Result<Self, RingError> {
        let file = open_for_writing(path)?;
        Self::reset(file, total_bytes, interval_secs, Timestamp::now())
    }
}

fn open_for_writing(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    // Share for reading only. Without FILE_SHARE_DELETE the ring cannot be deleted or renamed out
    // from under the writer, which would go on writing to a file nobody can reach; without
    // FILE_SHARE_WRITE a second writer cannot open it. Readers (read access only) still can.
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::share_mode(&mut options, 1 /* FILE_SHARE_READ */);
    options.open(path)
}

fn read_header<R: Read + Seek>(r: &mut R) -> Result<Header, RingError> {
    r.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; HEADER_LEN];
    let got = read_full(r, &mut head)?;
    Header::decode(&head[..got])
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use super::*;

    const T0: i64 = 1_793_692_800; // 2026-11-03T08:00:00Z

    fn proc(name: &str, cpu: u32, io: u64) -> RecordedProcess {
        RecordedProcess {
            name: name.into(),
            cpu_permille: cpu,
            io_bytes_per_sec: io,
        }
    }

    fn request(owner: &str, kind: &str, reason: Option<&str>) -> RecordedRequest {
        RecordedRequest {
            owner: owner.into(),
            kind: kind.into(),
            reason: reason.map(String::from),
        }
    }

    /// Sample number `n`, one second after the one before.
    fn sample(n: i64) -> Sample {
        Sample {
            row: RecorderRow {
                at: Timestamp::from_second(T0 + n).unwrap(),
                interval_secs: 60,
                top_cpu: vec![proc("chrome.exe", 250 + n as u32, 1_000)],
                top_io: vec![proc("svchost.exe", 3, 4_000_000)],
                power_requests: vec![request("teams.exe", "display", Some("In a call"))],
            },
            requests_visible: true,
            truncated: false,
        }
    }

    /// A sample whose payload is well over 512 bytes, so a torn write at a sector boundary shows.
    fn fat_sample(tag: &str) -> Sample {
        let mut s = sample(0);
        s.row.power_requests = (0..4)
            .map(|i| {
                request(
                    &format!("{tag}-owner-{i}-padding-padding-pad.exe"),
                    "execution",
                    // The tag ends the payload, so old and new differ in the bytes past a sector.
                    Some(&format!("{}-{tag}", "reason ".repeat(10))),
                )
            })
            .collect();
        s
    }

    fn ring(slots: u64) -> RingWriter<Cursor<Vec<u8>>> {
        let now = Timestamp::from_second(T0).unwrap();
        RingWriter::start(Cursor::new(Vec::new()), (slots + 1) * BLOCK as u64, 60, now).unwrap()
    }

    fn seqs(scan: &Scan) -> Vec<u64> {
        scan.samples.iter().map(|(seq, _)| *seq).collect()
    }

    fn scan_of(w: &RingWriter<Cursor<Vec<u8>>>) -> Result<Scan, RingError> {
        scan(&mut Cursor::new(w.file.get_ref().clone()))
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_new_ring_is_empty_and_exactly_the_size_asked_for() {
        let w = ring(7);
        assert_eq!(w.file.get_ref().len(), 8 * BLOCK);
        let s = scan_of(&w).unwrap();
        assert!(s.samples.is_empty());
        assert_eq!(s.skipped, 0);
        assert_eq!(s.header.slot_count, 7);
        assert_eq!(s.header.interval_secs, 60);
    }

    #[test]
    fn default_size_is_16_mib_and_16383_slots() {
        assert_eq!(DEFAULT_BYTES / BLOCK as u64 - 1, 16_383);
        // 16 383 samples at the default 60 s interval, in days.
        assert!((16_383.0 * 60.0 / 86_400.0 - 11.38f64).abs() < 0.01);
    }

    #[test]
    fn a_sample_survives_the_round_trip() {
        let mut w = ring(4);
        let mut s = sample(1);
        s.row.top_cpu.push(proc("Блокнот.exe", 12, 0));
        s.row.power_requests.push(request("a.exe", "system", None));
        w.append(&s).unwrap();
        let got = scan_of(&w).unwrap();
        assert_eq!(got.samples, vec![(1, s)]);
    }

    #[test]
    fn requests_not_visible_is_kept() {
        let mut w = ring(4);
        let mut s = sample(1);
        s.requests_visible = false;
        s.row.power_requests.clear();
        w.append(&s).unwrap();
        let got = scan_of(&w).unwrap();
        assert!(!got.samples[0].1.requests_visible);
        assert!(got.samples[0].1.row.power_requests.is_empty());
    }

    #[test]
    fn wrap_around_keeps_the_newest_slots_in_order() {
        let mut w = ring(5);
        for n in 1..=12 {
            w.append(&sample(n)).unwrap();
        }
        let got = scan_of(&w).unwrap();
        assert_eq!(seqs(&got), vec![8, 9, 10, 11, 12]);
        assert_eq!(got.skipped, 0);
        // The sample bodies went with their sequence numbers.
        assert_eq!(
            got.samples[0].1.row.at,
            Timestamp::from_second(T0 + 8).unwrap()
        );
        assert_eq!(w.header().next_seq, 13);
    }

    #[test]
    fn a_partly_filled_ring_has_no_skips() {
        let mut w = ring(5);
        for n in 1..=3 {
            w.append(&sample(n)).unwrap();
        }
        let got = scan_of(&w).unwrap();
        assert_eq!(seqs(&got), vec![1, 2, 3]);
        assert_eq!(got.skipped, 0);
    }

    #[test]
    fn a_torn_write_is_skipped_and_counted() {
        let mut w = ring(4);
        for _ in 1..=4 {
            w.append(&fat_sample("old")).unwrap();
        }
        // Sample 5 belongs in slot 0. Only its first sector reached the disk.
        let new = encode_slot(5, &fat_sample("new"));
        // The test only means something if the payload reaches into the second sector.
        let payload_len = usize::from(u16::from_le_bytes(array_at(&new, 4)));
        assert!(SLOT_HEAD + payload_len > 512 + 8, "{payload_len}");
        let at = BLOCK;
        w.file.get_mut()[at..at + 512].copy_from_slice(&new[..512]);

        let got = scan_of(&w).unwrap();
        assert_eq!(seqs(&got), vec![2, 3, 4]);
        assert_eq!(got.skipped, 1);

        // A writer that starts again heals the slot instead of failing.
        let mut again = RingWriter::start(
            Cursor::new(w.file.get_ref().clone()),
            0,
            60,
            Timestamp::from_second(T0).unwrap(),
        )
        .unwrap();
        assert_eq!(again.header().next_seq, 5);
        again.append(&fat_sample("new")).unwrap();
        let healed = scan(&mut Cursor::new(again.file.get_ref().clone())).unwrap();
        assert_eq!(seqs(&healed), vec![2, 3, 4, 5]);
        assert_eq!(healed.skipped, 0);
    }

    #[test]
    fn damaged_and_misplaced_slots_are_counted() {
        let mut w = ring(4);
        for n in 1..=4 {
            w.append(&sample(n)).unwrap();
        }
        // Flip a payload byte of slot 1 (sample 2).
        w.file.get_mut()[2 * BLOCK + SLOT_HEAD + 3] ^= 0xFF;
        // Put sample 3's block, valid in itself, into slot 3 where it does not belong.
        let moved = w.file.get_ref()[3 * BLOCK..4 * BLOCK].to_vec();
        w.file.get_mut()[4 * BLOCK..5 * BLOCK].copy_from_slice(&moved);
        let got = scan_of(&w).unwrap();
        assert_eq!(seqs(&got), vec![1, 3]);
        assert_eq!(got.skipped, 2);
    }

    #[test]
    fn a_file_cut_short_counts_the_missing_slots() {
        let mut w = ring(6);
        for n in 1..=6 {
            w.append(&sample(n)).unwrap();
        }
        w.file.get_mut().truncate(4 * BLOCK + 10);
        let got = scan_of(&w).unwrap();
        assert_eq!(seqs(&got), vec![1, 2, 3]);
        assert_eq!(got.skipped, 3);
    }

    #[test]
    fn wrong_magic_version_and_header_are_errors_not_panics() {
        let good = ring(3).file.into_inner();

        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(matches!(
            scan(&mut Cursor::new(bad)),
            Err(RingError::BadMagic)
        ));

        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            scan(&mut Cursor::new(bad)),
            Err(RingError::BadVersion(2))
        ));

        let mut bad = good.clone();
        bad[20] ^= 1; // interval, covered by the header checksum
        assert!(matches!(
            scan(&mut Cursor::new(bad)),
            Err(RingError::HeaderCorrupt)
        ));

        assert!(matches!(
            scan(&mut Cursor::new(good[..20].to_vec())),
            Err(RingError::TooShort)
        ));
        assert!(matches!(
            scan(&mut Cursor::new(Vec::new())),
            Err(RingError::TooShort)
        ));
    }

    #[test]
    fn the_largest_sequence_number_is_refused_not_wrapped() {
        let mut w = ring(4);
        // A valid, correctly placed slot numbered u64::MAX, as a damaged or hostile file could hold.
        let index = ((u64::MAX - 1) % 4) as usize;
        let block = encode_slot(u64::MAX, &sample(1));
        let at = (index + 1) * BLOCK;
        w.file.get_mut()[at..at + BLOCK].copy_from_slice(&block);
        let now = Timestamp::from_second(T0).unwrap();
        let mut again =
            RingWriter::start(Cursor::new(w.file.get_ref().clone()), 0, 60, now).unwrap();
        assert_eq!(again.header().next_seq, u64::MAX);
        let before = again.file.get_ref().clone();
        let err = again.append(&sample(2)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // Nothing was written, and the ring still reads.
        assert_eq!(*again.file.get_ref(), before);
        let got = scan(&mut Cursor::new(before)).unwrap();
        assert_eq!(seqs(&got), vec![u64::MAX]);
    }

    #[test]
    fn a_header_claiming_billions_of_slots_in_a_short_file_is_read_without_trouble() {
        // A header that passes its checksum but lies about the geometry, over three real blocks,
        // one of them torn: no giant allocation or loop, and the missing slots are counted.
        let lying = Header {
            interval_secs: 60,
            slot_count: u32::MAX,
            created_ms: 0,
            next_seq: 1,
        };
        let mut bytes = vec![0u8; 4 * BLOCK];
        bytes[..HEADER_LEN].copy_from_slice(&lying.encode());
        bytes[BLOCK + 9] = 1; // slot 0: not empty, not valid
        let got = scan(&mut Cursor::new(bytes)).unwrap();
        assert!(got.samples.is_empty());
        assert_eq!(got.skipped, u32::MAX - 2); // one torn, the other u32::MAX - 3 missing
    }

    #[test]
    fn the_writer_refuses_a_file_that_is_not_its_own_and_leaves_it_alone() {
        let now = Timestamp::from_second(T0).unwrap();
        let foreign = b"some other program's data, long enough to look like a file".to_vec();
        let err = RingWriter::start(Cursor::new(foreign.clone()), DEFAULT_BYTES, 60, now)
            .err()
            .unwrap();
        assert!(matches!(err, RingError::BadMagic));

        let mut other_version = ring(3).file.into_inner();
        other_version[8..12].copy_from_slice(&9u32.to_le_bytes());
        let mut cursor = Cursor::new(other_version.clone());
        let err = RingWriter::start(&mut cursor, 0, 60, now).err().unwrap();
        assert!(matches!(err, RingError::BadVersion(9)));
        assert_eq!(cursor.into_inner(), other_version);
    }

    /// A ring of three samples, as bytes.
    fn ring_with_history() -> Vec<u8> {
        let mut w = ring(4);
        for n in 1..=3 {
            w.append(&sample(n)).unwrap();
        }
        w.file.into_inner()
    }

    #[test]
    fn a_damaged_header_is_refused_with_the_reason_and_the_history_is_kept() {
        let mut bytes = ring_with_history();
        bytes[24] ^= 0xFF; // the creation time, covered by the header checksum
        let now = Timestamp::from_second(T0).unwrap();
        let mut file = Cursor::new(bytes.clone());
        let err = RingWriter::start(&mut file, 5 * BLOCK as u64, 30, now)
            .err()
            .unwrap();
        assert!(matches!(err, RingError::HeaderCorrupt), "{err}");
        assert_eq!(file.into_inner(), bytes, "the file was changed");
    }

    #[test]
    fn a_length_that_is_not_the_headers_is_refused_with_the_reason_and_left_alone() {
        let now = Timestamp::from_second(T0).unwrap();
        let whole = ring_with_history();
        let mut longer = whole.clone();
        longer.extend_from_slice(&[0; 100]);
        let mut shorter = whole.clone();
        shorter.truncate(3 * BLOCK);
        for (bytes, found) in [(longer, 5 * BLOCK + 100), (shorter, 3 * BLOCK)] {
            let mut file = Cursor::new(bytes.clone());
            let err = RingWriter::start(&mut file, 0, 60, now).err().unwrap();
            match err {
                RingError::WrongLength { expected, found: f } => {
                    assert_eq!((expected, f), (5 * BLOCK as u64, found as u64));
                }
                other => panic!("{other}"),
            }
            assert_eq!(file.into_inner(), bytes, "the file was changed");
        }
    }

    #[test]
    fn reset_starts_a_new_ring_only_when_asked_and_only_for_our_own_file() {
        let now = Timestamp::from_second(T0).unwrap();
        // A damaged header, and a wrong length: the two cases `start` refuses.
        let mut damaged = ring_with_history();
        damaged[24] ^= 0xFF;
        let mut cut = ring_with_history();
        cut.truncate(2 * BLOCK);
        for bytes in [damaged, cut] {
            let w = RingWriter::reset(Cursor::new(bytes), 5 * BLOCK as u64, 30, now).unwrap();
            assert_eq!(w.header().slot_count, 4);
            assert_eq!(w.header().interval_secs, 30);
            assert_eq!(w.header().next_seq, 1);
            assert_eq!(w.file.get_ref().len(), 5 * BLOCK);
            // Empty, with no sample left from before.
            assert!(scan_of(&w).unwrap().samples.is_empty());
        }
        // An empty file is simply formatted.
        let fresh = RingWriter::reset(Cursor::new(Vec::new()), 4 * BLOCK as u64, 60, now).unwrap();
        assert_eq!(fresh.header().slot_count, 3);
        // A file that is not ours, or from another version, or too short to tell, is refused untouched.
        let mut other_version = ring_with_history();
        other_version[8..12].copy_from_slice(&9u32.to_le_bytes());
        let foreign = b"some other program's data, long enough to look like a file".to_vec();
        for bytes in [foreign, other_version, b"tiny".to_vec()] {
            let mut file = Cursor::new(bytes.clone());
            assert!(RingWriter::reset(&mut file, BLOCK as u64 * 4, 60, now).is_err());
            assert_eq!(file.into_inner(), bytes);
        }
    }

    #[test]
    fn a_writer_carries_on_after_the_newest_sample_even_with_a_stale_hint() {
        let mut w = ring(4);
        for n in 1..=3 {
            w.append(&sample(n)).unwrap();
        }
        // A crash after the slot write and before the header write leaves the hint behind.
        let mut bytes = w.file.get_ref().clone();
        let stale = Header {
            next_seq: 2,
            ..*w.header()
        };
        bytes[..HEADER_LEN].copy_from_slice(&stale.encode());
        let now = Timestamp::from_second(T0).unwrap();
        let mut again = RingWriter::start(Cursor::new(bytes), 0, 15, now).unwrap();
        assert_eq!(again.header().next_seq, 4);
        assert_eq!(again.header().interval_secs, 15);
        again.append(&sample(4)).unwrap();
        let got = scan(&mut Cursor::new(again.file.into_inner())).unwrap();
        assert_eq!(seqs(&got), vec![1, 2, 3, 4]);
    }

    #[test]
    fn long_names_are_cut_at_a_character_boundary_and_marked() {
        let mut w = ring(4);
        let mut s = sample(1);
        s.row.top_cpu = vec![
            proc(&"x".repeat(100), 1, 1),
            // 2-byte characters: the cut must not split one.
            proc(&"ж".repeat(40), 2, 2),
            proc("short.exe", 3, 3),
        ];
        s.row.power_requests = vec![request("o", "k", Some(&"р".repeat(100)))];
        w.append(&s).unwrap();
        let got = &scan_of(&w).unwrap().samples[0].1;
        assert!(got.truncated);
        let names: Vec<_> = got.row.top_cpu.iter().map(|p| p.name.as_str()).collect();
        assert!(names[0].ends_with('…') && names[0].len() <= NAME_MAX);
        assert!(names[1].ends_with('…') && names[1].len() <= NAME_MAX);
        assert!(names[1].starts_with("жж"));
        assert_eq!(names[2], "short.exe");
        let reason = got.row.power_requests[0].reason.as_deref().unwrap();
        assert!(reason.ends_with('…') && reason.len() <= REASON_MAX);
    }

    #[test]
    fn a_sample_that_fits_is_not_marked_truncated() {
        let mut w = ring(4);
        let mut s = sample(1);
        s.row.top_cpu = vec![proc(&"n".repeat(NAME_MAX), 1, 1)];
        w.append(&s).unwrap();
        let got = &scan_of(&w).unwrap().samples[0].1;
        assert!(!got.truncated);
        assert_eq!(got.row.top_cpu[0].name.len(), NAME_MAX);
    }

    #[test]
    fn requests_that_do_not_fit_are_dropped_from_the_end_and_marked() {
        let mut w = ring(4);
        let mut s = fat_sample("a");
        s.row.power_requests = (0..40)
            .map(|i| request(&format!("owner{i}"), "execution", Some(&"r".repeat(70))))
            .collect();
        w.append(&s).unwrap();
        let got = &scan_of(&w).unwrap().samples[0].1;
        assert!(got.truncated);
        let n = got.row.power_requests.len();
        assert!(n > 3 && n < 40, "{n}");
        assert_eq!(got.row.power_requests[0].owner, "owner0");
        assert_eq!(
            got.row.power_requests[n - 1].owner,
            format!("owner{}", n - 1)
        );
    }

    #[test]
    fn more_than_five_processes_per_list_are_cut_and_marked() {
        let mut w = ring(4);
        let mut s = sample(1);
        s.row.top_cpu = (0..9).map(|i| proc(&format!("p{i}"), i, 0)).collect();
        w.append(&s).unwrap();
        let got = &scan_of(&w).unwrap().samples[0].1;
        assert!(got.truncated);
        assert_eq!(got.row.top_cpu.len(), MAX_PER_LIST);
    }

    #[test]
    fn the_fullest_allowed_sample_always_fits() {
        // Five processes per list with the longest names, no request.
        let mut s = sample(1);
        s.row.top_cpu = (0..5)
            .map(|_| proc(&"m".repeat(NAME_MAX), u32::MAX, u64::MAX))
            .collect();
        s.row.top_io = s.row.top_cpu.clone();
        s.row.power_requests.clear();
        let mut w = ring(2);
        w.append(&s).unwrap();
        let got = &scan_of(&w).unwrap().samples[0].1;
        assert!(!got.truncated);
        assert_eq!(got.row.top_io.len(), 5);
    }

    /// A small xorshift, so the "random" bytes are the same on every run.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn nothing_a_corrupt_slot_holds_can_panic_the_decoder() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let valid = encode_slot(1, &fat_sample("fuzz"));

        // Whole blocks of noise.
        for _ in 0..5_000 {
            let mut block = [0u8; BLOCK];
            for b in &mut block {
                *b = rng.next() as u8;
            }
            let _ = decode_slot(&block, 0, 4);
        }
        // Valid blocks with a few payload bytes changed and the checksum made right again, so the
        // payload parser itself is the thing under test.
        let mut valid_after = 0;
        for _ in 0..30_000 {
            let mut block = valid;
            let len = usize::from(u16::from_le_bytes(array_at(&block, 4)));
            for _ in 0..1 + rng.next() % 3 {
                let at = SLOT_HEAD + (rng.next() as usize % len);
                block[at] = rng.next() as u8;
            }
            if rng.next().is_multiple_of(4) {
                let new_len = (rng.next() as usize) % (MAX_PAYLOAD + 1);
                block[4..6].copy_from_slice(&(new_len as u16).to_le_bytes());
            }
            let len = usize::from(u16::from_le_bytes(array_at(&block, 4)));
            let crc = crc32(&block[4..SLOT_HEAD + len]);
            block[0..4].copy_from_slice(&crc.to_le_bytes());
            if matches!(decode_slot(&block, 0, 4), Slot::Valid { .. }) {
                valid_after += 1;
            }
        }
        // Some mutations land on numbers and stay valid, which shows the loop reaches the parser.
        assert!(valid_after > 0);
    }

    #[test]
    fn a_ring_file_keeps_its_exact_size_across_many_wraps() {
        let dir = TempDir::new("wrap");
        let path = dir.0.join("test.ring");
        let total = 64 * 1024u64; // 63 slots
        let mut w = RingWriter::open(&path, total, 60).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), total);
        for n in 0..2_000 {
            w.append(&sample(n)).unwrap();
        }
        // About 31 wraps later the file has the same length, byte for byte.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), total);
        assert_eq!(std::fs::read(&path).unwrap().len() as u64, total);
        let got = scan(&mut File::open(&path).unwrap()).unwrap();
        assert_eq!(got.samples.len(), 63);
        assert_eq!(got.samples.last().unwrap().0, 2_000);
        assert_eq!(got.skipped, 0);
        // Reopening with a different requested size keeps the ring's own size.
        drop(w);
        let again = RingWriter::open(&path, 1 << 20, 30).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), total);
        assert_eq!(again.header().next_seq, 2_001);
    }

    #[cfg(windows)]
    #[test]
    fn an_open_ring_cannot_be_deleted_replaced_or_written_by_another_but_can_be_read() {
        let dir = TempDir::new("share");
        let path = dir.0.join("test.ring");
        let mut writer = RingWriter::open(&path, 8 * BLOCK as u64, 60).unwrap();
        writer.append(&sample(1)).unwrap();
        // Deleting or renaming it would leave the writer filling a file nobody can reach.
        assert!(std::fs::remove_file(&path).is_err());
        assert!(std::fs::rename(&path, dir.0.join("moved.ring")).is_err());
        // A second writer is refused.
        assert!(RingWriter::open(&path, 8 * BLOCK as u64, 60).is_err());
        // A reader is not, and sees what has been written so far.
        let got = scan(&mut File::open(&path).unwrap()).unwrap();
        assert_eq!(seqs(&got), vec![1]);
        // Once the writer has gone, the file can be removed again.
        drop(writer);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_default_ring_is_16_mib_exactly() {
        let dir = TempDir::new("default");
        let path = dir.0.join("test.ring");
        let w = RingWriter::open(&path, DEFAULT_BYTES, 60).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 16 * 1024 * 1024);
        assert_eq!(w.header().slot_count, 16_383);
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir =
                std::env::temp_dir().join(format!("pcsleuth-ring-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
