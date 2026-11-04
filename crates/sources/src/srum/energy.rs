//! The `BinaryData` blob of the energy estimation table `{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}`.
//!
//! The layout is not documented by Microsoft. It was worked out from a real database and checked
//! against `powercfg /srumutil /csv` taken from the same machine: 45,596 records lined up one to one,
//! and every energy column agreed exactly. All offsets are little endian.
//!
//! | Offset | Size | Meaning |
//! |---|---|---|
//! | 0 | u32 | flags: bit 0 on battery, bit 1 screen on, bit 2 battery saver, bit 4 foreground, bits 5-6 interactivity (0 not unique, 1 minimized, 2 visible, 3 focus) |
//! | 4 | u32 | duration the record covers, in milliseconds |
//! | 8 | u32 | mask `B`: which values follow (bit 2 is always set and carries no value) |
//! | 12 | u32 | mask `C`: bit 3 means a value follows, bit 28 only marks the measured-total form |
//! | 16 | 8 bytes | not decoded |
//! | 24 | u64 | energy loss |
//! | 32 | u64 each | one value per known mask bit, `B` bits in ascending order, then `C` bit 3 |
//!
//! `B` bit 3 is CPU, 4 SoC, 5 display, 6 disk, 7 network, 12 EMI total, 19 CPU on behalf of other
//! apps; `C` bit 3 is CPU attributed. A mask bit this decoder does not know cannot be placed in
//! the value list, so such a record is rejected, not guessed.

/// Size of the fixed header before the value list.
const HEADER_LEN: usize = 32;

/// Mask `B` bits that mean something here; bit 2 is the always-set base bit.
const KNOWN_B: u32 =
    (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 12) | (1 << 19);
const KNOWN_C: u32 = (1 << 3) | (1 << 28);

/// One decoded energy record. Values are in the units SRUM stores.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnergyRecord {
    pub duration_ms: u32,
    pub on_battery: bool,
    pub screen_on: bool,
    pub battery_saver: bool,
    pub foreground: bool,
    /// 0 not unique, 1 minimized, 2 visible, 3 focus.
    pub interactivity: u8,
    pub loss: u64,
    pub cpu: u64,
    pub soc: u64,
    pub display: u64,
    pub disk: u64,
    pub network: u64,
    pub emi: u64,
    /// CPU energy spent on behalf of other apps. A part of `cpu`, not an addition to it.
    pub cpu_work_on_behalf: u64,
    /// CPU energy attributed to this app. A part of `cpu`, not an addition to it.
    pub cpu_attributed: u64,
}

impl EnergyRecord {
    /// What `powercfg /srumutil` prints as `TotalEnergyConsumption`: the components plus the loss.
    /// The work-on-behalf and attributed values break `cpu` down and are not added again.
    pub fn total(&self) -> u64 {
        [
            self.cpu,
            self.soc,
            self.display,
            self.disk,
            self.network,
            self.emi,
            self.loss,
        ]
        .into_iter()
        .fold(0u64, u64::saturating_add)
    }
}

/// Why a blob was not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnergyBlobError {
    /// Shorter than the fixed header.
    TooShort { len: usize },
    /// A mask bit this decoder does not know, so the value list cannot be placed.
    UnknownMask { b: u32, c: u32 },
    /// The blob length does not match the number of values the masks promise.
    LengthMismatch { expected: usize, actual: usize },
}

fn u32_at(blob: &[u8], at: usize) -> u32 {
    let bytes: [u8; 4] = blob[at..at + 4].try_into().unwrap_or([0; 4]);
    u32::from_le_bytes(bytes)
}

fn u64_at(blob: &[u8], at: usize) -> u64 {
    let bytes: [u8; 8] = blob[at..at + 8].try_into().unwrap_or([0; 8]);
    u64::from_le_bytes(bytes)
}

/// Decode one blob. Never panics on short or odd input.
pub fn decode_energy(blob: &[u8]) -> Result<EnergyRecord, EnergyBlobError> {
    if blob.len() < HEADER_LEN {
        return Err(EnergyBlobError::TooShort { len: blob.len() });
    }
    let flags = u32_at(blob, 0);
    let (b, c) = (u32_at(blob, 8), u32_at(blob, 12));
    if (b & !KNOWN_B) != 0 || (c & !KNOWN_C) != 0 {
        return Err(EnergyBlobError::UnknownMask { b, c });
    }
    let values = [3, 4, 5, 6, 7, 12, 19]
        .iter()
        .filter(|&&bit| b >> bit & 1 == 1)
        .count()
        + usize::from(c >> 3 & 1 == 1);
    let expected = HEADER_LEN + 8 * values;
    if blob.len() != expected {
        return Err(EnergyBlobError::LengthMismatch {
            expected,
            actual: blob.len(),
        });
    }

    let mut record = EnergyRecord {
        duration_ms: u32_at(blob, 4),
        on_battery: flags & 1 != 0,
        screen_on: flags >> 1 & 1 != 0,
        battery_saver: flags >> 2 & 1 != 0,
        foreground: flags >> 4 & 1 != 0,
        interactivity: (flags >> 5 & 3) as u8,
        loss: u64_at(blob, 24),
        ..EnergyRecord::default()
    };
    let mut next = HEADER_LEN;
    let mut take = |present: bool| {
        present.then(|| {
            let value = u64_at(blob, next);
            next += 8;
            value
        })
    };
    record.cpu = take(b >> 3 & 1 == 1).unwrap_or(0);
    record.soc = take(b >> 4 & 1 == 1).unwrap_or(0);
    record.display = take(b >> 5 & 1 == 1).unwrap_or(0);
    record.disk = take(b >> 6 & 1 == 1).unwrap_or(0);
    record.network = take(b >> 7 & 1 == 1).unwrap_or(0);
    record.emi = take(b >> 12 & 1 == 1).unwrap_or(0);
    record.cpu_work_on_behalf = take(b >> 19 & 1 == 1).unwrap_or(0);
    record.cpu_attributed = take(c >> 3 & 1 == 1).unwrap_or(0);
    Ok(record)
}

/// Build a blob in the layout above, for tests. Zero values are left out, as Windows does.
#[cfg(test)]
pub(crate) fn encode_energy(record: &EnergyRecord) -> Vec<u8> {
    let mut flags = 0x9800u32; // the high bits every real record carries
    flags |= u32::from(record.on_battery);
    flags |= u32::from(record.screen_on) << 1;
    flags |= u32::from(record.battery_saver) << 2;
    flags |= u32::from(record.foreground) << 4;
    flags |= u32::from(record.interactivity & 3) << 5;
    let slots = [
        (3, record.cpu),
        (4, record.soc),
        (5, record.display),
        (6, record.disk),
        (7, record.network),
        (12, record.emi),
        (19, record.cpu_work_on_behalf),
    ];
    let mut b = 1u32 << 2;
    let mut values = Vec::new();
    for (bit, value) in slots {
        if value != 0 {
            b |= 1 << bit;
            values.push(value);
        }
    }
    let mut c = 0u32;
    if record.cpu_attributed != 0 {
        c |= 1 << 3;
        values.push(record.cpu_attributed);
    }
    let mut blob = Vec::new();
    blob.extend(flags.to_le_bytes());
    blob.extend(record.duration_ms.to_le_bytes());
    blob.extend(b.to_le_bytes());
    blob.extend(c.to_le_bytes());
    blob.extend([0u8; 8]);
    blob.extend(record.loss.to_le_bytes());
    for value in values {
        blob.extend(value.to_le_bytes());
    }
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built from the documented layout; not a capture from a machine.
    fn synthetic() -> EnergyRecord {
        EnergyRecord {
            duration_ms: 3_665_482,
            on_battery: true,
            screen_on: true,
            battery_saver: false,
            foreground: true,
            interactivity: 2,
            loss: 61,
            cpu: 1827,
            disk: 26,
            cpu_work_on_behalf: 1057,
            cpu_attributed: 818,
            ..EnergyRecord::default()
        }
    }

    #[test]
    fn decodes_the_documented_layout_by_hand_built_bytes() {
        // flags 0x9857: on battery, screen on, battery saver, foreground, visible. Mask B has CPU,
        // disk and work on behalf; mask C has attributed. Then loss, then four values.
        let mut blob = Vec::new();
        blob.extend(0x9857u32.to_le_bytes());
        blob.extend(1000u32.to_le_bytes());
        blob.extend(((1u32 << 2) | (1 << 3) | (1 << 6) | (1 << 19)).to_le_bytes());
        blob.extend((1u32 << 3).to_le_bytes());
        blob.extend([0xAAu8; 8]);
        blob.extend(7u64.to_le_bytes());
        for value in [100u64, 20, 30, 40] {
            blob.extend(value.to_le_bytes());
        }
        let record = decode_energy(&blob).unwrap();
        assert_eq!(record.duration_ms, 1000);
        assert!(record.on_battery && record.screen_on && record.battery_saver && record.foreground);
        assert_eq!(record.interactivity, 2);
        assert_eq!(
            (
                record.cpu,
                record.disk,
                record.cpu_work_on_behalf,
                record.cpu_attributed
            ),
            (100, 20, 30, 40)
        );
        assert_eq!(record.loss, 7);
        // Total is the components plus the loss; work-on-behalf and attributed are not added.
        assert_eq!(record.total(), 100 + 20 + 7);
    }

    #[test]
    fn round_trips_and_total_matches_powercfg_arithmetic() {
        let record = synthetic();
        let blob = encode_energy(&record);
        assert_eq!(blob.len(), 32 + 8 * 4);
        assert_eq!(decode_energy(&blob).unwrap(), record);
        // 1827 CPU + 26 disk + 61 loss; the breakdown columns are not added.
        assert_eq!(record.total(), 1914);
    }

    #[test]
    fn a_header_only_blob_is_an_empty_record() {
        let record = EnergyRecord::default();
        let blob = encode_energy(&record);
        assert_eq!(blob.len(), 32);
        assert_eq!(decode_energy(&blob).unwrap(), record);
        assert_eq!(record.total(), 0);
    }

    #[test]
    fn the_measured_total_form_carries_a_single_emi_value() {
        let record = EnergyRecord {
            emi: 5_000,
            ..EnergyRecord::default()
        };
        let mut blob = encode_energy(&record);
        // Real records of this form also set C bit 28; it must not shift the value list.
        blob[12..16].copy_from_slice(&(1u32 << 28).to_le_bytes());
        let decoded = decode_energy(&blob).unwrap();
        assert_eq!(decoded.emi, 5_000);
        assert_eq!(decoded.total(), 5_000);
    }

    #[test]
    fn rejects_short_unknown_and_inconsistent_blobs_without_panicking() {
        assert_eq!(
            decode_energy(&[]),
            Err(EnergyBlobError::TooShort { len: 0 })
        );
        assert_eq!(
            decode_energy(&[0; 31]),
            Err(EnergyBlobError::TooShort { len: 31 })
        );

        let mut unknown = encode_energy(&synthetic());
        unknown[8..12].copy_from_slice(&((1u32 << 2) | (1 << 9)).to_le_bytes());
        assert!(matches!(
            decode_energy(&unknown),
            Err(EnergyBlobError::UnknownMask { .. })
        ));

        let mut truncated = encode_energy(&synthetic());
        truncated.truncate(truncated.len() - 8);
        assert_eq!(
            decode_energy(&truncated),
            Err(EnergyBlobError::LengthMismatch {
                expected: 64,
                actual: 56
            })
        );
    }

    #[test]
    fn total_saturates_instead_of_overflowing() {
        let record = EnergyRecord {
            cpu: u64::MAX,
            disk: 5,
            ..EnergyRecord::default()
        };
        assert_eq!(record.total(), u64::MAX);
    }
}
