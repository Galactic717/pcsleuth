//! What the optional recorder keeps per sample. Logs do not keep these, so the recorder does.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// One process at one sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedProcess {
    /// Exe base name, such as `chrome.exe`.
    pub name: String,
    /// CPU over the sample interval, in tenths of a percent of the whole machine.
    pub cpu_permille: u32,
    pub io_bytes_per_sec: u64,
}

/// One live power request at one sample. Owners are visible only when the recorder runs elevated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRequest {
    /// Exe base name, driver or service holding the request.
    pub owner: String,
    /// `system`, `display`, `away_mode`, `execution` or a similar stable identifier.
    pub kind: String,
    pub reason: Option<String>,
}

/// One sample. A finding built from it has [`crate::Confidence::Sampled`] and states `interval_secs`,
/// since anything shorter than the interval can be missed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecorderRow {
    pub at: Timestamp,
    pub interval_secs: u32,
    pub top_cpu: Vec<RecordedProcess>,
    pub top_io: Vec<RecordedProcess>,
    pub power_requests: Vec<RecordedRequest>,
}
