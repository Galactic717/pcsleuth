//! The contract every pcsleuth package depends on.
//!
//! Pure data and rules: no OS calls, no `cfg(windows)`, builds anywhere. Sources return
//! [`Sourced`] values, the engine turns them into [`Finding`]s, and the command line and the app
//! show an [`Answer`]. The JSON form of [`Answer`] is the public interface; its shape is pinned by
//! a golden test and versioned by [`SCHEMA_VERSION`].
#![forbid(unsafe_code)]

mod answer;
mod finding;
mod recorder;
mod source;
mod timeline;

pub use answer::{Answer, Question, SCHEMA_VERSION};
pub use finding::{Confidence, Evidence, Finding, FindingError, Fix, NotRecorded};
pub use jiff::Timestamp;
pub use recorder::{RecordedProcess, RecordedRequest, RecorderRow};
pub use source::{Access, Limit, SourceId, Sourced};
pub use timeline::merge_timeline;
