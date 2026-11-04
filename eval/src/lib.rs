//! Fault injection and scoring for the published evaluation. Method and numbers: docs/EVAL.md.
//!
//! `score`, `scenario` and `report` are pure and portable. `sys` holds the few OS calls, and
//! everything that touches Windows is behind `cfg(windows)`, so the crate still builds elsewhere.
#![deny(unsafe_code)]

pub mod fault;
pub mod host;
pub mod report;
pub mod runner;
pub mod scenario;
pub mod score;
#[allow(unsafe_code)]
pub mod sys;
