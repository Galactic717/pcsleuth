//! Readers for what Windows keeps. Every read returns `pcsleuth_core::Sourced`, so an unreadable
//! source is data, never a panic.
//!
//! OS calls live here behind `#[cfg(windows)]` (ADR 0001), so unlike the pure crates this one does
//! not forbid `unsafe_code`. Each module is filled in by one package; see "Layout and ownership" in
//! docs/PLAN.md.

pub mod battery;
pub mod eventlog;
pub mod power;
pub mod processes;
pub mod srum;
pub mod tasks;
