# ADR-0001: Rust with the official `windows` crate

**Date**: 2026-11-03. **Status**: accepted.

## Context

The tool makes native calls (`EvtQuery`, `CallNtPowerInformation`, `DevicePowerEnumDevices`, ESENT), ships as small
binaries and must not need a runtime on the user's machine. Parsers should run against fixtures without an OS.

## Decision

Rust stable with the official `windows` crate. `crates/core` is pure and builds anywhere. OS calls live behind
`#[cfg(windows)]` in `crates/sources` and `crates/recorder`.

## Alternatives considered

- **.NET 10**: `System.Diagnostics.Eventing.Reader` is convenient, but self-contained output is large and it wraps
  away the native access errors that `doctor` must report.
- **Go**: no first-party Windows bindings for these APIs, and Tauri needs Rust anyway.

## Consequences

Unsafe FFI is confined to `sources` and `recorder` and needs review. `windows` is a heavy dependency, so its features
stay declared in one place, `crates/sources/Cargo.toml`.
