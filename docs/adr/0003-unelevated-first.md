# ADR-0003: Unelevated first, elevate per run through UAC

**Date**: 2026-11-03. **Status**: accepted.

## Context

Most answers work without admin. Live power requests, wake timers, SRUM and Diagnostics-Performance do not. A tool
that always elevates asks for more trust than its reads need.

## Decision

Every command runs unelevated and reports each unavailable source as a typed `Access` value naming what elevation
adds. `--elevate` relaunches the same command once through UAC with `ShellExecuteW` and the `runas` verb, sending
its JSON to a temporary file the parent reads and deletes. Nothing runs elevated in the background.

## Alternatives considered

- **`requireAdministrator` manifest**: simple, but it breaks the "first run works without admin" promise.
- **Installed elevated helper service**: always-on privilege for occasional reads. Too much for v0.1.0.

## Consequences

Elevated output reaches the parent through a file, so that file sits in a per-user temp folder and is deleted after
reading. UAC behavior needs a manual check on real hardware; it cannot run unattended.
