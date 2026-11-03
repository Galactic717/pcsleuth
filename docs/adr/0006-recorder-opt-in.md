# ADR-0006: Recorder as an opt-in process with a fixed-size ring file

**Date**: 2026-11-03. **Status**: accepted, overhead budget to be confirmed by measurement.

## Context

Logs do not keep past power requests or past CPU and disk hogs, so `nosleep` and `slow` must often say "not recorded".
A recorder fixes that, but it must be off by default and its cost must be small, bounded and published.

## Decision

`pcsleuth-recorder` samples at a fixed interval into one preallocated ring file with a hard size cap, so disk use
never grows after creation. It runs in the foreground with no admin (`--foreground`, which is also how overhead is
measured) or as a Windows service the user installs through UAC, which adds power request owners. Budget: under 1% CPU
on average, and the disk cap is the file size.

## Alternatives considered

- **ETW session**: precise, but needs admin always and has heavier tooling.
- **SQLite**: adds a dependency, and growth has to be managed by hand. A ring of fixed-size records cannot grow.
- **Scheduled task**: no benefit over a service, and it runs in a harder-to-control context.

## Consequences

Sampling can miss short events, so recorder evidence has lower confidence than a logged event and states its sampling
interval. The ring file holds process names, so it stays in a folder only the user and administrators can read, and
uninstall deletes it.
