# ADR-0004: Read SRUM through esent.dll on a shadow copy

**Date**: 2026-11-03. **Status**: accepted, to be confirmed by the srum package against a real copy.

## Context

`SRUDB.dat` is an ESE database locked by a running service, and access is denied without admin. `powercfg /srumutil`
failed here with 0x1f, cause not established. Per-app energy and IO exist nowhere else.

## Decision

When elevated, copy the database and its logs with the built-in `esentutl /y <file> /vss /d <temp>`, replay logs if
the copy is dirty, then read it with the ESENT API in `Win32_Storage_Jet` opened read-only. Delete the copy after.

## Alternatives considered

- **Pure Rust ESE parser or libesedb bindings**: runs off Windows, which we do not need, and adds third-party code
  parsing a complex format. `esent.dll` ships with every target and always matches the format.
- **`powercfg /srumutil /csv`**: failed on the only machine tested, and its column set is undocumented.

## Consequences

Tests build a small ESE database with the same schema at run time, so no personal usage data is committed. Anything
this path cannot do degrades to a typed reason. A real copy is validated by an ignored local test.
