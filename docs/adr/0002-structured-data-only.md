# ADR-0002: Structured data only, never display text

**Date**: 2026-11-03. **Status**: accepted.

## Context

The live probe on a uk-UA system showed localized `param3` and `param5` in User32 1074, localized `Response` in WER
1001, and `wevtutil` output mangled by a PowerShell pipe. Rendered `Message` text also holds invisible direction
marks in timestamps.

## Decision

Sources read `EvtRender` XML by field name, and native APIs. `powercfg` is called only for `/batteryreport /xml`,
which has a schema. Localized fields are carried as opaque text for display and never branched on.

## Alternatives considered

- **`powercfg /requests`, `/waketimers` text**: localized, and they need admin anyway. Used only by hand, to
  cross-check native results.
- **`wevtutil` subprocess**: encoding depends on the console. `EvtQuery` also returns precise access errors.

## Consequences

User32 1074 cannot say shutdown versus restart, since only localized `param5` holds it, so findings use "shut down
or restarted" unless a following event or a reason code settles it. Fixtures keep real localized text to prove this.
