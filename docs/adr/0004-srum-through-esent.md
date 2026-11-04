# ADR-0004: Read SRUM through esent.dll on a shadow copy

**Date**: 2026-11-03. **Status**: accepted. Confirmed on 2026-11-04 against a real copy from this laptop, except the
elevated snapshot step, which has not been run (see "Not verified").

## Context

`SRUDB.dat` is an ESE database locked by a running service, and access is denied without admin. `powercfg /srumutil`
failed unelevated with 0x1f and works elevated (13 MB of CSV here), but it covers energy only. Per-app IO and network
exist nowhere else. An `esentutl /vss` copy on this laptop reports `Dirty Shutdown`, so log replay on the copy is
required.

## Decision

When elevated, copy the database and its logs with the built-in `esentutl /y <file> /vss /d <temp>`, replay logs if
the copy is dirty, then read it with the ESENT API in `Win32_Storage_Jet` opened read-only. Delete the copy after.

## Alternatives considered

- **Pure Rust ESE parser or libesedb bindings**: runs off Windows, which we do not need, and adds third-party code
  parsing a complex format. `esent.dll` ships with every target and always matches the format.
- **`powercfg /srumutil /csv`**: elevated only, energy only, undocumented columns. Useful as a cross-check of what the
  ESE reader returns, not as the source.

## Consequences

Tests build a small ESE database with the same schema at run time, so no personal usage data is committed. Anything
this path cannot do degrades to a typed reason. A real copy is validated by an ignored local test.

### What worked on the real copy (Windows 11 build 26300)

The copy was a `Dirty Shutdown` file: page size 4096, 64 KB log files with the base name `SRU`, one log generation
required, and `SRU.log` holding it. The logs record the live path `C:\WINDOWS\system32\SRU\`.

- **Log replay on the copy works two ways, both on a copy only.** `esentutl /r SRU /l<dir> /s<dir> /d<dir>` took 0.8 s
  and left `Clean Shutdown`. The same through ESENT in process is what the reader does: `JetInit` with
  `JET_paramRecovery` on, `JET_paramBaseName` `SRU`, system and log path set to the copy's folder,
  `JET_paramAlternateDatabaseRecoveryPath` set to the copy's folder, then a clean `JetTerm`. The alternate recovery path
  (`/d` in esentutl) is the part that matters: without it replay targets the path recorded in the logs, the live
  database. Replay rewrites the copy and adds log files beside it, so `read_usage` requires a copy it may modify.
- **Page size and log size must match the files.** Page size is read from the database header with
  `JetGetDatabaseFileInfo(JET_DbInfoPageSize)` and the log size from the length of `SRU.log`. The page size is a
  process-wide ESE parameter, so the reader keeps one ESE instance at a time behind a lock.
- **Dirty or clean is read from the header** (`JET_DbInfoMisc`, `dbstate`), so a clean copy is never replayed.
- **Reading a clean copy writes nothing beside it.** The instance runs with recovery off, the database is attached and
  opened with `JET_bitDbReadOnly`, and the temporary database goes to a per-run folder under the system temp dir that is
  deleted afterwards. A test checks that the folder listing and the file bytes are unchanged after a read.
- **No Windows event log noise.** `JET_paramEventLoggingLevel` is 0 and `JET_paramNoInformationEvent` is set, so
  replay and reads do not write ESENT events to the Application log.
- **The cursor calls need the `Win32_Storage_StructuredStorage` feature** of the `windows` crate, not only
  `Win32_Storage_Jet`, because `JET_TABLEID` lives there. It is added to `crates/sources/Cargo.toml`.
- Replay plus a full read took 6.7 s here, 176,873 hour buckets.

### Schema found

`SruDbIdMapTable` maps ids to names: `IdType` 0 and 1 are NUL-terminated UTF-16 (executable paths, `!!name!date!`
forms, service names), 2 is a package family name, 3 is a binary SID. The reader decides by the shape of the bytes, not
`IdType`, and treats the empty entries at ids 1 and 2 as unnamed.

| Table | Content | Notes |
|---|---|---|
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | app resource usage | foreground and background cycle time, bytes read and written, as 64-bit counters |
| `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | network usage | `BytesSent`, `BytesRecvd`, one row per interface |
| `{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}` | energy estimation | **one packed `BinaryData` blob per row, no energy columns** |
| `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` and `LT` | battery charge and capacity | not per app, not read yet |
| `{5C8CF1C7-7257-4F13-B223-970EF5939312}` | app timeline | not read yet |

`TimeStamp` is an OLE date of the write, at arbitrary minutes, not the top of an hour (only 910 distinct values over 60
days in the resource table). The reader floors readings to the UTC hour. Several rows can share an app, user and time
(one per interface, one per power state), so they are summed.

The energy blob layout is not documented. It is a 32-byte header (flags with on-battery, screen, battery saver,
foreground and interactivity bits; duration; two presence masks; energy loss) followed by one 64-bit value per mask bit.
The layout, with the mask bits, is in `crates/sources/src/srum/energy.rs`. A mask bit the decoder does not know makes the
record unreadable, so it is counted in a note and left out of the sums, never guessed.

### Energy checked against `powercfg /srumutil /csv` from the same machine

All 46,015 blobs have a recognized layout. Lined up in order by duration, 45,596 blobs matched a CSV row and every
energy column of every matched row agreed exactly. `TotalEnergyConsumption` is the components plus the energy loss; the
work-on-behalf and attributed values break CPU down and are not added again. The CSV is written a little after the
shadow copy and has 6,130 more rows from its last day, so the comparison covers whole days before that day:

- total energy: 8,793,173,291 from the reader and from the CSV, equal;
- energy on battery: 1,660,615,604 from both, equal;
- per app: 1,426 of the 1,426 apps that have the same name in both agree exactly (the CSV spells apps with non-ASCII
  names differently, so 12 names cannot be paired);
- the top app: 3,524,492,664 from both.

The values are SRUM's own units, the same numbers `powercfg` prints. They are not documented. Summed over all apps an
active hour comes to about 1e8, which fits millijoules (about 25 W), but that is inferred.

### Not verified

- **The elevated snapshot (`snapshot_copy`)** has not been run, because it needs an elevated process. Verified without
  admin: the argument shape `esentutl /y <file> /d <copy>` copies a file; the replay and read path on a copy of the
  elevated capture; the not-elevated answer (`Access::NeedsAdmin` without trying). Not verified: `/vss` itself, listing
  `C:\Windows\System32\SRU` when elevated, and replay on a copy made by this code. The ignored test
  `elevated_srum_snapshot` covers it for whoever has the owner's permission.
- **Each file is copied by its own `esentutl` call, and each call makes its own shadow copy** (the owner's capture shows
  one volume shadow copy per file), taking several seconds each. The database goes first, then the logs, so every log is
  at least as new as the database. The checkpoint file `SRU.chk` is not copied: a checkpoint from a later snapshot than
  the database could start replay too late, and replay without one starts from the oldest log copied.
- Energy units, and the mask bits for MBB, NPU and other energy, which never appeared in this database.
