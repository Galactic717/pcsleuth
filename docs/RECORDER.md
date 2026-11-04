# The recorder

The logs do not keep past power requests or past CPU and disk hogs, so `nosleep` and `slow` often have to answer
"not recorded". The recorder keeps them. It is optional, off by default, and writes to one file of a fixed size
that never grows ([ADR 0006](adr/0006-recorder-opt-in.md)). Without it pcsleuth works as before.

## Use

```text
pcsleuth-recorder --foreground            record in this terminal until Ctrl+C; no admin needed
pcsleuth-recorder status                  what the ring holds
pcsleuth-recorder install                 register the Windows service (elevated prompt); does not start it
pcsleuth-recorder install --auto-start    the same, starting at boot
pcsleuth-recorder uninstall               stop and remove the service and delete its ring (elevated prompt)
pcsleuth-recorder --measure 600           run real ticks for 600 s and report the recorder's own cost
```

`--interval SECS` (default 60) and `--ring PATH` work with every command. `run-service` is the entry point the
Service Control Manager starts; run from a terminal it refuses and says to use `--foreground`.

`install` and `uninstall` need an elevated prompt. Without one they print what is needed, change nothing and exit
with code 5. The service is never installed by anything but `pcsleuth-recorder install`, and `install` does not
start it: it prints `sc start pcsleuth-recorder`.

| | `--foreground` | service |
|---|---|---|
| Needs admin | no | to install and uninstall |
| Ring | `%LOCALAPPDATA%\pcsleuth\recorder.ring` | `%ProgramData%\pcsleuth\recorder.ring` |
| Power request owners | not visible, and every row says so | visible (runs as LocalSystem) |
| Stops on | Ctrl+C, Ctrl+Break, closing the console | `sc stop`, shutdown |

## What a row holds

One row per interval: the time, the span the rates cover, the top 5 processes by CPU and the top 5 by IO (name, CPU in
tenths of a percent of the whole machine, IO bytes per second), and every live power request (owner, kind, reason).
These are `pcsleuth_core::RecorderRow` values, built from `processes::sample` and `processes::top` and from
`power::power_requests`, the same sources `now` uses.

**Power requests need admin.** Without it `power_requests` returns `NeedsAdmin`. The row is still written, with
`requests_visible = false`, so a reader never takes an empty list for "none held". `RecorderRow` has no field for this,
so the ring keeps it next to the row (`Sample`) and `read_rows` reports it through `Access::Partial` (see
[API](#library-api)).

`interval_secs` in a row is the span the rates really cover, not the configured interval. If the machine slept between
two ticks the span is long and the rates are averages over it; a finding built from such a row must say so. Anything
shorter than the span can be missed, which is why recorder evidence is `Confidence::Sampled`.

## The ring file

One file, created at its full size and never resized. All numbers are little endian.

```text
block 0        header (48 bytes used): magic "PCSLRING", version 1, slot size 1024, slot count, interval,
               created, next sequence number (the write position), CRC-32 of the above
blocks 1..=N   slots of 1024 bytes: CRC-32, payload length, flags, sequence number, payload, zero padding
```

Sample number `seq` (from 1) lives in slot `(seq - 1) % N`, so the oldest sample is overwritten only after N newer
ones, and a write never lands outside the file. Names, owners and reasons are length-prefixed; the longest are 32, 40
and 80 bytes. A longer one is cut at a character boundary and ends with `…`, and the slot's `truncated` flag is set.
Power requests that do not fit in a slot's payload are dropped from the end and the slot is flagged the same way.

| Size | Slots | History at 60 s | At 30 s | At 5 s |
|---|---|---|---|---|
| 16 MiB (default) = 16 777 216 bytes | 16 383 | 11.38 days | 5.69 days | 22.75 hours |

That is 16 383 x 60 s = 982 980 s, computed, not measured. Each tick writes one 1024-byte slot and a 48-byte header
update, 1072 bytes, which is about 1.5 MB a day at the default interval.

**Damage is skipped, never fatal.** A slot is used only if its checksum is right, it fits its block, and its sequence
number belongs in that slot. Anything else that is not all zero (a torn write, a flipped bit, a block in the wrong
place) is skipped and counted, and the reader returns `Access::Partial` saying how many. A file that is shorter than its
header says counts the missing slots the same way. A file with the wrong magic or version, or a damaged header, is an
`Access::Failed`, not a panic. A writer opening an existing ring takes the highest valid sequence number from the
slots, not from the header, so a crash between the slot write and the header write loses nothing and a torn slot is
overwritten in place. A writer refuses a file that is not a ring (wrong magic or another version) and leaves it
untouched; a damaged ring of its own, or one of the wrong length, is formatted afresh.

## Library API

`pcsleuth_recorder`, for the engine:

| Function | Returns |
|---|---|
| `default_ring_path()` | the service's ring if it exists, else the user's. `service_ring_path()` and `user_ring_path()` give each |
| `read_rows(path, since)` | `Sourced<RecorderRow>`, oldest first, rows at or after `since` |
| `read_samples(path, since)` | `Sourced<Sample>`: the same rows with `requests_visible` and `truncated` |
| `status(path)` | `Sourced<Status>`: size, slots, interval, rows, skipped, oldest, newest, how many rows lack request visibility |

No ring file is `Access::Missing` and a folder the caller cannot read is `Access::NeedsAdmin`, never an error. Damaged
slots give `Access::Partial` with their count. `read_rows` also gives `Partial` when some rows were recorded without
admin, because `RecorderRow` cannot carry that per row. **The engine should use `read_samples` for `nosleep`**, where an
empty `power_requests` in a row with `requests_visible == false` must never be read as "nothing held". A follow-up in
`pcsleuth-core` could add `requests_visible` to `RecorderRow` and make `read_samples` unnecessary.

## Who can read the ring

The ring holds process names and the reasons programs give for power requests. The service's folder is created by
`install` with a protected permission list (nothing inherited from `%ProgramData%`): full control for SYSTEM,
Administrators and the SID of the user who ran `install`, and nobody else. The ring inherits it. `install` creates the
folder with that list before it creates the service, so the ring never exists in a readable place. `--foreground` keeps
its ring under the user's own `%LOCALAPPDATA%`. `uninstall` deletes the ring and the folder. A foreground ring is not
touched by `uninstall`; delete it by hand.

## Behaviour that matters for cost

- It waits in a kernel wait between ticks (`recv_timeout` on a channel), so an idle recorder uses no CPU and Ctrl+C or a
  service stop wakes it at once. A test shows a second of ticks costs under 60 ms of thread CPU, where a busy wait would
  cost a second.
- It does not change the system timer resolution and never calls `SetThreadExecutionState`, so it never keeps the machine
  awake. A machine that sleeps has no ticks while it sleeps.
- The sampling thread runs in `THREAD_MODE_BACKGROUND_BEGIN`: lowest CPU, IO and memory priority.
- Ticks fall on a fixed grid. After a long tick or a resume from sleep it skips the ticks it missed rather than running
  them in a burst.
- A process list that cannot be read skips that tick; a failed write is counted and the next tick tries again.

## Overhead

Budget: under 1% CPU of the whole machine on average, and a hard disk cap (the file size, above). **Both met, by a
wide margin, in the runs below.**

### Method

`pcsleuth-recorder --measure SECS --interval SECS` runs the production loop for a stated time: the same
`processes::sample` and `top`, the same `power::power_requests`, the same ring writes, the same background thread
priority. The window starts after the process has started, the 16 MiB ring exists and the baseline sample is taken,
so it covers steady state; those one-off costs are outside it. It reports, for the window only:

- CPU: the process's kernel plus user time from `GetProcessTimes`, before and after, divided by wall time (`Instant`)
  times the number of logical processors. That is a percentage of the **whole machine**, so one core fully busy on this
  20-processor machine reads 5%.
- Time inside ticks: wall time spent reading, ranking and writing. On one thread the CPU used cannot exceed it, so it is
  an upper bound for the same quantity, and unlike `GetProcessTimes` it is not read in scheduler steps.
- Peak working set (`GetProcessMemoryInfo`, whole process life, so it includes start up).
- Bytes written: by the ring writer, and by the process in all (`GetProcessIoCounters`, every kind of write).

Limits of the method: the kernel accounts process CPU in steps of 15.625 ms, so the CPU figures below are multiples of
it (14 and 56 steps) and are good to about one step; the upper bound is the tighter figure. A run that spans a sleep
would show a local clock time longer than the window, so each run also records the local clock before and after.

### Machine

Intel Core i7-12700H (14 cores, 20 logical processors), 15.7 GB RAM, Windows 11 Home build 26300, ring file on the
internal NVMe SSD (the system drive), balanced power plan, **running on battery**, the recorder **not elevated**. The
machine was in ordinary use during the runs (an editor and a coding assistant were open) and no build or test was
running. Release build (`cargo build --release -p pcsleuth-recorder`).

### Results, measured on 4 November 2026

| | 60 s interval (default) | 5 s interval (stress) |
|---|---|---|
| Window (wall clock) | 900.029 s (local clock: 900.6 s) | 300.017 s (local clock: 300.1 s) |
| Ticks, rows written | 15, 15 | 60, 60 |
| CPU used (`GetProcessTimes`) | 218.8 ms = **0.0012%** of the machine | 875.0 ms = **0.0146%** of the machine |
| Time inside ticks (upper bound) | 334.7 ms = 0.0019% | 1408.5 ms = 0.0235% |
| Slowest tick | 39.7 ms | 32.9 ms |
| Peak working set | 7.2 MiB | 6.7 MiB |
| Bytes written to the ring | 16 080 (15 x 1 072) | 64 320 (60 x 1 072) |
| Bytes written by the process in all | 16 080 | 64 320 |

The raw output of the two runs (only the ring path line is shortened, because the real one holds a user name):

```text
Measuring for 900 s at a 60 s interval (real ticks, real ring writes). ...
ring file:               %LOCALAPPDATA%\pcsleuth\measure.ring (16777216 bytes)
elevated:                false
logical processors:      20
interval:                60 s
window (wall clock):     900.029 s
ticks:                   15 (15 rows written, 0 with power requests visible)
CPU used (GetProcessTimes): 218.8 ms = 0.0012% of the whole machine
time inside ticks:       334.7 ms = 0.0019% of the whole machine (upper bound), slowest tick 39.7 ms
working set:             6.6 MiB now, 7.2 MiB peak of the process
bytes written:           16080 to the ring, 16080 by the process in all

Measuring for 300 s at a 5 s interval (real ticks, real ring writes). ...
ring file:               %LOCALAPPDATA%\pcsleuth\measure.ring (16777216 bytes)
elevated:                false
logical processors:      20
interval:                5 s
window (wall clock):     300.017 s
ticks:                   60 (60 rows written, 0 with power requests visible)
CPU used (GetProcessTimes): 875.0 ms = 0.0146% of the whole machine
time inside ticks:       1408.5 ms = 0.0235% of the whole machine (upper bound), slowest tick 32.9 ms
working set:             6.1 MiB now, 6.7 MiB peak of the process
bytes written:           64320 to the ring, 64320 by the process in all
```

Both runs agree on the cost of one tick: about 14.6 ms of CPU (218.8 / 15 and 875.0 / 60) and about 22 to 23 ms of wall
time, because the thread runs at background priority. Cost scales with the number of ticks, so the default interval is
12 times cheaper than the stress case. The worst case measured, 0.0235% as an upper bound at 5 s, is 43 times under the
1% budget; the default is over 500 times under.

### What the numbers do not cover

- **Elevated cost.** Both runs were unelevated, where the power request read fails at once with access denied. Elevated,
  each tick also lists and parses the live power requests, and the service runs as LocalSystem, which can open more
  processes than a user can. Neither was measured. The budget is 1% of 20 processors, which is 0.2 core-seconds per
  second: 12 s of CPU per tick at the default interval, 1 s per tick at 5 s (computed from the budget, not measured).
  A tick is about 14.6 ms, so elevation would have to multiply it by hundreds to reach the budget. Run `--measure`
  elevated to put a number on it.
- **The service host.** `--measure` runs the same loop as the service, not the service itself.
- **Disk wear.** The ring writer wrote 1 072 bytes a tick. What the drive does with that (sector size, write caching) was
  not measured.
- **Battery.** No battery draw was measured, only CPU time.
- **One machine.** A machine with many more processes spends longer per tick (the process list is the cost).

## What is verified and what is not

Written without administrator rights and without installing anything, so the service paths could not be run.

**Verified, by commands that were run:**

- `cargo test -p pcsleuth-recorder`: the ring (wrap-around, torn write, damaged and misplaced slots, a short file, wrong
  magic and version, a damaged header, truncation, a seeded fuzz of the decoder, and a real file whose size is
  byte-identical after about 31 wraps), the sample mapping, the loop, the reading API, and the Windows pieces that need no
  admin: the SID lookup, the protected folder (a new folder and an existing open one both end with exactly SYSTEM,
  Administrators and the user, protected, and a file inside inherits them), and a second of waiting costing under 60 ms
  of thread CPU.
- The real binary, unelevated: `install` and `uninstall` refuse with exit code 5, say what is needed and change nothing
  (no service, no folder); `run-service` from a terminal is refused and points to `--foreground`; `status` of a missing
  ring says so.
- `--foreground` for real (`-- --ignored console`, which sends Ctrl+Break): it recorded, stopped cleanly on Ctrl+Break
  with exit code 0, `status` and `read_rows` read back what it wrote, rows said power requests were not visible, and the
  file was exactly 16 777 216 bytes.
- `--measure`, as above.

**Not verified, because it needs administrator rights:**

- `run-service` as the Service Control Manager starts it: registering the handler, reporting start, running and stop, and
  stopping on `sc stop` and on shutdown.
- `install`: creating the service (manual or auto start, LocalSystem), its description, and the folder under
  `%ProgramData%` (the folder code itself is verified above, in a temp folder).
- `uninstall` stopping a running service, deleting it, the ring and the folder.
- Power request owners actually appearing in rows when the recorder is elevated (the parser is the one in
  `pcsleuth-sources`, whose layout is itself unverified until its own elevated test has run).
- The overhead of an elevated tick.

`crates/recorder/tests/elevated.rs` covers these. Its tests are ignored by default and refuse to run unless elevated.
One of them installs, starts, stops and removes the real service, so run it only with the machine owner's permission:

```text
cargo test -p pcsleuth-recorder --test elevated -- --ignored --test-threads=1 --nocapture
```

It checks that the service installs for manual start as LocalSystem and is not running, that the folder permissions are
the intended three, that a second `install` is refused, that after `sc start` rows appear with power requests visible,
that `sc stop` ends it with the file at its full size, and that `uninstall` leaves no service, ring or folder.
