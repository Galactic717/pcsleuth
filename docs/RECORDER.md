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
pcsleuth-recorder reset                   throw away a damaged ring's history and start a new one
pcsleuth-recorder --measure 600           run real ticks for 600 s and report the recorder's own cost
```

`--interval SECS` (default 60) and `--ring PATH` work with every command. `run-service` is the entry point the
Service Control Manager starts; run from a terminal it refuses and says to use `--foreground`.

`install` and `uninstall` need an elevated prompt. Without one they print what is needed, change nothing and exit
with code 5. The service is never installed by anything but `pcsleuth-recorder install`, and `install` does not
start it: it prints `sc start pcsleuth-recorder`.

**`install` only accepts a program file under `C:\Program Files`.** The service runs as SYSTEM, so whoever can replace
its program file can run code as SYSTEM at its next start. A copy in a build folder, Downloads or `%LOCALAPPDATA%` is
writable by any program running as you. So copy `pcsleuth-recorder.exe` into a folder under Program Files (for example
`C:\Program Files\pcsleuth\`) from an elevated prompt, and run `install` from that copy. Program Files is found with the
shell's known-folder call, not an environment variable, and both paths are resolved first, so a junction, `..` or a
change of case does not get a program from elsewhere past it. `install` exits with code 6 and creates nothing otherwise.
It trusts Windows' default that only administrators can write under Program Files; it does not inspect the permissions
of the folders in between.

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
`requests_visible = false` (a field of `RecorderRow`), so a reader never takes an empty list for "none held". Such a row
is still a good sample of CPU and IO, so reading it is `Access::Ok`. The engine's `nosleep` counts only rows that could
see requests, and when none could it says "could not see power requests in any of them. That says nothing about what was
held" and that the recorder needs to run as admin.

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
overwritten in place.

**History is never thrown away silently.** A writer refuses, with the reason and without touching the file, anything
that is not a healthy ring: wrong magic, another version, a damaged header, or a length that is not what the header says.
`--foreground` prints the reason and the command to start over; the service stops with error code 13 (see
`sc query pcsleuth-recorder`), and `pcsleuth-recorder status` shows the reason. Only `pcsleuth-recorder reset` starts a
new ring, and it still refuses a file that is not a ring of this program, so it cannot wipe an unrelated file. It needs
the recorder stopped (the ring is open for writing while it runs) and, for the service's ring, an elevated prompt.
The sequence number never wraps: a ring whose newest slot holds the largest value is refused for writing until reset.

**The writer holds the ring open for reading only by others.** It shares the file for reading and not for writing or
deleting, so the ring cannot be deleted or renamed out from under it (it would go on writing to a file nobody can
reach), a second recorder cannot open the same ring, and readers such as `status` and the engine still can.

## Library API

`pcsleuth_recorder`, for the engine:

| Function | Returns |
|---|---|
| `default_ring_path()` | the service's ring if it is there (also when this user may not look at it, which then reads as `NeedsAdmin`, not `Missing`), else the user's. `service_ring_path()` and `user_ring_path()` give each |
| `read_rows(path, since)` | `Sourced<RecorderRow>`, oldest first, rows at or after `since`. The only reader; each row carries `requests_visible` |
| `status(path)` | `Sourced<Status>`: size, slots, interval, rows, skipped, oldest, newest, how many rows lack request visibility, and `newest_age(now)` / `looks_stopped(now)` (the newest row is older than three intervals and a minute, so the recorder is probably not running, or the machine slept) |

No ring file is `Access::Missing` and a folder the caller cannot read is `Access::NeedsAdmin`, never an error. Damaged
slots give `Access::Partial` with their count. Rows recorded without admin do **not** make a read partial: each says in
`requests_visible` that its empty `power_requests` means "not visible", and whoever reads power requests must check it.

The engine reads the ring in its gather step (`pcsleuth_recorder::read_rows(&default_ring_path(), since)`), for `nosleep`
and `slow`, and `doctor` reports the recorder's access from the same read.

## Who can read the ring

The ring holds process names and the reasons programs give for power requests. The service's folder is created by
`install` with a protected permission list (nothing inherited from `%ProgramData%`): full control for SYSTEM and
Administrators, and **read only** for the SID of the user who ran `install`, and nobody else. The ring inherits it. The
user reads their own history but cannot write, rename or delete in a folder that SYSTEM writes in; with full control,
their unelevated processes could swap the folder for a junction and steer SYSTEM's writes. The folder is found with the
known-folder call, not `%ProgramData%`. `install` creates the folder with that list before it creates the service, so the
ring never exists in a readable place, but only after it has checked that no service of that name exists, so a refused
second install changes nothing.

An existing `%ProgramData%\pcsleuth` is **not trusted**: `install` uses it only if it is a real folder, not a link, owned
by Administrators or SYSTEM. Otherwise another user could have made it first and kept control of it, or made it a
junction so that replacing its permissions rewrote those of a folder somewhere else. It is refused untouched, with the
reason and what to do. `--foreground` keeps its ring under the user's own `%LOCALAPPDATA%`. `uninstall` deletes the ring
and the folder. A foreground ring is not touched by `uninstall`; delete it by hand.

## Behaviour that matters for cost

- It waits in a kernel wait between ticks (`recv_timeout` on a channel), so an idle recorder uses no CPU and Ctrl+C or a
  service stop wakes it at once. A test shows a second of ticks costs under 60 ms of thread CPU, where a busy wait would
  cost a second.
- It does not change the system timer resolution and never calls `SetThreadExecutionState`, so it never keeps the machine
  awake. A machine that sleeps has no ticks while it sleeps.
- The sampling thread runs in `THREAD_MODE_BACKGROUND_BEGIN`: lowest CPU, IO and memory priority.
- Ticks fall on a fixed grid. After a long tick or a resume from sleep it skips the ticks it missed rather than running
  them in a burst.
- A process list that cannot be read skips that tick, and a failed write is counted and tried again at the next tick.
  After **three failed ticks in a row** (either kind) it gives up instead of staying up and recording nothing: the
  service reports STOPPED with the error code of the last failure (`sc query pcsleuth-recorder` shows it as
  WIN32_EXIT_CODE, and the Service Control Manager logs it), and `--foreground` prints it and exits with code 1. A
  good tick in between starts the count again.
- `--measure` deletes its ring only if it created it. Given the path of an existing ring with `--ring`, it adds its rows
  (real samples) to it and leaves it in place.

## Known limits

Found in review and not fixed yet:

- **Wall-clock steps are not flagged.** Rates are computed over the wall-clock time between two samples. If the clock is
  set backwards, the next row is dropped without a count; if it jumps forwards or backwards by hand or by time sync, the
  row's `interval_secs` and rates are skewed, and a time-filtered read (`since`) can drop rows whose time went backwards.
  A sleep is not a step: the row says it covers the whole gap. A fix would compare the wall clock with a monotonic one
  per tick, count the disagreements, and flag the slots.
- **A service that cannot register its control handler reports nothing.** If `RegisterServiceCtrlHandlerExW` fails there
  is no status handle to report through, and the Service Control Manager only times out. The results of
  `SetServiceStatus` are not checked either. Both are start-up failures of the Windows service machinery, not seen in
  practice, and neither loses data. A fix would carry the error out of `service_main` so that `run-service` exits
  with it.

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
  magic and version, a damaged header or wrong length refused with the history untouched and `reset` as the only way
  out, truncation, the largest sequence number refused, a seeded fuzz of the decoder, and a real file whose size is
  byte-identical after about 31 wraps), a real ring that cannot be deleted, renamed or opened by a second writer while
  open but can be read, the sample mapping, the loop (three failed ticks in a row end it with the error code, a good tick
  resets the count), the reading API (including a ring this user may not open reading as `NeedsAdmin`, not missing, and
  the staleness hint), and the Windows pieces that need no admin: the SID lookup, the Program Files check (paths
  outside it, siblings like `Program Files (x86)`, `..` and case), the protected folder (SYSTEM and Administrators full,
  the user read only: the user can list it and cannot write in it), an existing folder owned by the user or a junction in
  its place refused with its target's permissions unchanged, and a second of waiting costing under 60 ms of thread CPU.
- The real binary, unelevated: `install` and `uninstall` refuse with exit code 5, say what is needed (and that a build
  folder is not an acceptable place) and change nothing (no service, no folder); `run-service` from a terminal is
  refused and points to `--foreground`; `status` of a missing ring says so; a damaged ring is refused by `--foreground`
  with the reason and left byte-identical until `reset`; `--measure` leaves an existing ring in place.
- `--foreground` for real (`-- --ignored console`, which sends Ctrl+Break): it recorded, stopped cleanly on Ctrl+Break
  with exit code 0, `status` and `read_rows` read back what it wrote, rows said power requests were not visible, and the
  file was exactly 16 777 216 bytes.
- `--measure`, as above.
- Through the engine, with a ring from a real `--foreground` run (6 rows at a 2 s interval, unelevated, process ended
  with `Stop-Process`): `pcsleuth nosleep --since 1h` read it and said the recorder "took 6 recorder samples in this
  period, but it was not running as admin, so it could not see power requests in any of them. That says nothing about
  what was held", with "the pcsleuth recorder running as admin (the installed service does)" as what would capture it;
  `pcsleuth doctor` showed the recorder as readable. With no ring it said the recorder was missing. A Sampled finding
  from the recorder needs rows that could see requests (an elevated recorder); the engine tests cover that path with
  built rows, not a real elevated recording.

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

It copies the recorder into a new folder under Program Files (the only place `install` accepts) and removes it
afterwards. It checks that `install` from the build folder is refused with exit code 6, that the service installs from
the copy for manual start as LocalSystem and is not running, that the folder permissions are the intended three, that a
second `install` is refused without changing the folder's permissions, that after `sc start` rows appear with power
requests visible, that `sc stop` ends it with the file at its full size, and that `uninstall` leaves no service, ring or
folder. Not covered even there: the service stopping with an error code after three failed ticks (covered by the loop
test, not by a real disk failure).
