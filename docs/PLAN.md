# pcsleuth v0.1.0 plan

Goal: a Windows 10/11 tool that answers "why did my PC do that" from logs Windows already keeps, plus an
optional bounded recorder for what the logs miss. Evidence and rejected ideas: [RESEARCH.md](RESEARCH.md).
Decisions: [adr/](adr/README.md).

## Product rules

1. **Evidence first.** Every finding carries source, event or record id, timestamp and confidence. If Windows
   did not record the cause, the answer is "Windows did not record this" and names what would capture it. No
   LLM in the core.
2. **Local only.** No network code at all, proven by a test that fails if a network crate or socket API enters
   the tree. No telemetry.
3. **Read-only by default.** Fixes print the exact command. v0.1.0 has no apply path, so it never changes a
   setting. The recorder is the only writer, and only after the user turns it on.
4. **Degrades, never crashes.** Without admin, give partial answers and name exactly what elevation adds.
   Elevate only on request via UAC.
5. **Parse structured data, never display text.** Event `Message` and `powercfg` text are localized, and
   timestamps in `Message` contain invisible direction marks. Use event XML and native APIs.
6. **Both sleep models.** S3 and Modern Standby. Do not rely on Sleep Study or events 506/507 alone.

## Scope

CLI, all with `--json`: `wake`, `nosleep`, `battery`, `crash`, `slow`, `now`, `timeline`, `doctor`.

Desktop app: timeline with answer cards, each card opening its evidence. Keyboard and screen-reader usable.

Recorder: optional, off by default, bounded ring buffer, under 1% CPU on average and a hard disk cap, both
measured and published.

Out of scope: macOS, Linux, LLM explanations, anything cloud, localization beyond English, applying fixes.

## What each question reads

| Question | Without admin | Elevation adds | Honest gap |
|---|---|---|---|
| `wake` | Power-Troubleshooter 1, Kernel-Power 42/107, 506/507 where present, armed devices (`DevicePowerEnumDevices`) | Live wake timers | Hibernate resume usually reports `Unknown`; the firmware does not say |
| `nosleep` | Sleep timeouts (`PowerReadACValueIndex`), `SystemExecutionState` flags, last input, sleep and wake gaps in the log | Live power requests with owners | Past blockers are not logged. Only the recorder keeps them |
| `battery` | Battery report XML: recent usage, energy drains, capacity history, wear | Per-app energy from SRUM | Without SRUM, no app attribution |
| `crash` | Application Error 1000, Application Hang 1002, WER 1001, Kernel-Power 41, EventLog 6008, BugCheck 1001, User32 1074 | Nothing required | Kernel-Power 41 alone often means "power lost, cause unknown" |
| `slow` | Application Hang, Resource-Exhaustion 2004, Kernel-Processor-Power 37, storage warnings | Diagnostics-Performance boot and shutdown culprits, SRUM IO | Past CPU and disk hogs are not logged. Only the recorder keeps them |
| `now` | Top processes by CPU, memory and IO, power source, execution state, armed devices | Live power requests and wake timers | |
| `timeline` | Everything above, merged and sorted | Same | |
| `doctor` | Per source: readable, needs admin, log off, missing, with what each adds | Same | |

## Facts from the first live probe (Windows 11 26300, S3 laptop, uk-UA, unelevated)

- `WakeSourceType` in Power-Troubleshooter 1: 0 Unknown, 1 Power Button, 3 S4 Doze to Hibernate, 5 Device with
  `WakeSourceText` holding the device name. Other values are not seen here. Show them as "type N" until proven.
- `SleepTime == WakeTime` with `TargetState=0` is the S4 doze timer record, not a user-visible sleep.
- `TargetState`: 4 sleep, 5 hibernate. Kernel-Power 42 `Reason=7` went with a 3-hour programmed wake and a later
  hibernate, so `WakeRequesterType=4` marks the doze timer. Confirm before relying on it.
- Kernel-Power 41 `SleepInProgress` is a number in recent event versions, a boolean in old ones. Event versions
  matter: 506 v0-3, 507 v0-12 and 41 v0-10 all differ. Read fields by name and tolerate absent ones.
- User32 1074 `param3` and `param5` are localized. The shutdown versus restart difference exists only in localized
  `param5`, so do not claim it from there. `param4` (reason code), `param1` (process) and `param7` (user) are safe.
- The battery report is UTF-16 on disk.
- `wevtutil` output through a PowerShell pipe mangles non-ASCII text, so `EvtQuery` and `EvtRender` are required.
- Readable unelevated: System, Application, Defender, WindowsUpdateClient, Kernel-Boot, Kernel-PnP,
  Resource-Exhaustion-Detector. Denied: Diagnostics-Performance. Disabled here: TaskScheduler. Empty: Thermal.
- `powercfg /lastwake` said history count 0 even after a real wake, so the log is the source, not that command.
- Elevated, one read-only capture: Diagnostics-Performance gave events 100, 101, 110, 200, 203 (fixtures). `powercfg
  /requests` listed process owners and `/waketimers` listed none. `powercfg /srumutil /csv` worked, unlike unelevated.

**First real check.** Record 360285 (28 Oct 2026, 14:30:33 UTC, 16:30 local) must read as a Power Button wake.
Record 364927 (3 Nov 2026, 12:33:08 UTC, 14:33 local) must read as Unknown, from hibernate. Both are in
`fixtures/eventlog/power-troubleshooter-1.xml`, so a golden test covers them.

## Fixtures

`fixtures/` holds real captures, redacted by [`scripts/capture-fixtures.ps1`](../scripts/capture-fixtures.ps1). Rules:

- Tests read fixtures from there. Never capture into a test at run time.
- Any file with `synthetic` in its name was built by hand from the provider manifest (`ProviderMetadata`), because
  this laptop has no Modern Standby and no bugcheck history. Say so in its test and never count it as real
  validation.
- `user32-1074.xml` and `wer-1001.xml` keep real Ukrainian OS output on purpose. That is the proof of rule 5.
- Real SRUM data is not committed. Tests build a small ESE database with the same schema. A real copy may be used
  through an ignored test and the `PCSLEUTH_REAL_SRUDB` environment variable.

## Layout and ownership

| Work package | Owns | Delivers |
|---|---|---|
| core | `Cargo.toml`, `crates/core`, `crates/cli`, stubs in `crates/sources` and `crates/engine` | Types, JSON contract, CLI skeleton |
| eventlog | `crates/sources/src/eventlog*` | `EvtQuery` to typed events, parsers over fixtures |
| power | `crates/sources/src/{power,battery,tasks}*` | Power requests, wake timers, armed devices, sleep settings, battery report, tasks |
| srum | `crates/sources/src/srum*` | SRUDB reader through ESE, per-app energy, IO, network |
| recorder | `crates/recorder` | Service, ring buffer, measured overhead |
| engine | `crates/engine` | All questions, correlation, confidence, wording |
| app | `app/` | Tauri timeline and evidence view |
| eval | `eval/`, `docs/EVAL.md` | Fault injection, scorer, published numbers |
| release | `.github/`, packaging | CI, installer, checksums, SBOM, no-network test, fixture redaction check |
| docs | `README.md`, `docs/` except EVAL and RESEARCH | README from real output, comparison, launch draft |

Only the core package touches workspace files once it merges. Anyone else needing a new dependency adds it in
the crate they own and says so in the PR. Shared files in `crates/sources` (`lib.rs`, `Cargo.toml`) already declare
every module and Windows feature so parallel work does not collide.

## Order

| Phase | Work | Merge gate |
|---|---|---|
| 0 | Plan, ADRs, fixtures, elevated capture | Redaction check passes |
| 1 | core | Contract reviewed, builds on Linux and Windows for `core` |
| 2 | eventlog, power, srum, eval harness | Parsers green over fixtures, one live read per source |
| 3 | engine, recorder | Golden tests including the first real check, overhead measured |
| 4 | app, release | App runs here with real data, CI green, installer builds |
| 5 | docs, final eval, full review, release | Everything in "Done means" |

At most four packages run at once. Each works in its own worktree, opens a PR and is reviewed before merge.

## Every package must

- Use `CARGO_TARGET_DIR=D:\Projects\pcsleuth\.target` on this machine. D: is an external USB disk, so one shared
  target folder. The user profile path contains `!`, which breaks some tools.
- Pass `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` for what it owns.
- Keep parsers pure over fixtures. Keep OS calls behind `#[cfg(windows)]`.
- Never parse display text. Never panic on bad data from the OS: return a typed access result.
- Prove "works" with a command it ran. Report what it could not verify, including anything that needs admin.
- English only. Commit messages and PRs carry no tool attribution. The repository owner is the sole author.
- Never run an elevated command or a sleep test. Those need the owner's decision.

## Done means

All CLI commands and the app run on a real laptop with real data. `cargo test`, clippy with warnings denied and
the eval pass on CI. Overhead is measured. A GitHub release has the installer and checksums. The README shows
real redacted output, and every claim traces to a command that was run.

## Decisions kept for the owner

Posting Show HN or anything public beyond the repo, submitting to winget, buying code signing, any elevated run,
any sleep test.

## Risks

| Risk | Mitigation |
|---|---|
| No Modern Standby hardware here | Synthetic fixtures from the real manifest, labeled as such. README states S0 is unvalidated on hardware until someone reports |
| CI cannot sleep | Sleep and wake results come from this laptop. `docs/EVAL.md` says which result came from where |
| `SRUDB.dat` copy needs VSS and ESE recovery | ADR 0004. Fall back to "needs admin" or "could not read" with the exact reason, never a crash |
| WebView2 is a browser engine, so "no network code" has an edge | Strict CSP, no remote content, no updater. ADR 0005 states the limit plainly |
| Unsigned installer triggers SmartScreen | README says so. Signing is the owner's decision |
