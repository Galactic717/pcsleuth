# Evaluation

How pcsleuth is scored, how to reproduce it, and what has been measured so far. Every number here comes from a
run described in [Results](#results), with where it ran. Nothing is estimated. Code: `eval/`.

## Method

The harness creates a fault whose cause is known, asks pcsleuth the question a user would ask, and checks whether
the answer names that cause. It scores attribution, not wording. It reads `pcsleuth <question> --json` and never
the text.

1. **Inject.** A small program named `pcsleuth-fault-*.exe` creates one fault (a power request, a CPU hog, a
   crash) and exits by itself. Its exe name is the true cause.
2. **Ask.** `pcsleuth <question> --json --since <just before the injection>`.
3. **Score.** A pure function compares the answer with what is known (see [Scoring](#scoring)).

Two kinds of scenario matter equally:

- **Observable**: Windows records the cause where an unelevated read finds it. A good tool names it.
- **Not observable**: Windows does not record it, or hides it without admin. A good tool says so. This is the
  product's core promise ("Windows did not record this"), so it is scored, not assumed.

An honest tool that answers "not recorded" to everything would get every honesty point and find nothing. So the
two are always reported side by side, and honesty earns nothing from a placeholder answer (see below).

## The attribution contract

This is what the engine must emit for a finding to count. It is the only thing the scorer reads.

| Field | Meaning |
|---|---|
| `Evidence.fields["process"]` | The exe name of the process the finding blames, such as `chrome.exe`. Compared case-insensitively; a directory and a trailing `.exe` are ignored. |
| `Evidence.fields["device"]` | The name of the device the finding blames, compared case-insensitively. |
| `Evidence.record_id` | For event log evidence, the `EventRecordID` as a decimal string. |
| `Evidence.timestamp` | When the evidence happened, for evidence that has no record id. |

Rules the scorer applies:

- Only a **confident** finding can name a cause: confidence `recorded`, `correlated` or `sampled`. A
  `not_recorded` finding has no evidence by construction, so it cannot.
- When the scenario produced an event, it knows the record ids. A finding counts only if the evidence naming the
  cause **cites one of those ids**. The same exe naming an older record does not count, and is a false
  attribution. This is why a crash finding is matched to the right event and not to an earlier run of the same
  program.
- Without record ids, evidence with a `timestamp` older than the injection does not count.
- "Admits a gap" means any `not_recorded` finding, any finding carrying a gap note (`Finding::with_gap`), or, when
  the scenario names one, a `limits` entry for the relevant source (for example `power_requests`). The scorer
  does not read prose.

Process and device are the only attributions today. If a scenario needs another kind, it is added here first.

## Scoring

| Outcome | When | Points |
|---|---|---|
| `true_positive` | A confident finding names the right cause on the right record | +1 |
| `honest` | Not observable, and the answer says so (not-recorded finding, gap note or the relevant limit) | +1, but 0 if every finding is a `*.not_implemented` placeholder |
| `miss` | Observable, and no cause named | 0 |
| `silent` | Not observable, and the answer neither named a cause nor admitted a gap | 0 |
| `false_attribution` | A confident finding names a different cause, or the right one on the wrong record, and the right one is nowhere in the answer | -1 |
| `unverified` | Observability is not known until real hardware, and nothing was named | not counted |
| `not_run` | The scenario could not run; the reason is recorded | not counted, never a pass |

A confident wrong answer is the only negative, so it always ranks below "unknown". If the right cause is in the
answer, extra confident findings naming other things do not change the outcome, but they are counted (`extras`) and
shown, so an answer that lists everything is visible.

The headline is two ratios and a count, never one blended number: **found** (observable scenarios that were
named), **honest** (unobservable scenarios that said so) and **false attributions**.

A `*.not_implemented` finding is the stub the engine returns before it reads any log. It is a not-recorded finding,
so it is `honest` for an unobservable scenario by the rules above. It says nothing about the limit, so the summary
counts it as `honest_by_placeholder` and gives no points for it.

## Injectors

All are bounded in time, need no admin, change no setting, and print `ready` on stdout once the fault is active.
`--secs N` is clamped to 1..600 whatever it is given, and Ctrl+C ends them early.

| Exe | Fault | Bounds and cleanup |
|---|---|---|
| `pcsleuth-fault-power-request` | `PowerCreateRequest` + `PowerSetRequest(PowerRequestSystemRequired)`: blocks idle sleep | Default 30 s. Clears and closes the request; Windows also drops it on exit |
| `pcsleuth-fault-wake-timer` | `SetWaitableTimer` with the resume flag, 7 days ahead, so it never wakes anything | Default 30 s. Cancels and closes the timer. Reports an error if the PC cannot resume from a timer. `--fire-in N` (sleep scenarios only) sets it N seconds ahead |
| `pcsleuth-fault-cpu` | Busy threads | Default 20 s. At most 4 threads and never more than half the logical cores |
| `pcsleuth-fault-disk` | Paced `write` + `sync_data` | Default 20 s, 256 MiB total, 32 MiB/s. Hard caps 1024 MiB and 256 MiB/s. Writes only under `%TEMP%\pcsleuth-fault-disk-<pid>`, deleted on exit, and deleted again by the runner if the hog was killed first |
| `pcsleuth-fault-crash` | `RaiseException(0xC0000005)` with no handler: Application Error 1000 | Exits after 1 s |
| `pcsleuth-fault-hang` | A visible window whose thread stops pumping messages: Application Hang 1002 (see below) | Default 60 s |

What was verified about them, on the laptop described under Results:

- The crash injector produced Application Error 1000 for its own exe, with its own process id and exception code
  `c0000005`, about 2 s after the crash.
- The CPU hog used 20 CPU-seconds in about 5 s of wall time: 4 threads on a 20-thread machine.
- Killing the runner with `taskkill /F` while the CPU hog ran also ended the hog within 3 s (it was set to run for
  40 s). That is the job-object backstop.
- Tests cover: each injector says `ready` and exits by itself, the disk hog never writes more than its budget and
  deletes its directory, dropping the guard kills the injector and cleans up, a panic still cleans up, and a
  Ctrl+C-style interrupt makes the waits stop at once and the guard clean up.

Not verified: that the power request and the wake timer are visible to `powercfg /requests` and `/waketimers`.
That needs admin, and no elevated command was run. The two scenarios that depend on it are scored honest when
unelevated, so they do not need it; an elevated run by the owner would show whether it holds. A real Ctrl+C key
press was not sent either; the handler path was exercised by calling the function it calls, and the
job-object kill was exercised for real.

### Two things found while building them

**A crash is not reported if the parent suppressed it.** The first crash injector, run from the shell this work was
done in, produced no Application Error event at all. The shell had passed down the error mode `SEM_FAILCRITICALERRORS
| SEM_NOGPFAULTERRORBOX` (value 3), and the second flag stops Windows from reporting the crash. The injector now
resets its own error mode to 0 before it crashes (and the hang injector before it hangs). A CI agent or an IDE
may pass the same flag down, so this matters beyond this laptop. After the reset the event appeared.

**Event id 1000 is not only Application Error.** Another provider on this laptop also writes event id 1000. The
ground-truth query therefore filters on the provider name (`Application Error`, `Application Hang`) as well as the id.

### Can Application Hang 1002 be produced unattended?

Yes, but not by hanging alone, and the trigger is synthetic. What was tried, all unelevated, on this laptop:

1. A visible window left hung for 90 s with nobody interacting: **no 1002**. Windows logs 1002 when the
   not-responding program is closed through the shell, which needs a person.
2. After `IsHungAppWindow` reports the window hung, a helper thread of the same process calls `WerReportHang` on
   it. Windows Error Reporting then wrote Application Hang 1002 for `pcsleuth-fault-hang.exe` with the right
   process id and ended the process after about 13 s. Nothing waited for a person to answer.

So the event is a real 1002 written by WER, and its record id is real, but the program reported itself. It
validates reading and attributing 1002 events. It does not validate that Windows detects hangs on its own. The
event's `HangType` is `Unknown`, not `Top level window is idle` as in most real hangs. The scenario is scored
normally. A run that cannot produce the event (no WER, for example) records `not_run` with that reason, never a
pass. `--no-report` leaves a plain hang if someone wants to look at one.

## Scenarios

`pcsleuth-eval list` prints them. "Observable" is under the privileges of the run: the two admin rows turn into
observable scenarios when the harness is run elevated, and the results file says whether it was.

| Name | Question | True cause | Observable | Record ids |
|---|---|---|---|---|
| `crash-app-error` | `crash` | `pcsleuth-fault-crash` crashed | yes | Application Error 1000 id |
| `hang-app-hang` | `crash` | `pcsleuth-fault-hang` hung | yes | Application Hang 1002 id |
| `cpu-hog-live` | `now` | `pcsleuth-fault-cpu` using 4 threads now | yes | none |
| `disk-hog-live` | `now` | `pcsleuth-fault-disk` writing now | yes | none |
| `power-request-live` | `nosleep` | `pcsleuth-fault-power-request` holds a request now | only when elevated | none |
| `wake-timer-live` | `wake` | `pcsleuth-fault-wake-timer` armed a timer now | only when elevated | none |
| `power-request-past` | `nosleep` | the request was held, then released | no: past requests are not logged | none |
| `cpu-hog-past` | `slow` | the hog ran and exited, recorder off | no: past CPU use is not logged | none |
| `sleep-timer-wake` | `wake` | a timer from `pcsleuth-fault-wake-timer` woke the PC from sleep | unverified until hardware | none |
| `sleep-hibernate-timer-wake` | `wake` | a timer woke the PC from hibernate | no: hibernate resume usually reports an unknown source | none |

Sleep scenarios are not run by default and were never run by the author.

## Sleep and wake scenarios

CI runners cannot sleep, and a sleep test stops the session of whoever runs it. The last two scenarios are
defined and wired up, and are skipped unless `--sleep` is given **and** the phrase `sleep this pc` is typed at the
prompt. They are refused outright on CI (`PCSLEUTH_EVAL_WHERE=ci`, or the `CI` variable). Without the flag, or
without the phrase, they are reported `not_run` with the reason.

What happens when allowed: the wake-timer injector arms a timer 90 s ahead, the runner calls `SetSuspendState`
(sleep, or hibernate for the second scenario), waits 45 s after the PC is back, asks `wake`, and scores. Cautions
for the owner: keep the charger in; if the power plan has wake timers disabled the PC stays asleep until someone
wakes it; and `sleep-timer-wake` has no known expected result, which is why it is `unverified`. A first run decides
whether Windows names the timer's owner at all. If it does not, the scenario's `Needs` changes from `Unverified`
to `Never` in `eval/src/scenario.rs`, with the evidence from that run recorded here.

None of this code path has been executed. It is small and its gate is tested (`sleep_allowed`, `sleep_block`), but
whether the machine sleeps and wakes correctly is unverified.

## Reproduce

```
set CARGO_TARGET_DIR=D:\Projects\pcsleuth\.target     (this machine only)
cargo run -p pcsleuth-eval -- run
```

- `--pcsleuth <path>` scores that binary instead of building one. `--scenario <name>` (repeatable) runs only those.
  `--out <dir>` changes where the JSON goes (default `eval/results/`). `list` shows the scenarios.
- The runner always asks cargo to build the injectors and the tool, and takes their paths from cargo's output, so
  a stale binary left in a shared target folder is not scored by mistake.
- It prints a table and writes `eval/results/run-<UTC date>-<ci|laptop>.json`. The file holds the tag, whether it
  was elevated, the OS build, the git commit (and whether the tree was dirty), the date, and one row per scenario.
  It holds no machine name and no user name: every free-text field is scrubbed of `USERNAME`, `COMPUTERNAME`,
  `USERPROFILE` and `USERDOMAIN` before it is written.
- Tag: `ci` when `PCSLEUTH_EVAL_WHERE=ci` or the `CI` variable is set, otherwise `laptop`
  (`PCSLEUTH_EVAL_WHERE=laptop` forces it). Results from the two are never mixed.
- Cleanup: each injector is killed and cleaned up by a guard when its scenario ends or panics; Ctrl+C sets a flag
  every wait loop polls, so the guards run; and every injector sits in a job object that kills it if the runner
  disappears, however it ends. A scenario that cannot run reports `not_run` with the reason.
- The run exits 0 even when scores are low. Low scores are a measurement, not a harness failure. Only a harness
  error (cargo failed, the tool does not exist) is non-zero.
- Committed baselines are named `eval/results/baseline-*.json`; other result files stay local (`.gitignore`).

Tests: `cargo test -p pcsleuth-eval`. They need no admin and do not write events to the Application log; only the
evaluation run itself crashes and hangs a fault program.

## Results

### Baseline before the engine exists

This is the starting line, not an achievement. The engine is the stub from the core package: every question
returns one `*.not_implemented` not-recorded finding.

- **Where**: the author's laptop (`laptop`), Windows 11 build `10.0.26300`, **not elevated**.
- **When and what**: 2026-11-04T00:16:13Z, commit `72e8a448d04b`, clean tree. File:
  [`eval/results/baseline-before-engine-laptop.json`](../eval/results/baseline-before-engine-laptop.json).
- **Command**: `cargo run -p pcsleuth-eval -- run`.

| Scenario | Observable | Result |
|---|---|---|
| `crash-app-error` | yes | miss (event 173040 was injected and written) |
| `hang-app-hang` | yes | miss (event 173043 was injected and written) |
| `cpu-hog-live` | yes | miss |
| `disk-hog-live` | yes | miss |
| `power-request-live` | no (unelevated) | honest, by placeholder |
| `wake-timer-live` | no (unelevated) | honest, by placeholder |
| `power-request-past` | no | honest, by placeholder |
| `cpu-hog-past` | no | honest, by placeholder |
| `sleep-timer-wake` | unverified | not run: needs `--sleep` |
| `sleep-hibernate-timer-wake` | no | not run: needs `--sleep` |

- **Found: 0 of 4** observable scenarios.
- **Honest: 4 of 4** unobservable scenarios that ran, all **by placeholder** answers, so they earn no points.
- **False attributions: 0.**
- **Not run: 2** (sleep scenarios).
- **Net points: 0 of 8 possible.**

Read the 4 of 4 with care. The stub says "not implemented" to every question, so it cannot be wrong about a cause,
and it also cannot find one. The 0 of 4 is the real number; the 4 of 4 is an artifact of the stub.

### What no run covers yet

- **CI.** Nothing has run on a CI runner. The `ci` tag and the refusal to sleep there are tested, not exercised.
- **Elevated.** No elevated run exists. The two admin scenarios are only measured as honesty scenarios.
- **Sleep and wake.** Not run. See above.
- **An engine that answers.** All numbers are from the stub. The first real scores arrive with the engine package.

### Failures during development

Kept here because they shaped the harness (details above): the first crash injector left no event because the
parent had suppressed Windows Error Reporting; a hung window alone never produced event 1002; and event id 1000
is shared with an unrelated provider, so a query by id alone would have matched the wrong record.
