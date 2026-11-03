# Why this project exists

Research done on 3 November 2026. Star counts are from that day. Anything not opened or run is marked
as such.

## Starting point

[Still Unbuilt](https://stillunbuilt.shiptiffin.app) ranks the 100 tools Hacker News has asked for most
persistently, from 12,441 requests between 2008 and 2026. Its labels and idea list are CC BY 4.0. Idea
#89 is [Why is my computer doing that](https://stillunbuilt.shiptiffin.app/i/why-is-my-computer-doing-that/):
a tool that says why a machine won't sleep, what drains the battery and which process causes hangs.

Its numbers are modest, and that should be stated plainly: 12 asks, 2 of them since 2024, across 7 of 19
years, first asked in 2010. Two of the 12 appear to be one comment posted twice. Half want it local or
private. Nobody says they would pay. The list counts only Hacker News comments that use a fixed set of
phrases, so these are floors, but this idea was not chosen for its rank.

The asks closest to this project:

- A Windows equivalent of Sleep Aid for diagnosing wake and sleep problems
  ([44754605](https://news.ycombinator.com/item?id=44754605), Aug 2025).
- A tool to go back through recent history and explain why the machine was not sleeping or idling
  ([44751318](https://news.ycombinator.com/item?id=44751318), Jul 2025).
- A way to drill down on what is consuming power
  ([32040766](https://news.ycombinator.com/item?id=32040766), Jul 2022).
- A program that watches battery drain over time and points at the culprit
  ([13641937](https://news.ycombinator.com/item?id=13641937), Feb 2017).

## Why it was chosen

The list labels this idea "built, still asked for", but the label does not hold for Windows. None of the
8 launches on its page names Windows in its title: FSM (Linux), TTop, Gtop, Ktop (terminal monitors), Vitals,
Coolant (Mac), an iTerm2 widget, and Dialtone watcher. The launches themselves were not opened. They are mostly monitors, which show
the present. The asks are about the past and about causes.

Demand for "why" tools is visible elsewhere:

| Tool | Platform | State | What it answers |
|---|---|---|---|
| [witr](https://github.com/pranshuparmar/witr) | Linux, macOS, FreeBSD, Windows | 22,915 stars | Why a process, port or file exists now. Not history, power or sleep |
| [whyd](https://github.com/vmaltarello/whyd) | Linux (systemd) | 84 stars, created 9 Oct 2026, GPL-3.0 | How the previous session ended. Reads the journal |
| [rustwhy](https://github.com/Ninso112/rustwhy) | Linux | 5 stars | 13 diagnostic modules |
| [Sleep Aid](https://ohanaware.com/sleepaid/) | Mac | Paid, with a trial and press coverage | Sleep history and what prevents sleep. Product page read, app not run |

Closest on Windows:

| Tool | State | Gap |
|---|---|---|
| Built-in `powercfg`, Reliability Monitor | Ships with Windows | Separate reports, several admin-only, no answer to a question |
| [NirSoft TurnedOnTimesView, AppResourcesUsageView](https://www.nirsoft.net/utils/computer_turned_on_times.html) | Free, closed source | Show raw tables from one source each. Pages read, tools not run |
| [srum-dump](https://github.com/MarkBaggett/srum-dump), [EricZimmerman/Srum](https://github.com/EricZimmerman/Srum) | 766 and 56 stars | Forensics tools for analysts |
| [PowerCulprit](https://github.com/lwzhenglittle/PowerCulprit) | 2 stars | Battery drain on Intel platforms only |
| [WinNoWakeUp](https://github.com/C485/WinNoWakeUp) | 0 stars, Oct 2026 | Unwanted wakes only |
| [deadarcher/culprit](https://github.com/deadarcher/culprit) | 0 stars | Needs a PerfMon CSV you collected beforehand |

READMEs of the small Windows tools were not read in full. They show that others feel this problem and
that nobody has won it yet, not that the field is empty. The search was limited to GitHub and the web, so
a commercial tool could have been missed.

## What Windows gives without admin rights

Probed on one Windows 11 laptop without elevation:

| Source | Result |
|---|---|
| System log, Power-Troubleshooter ID 1 | Readable. 11 events back to 26 Sep 2026, each with sleep time, wake time and wake source |
| System log IDs 41, 6008, 1074 | Readable. 9, 9 and 150 events (the query was capped at 200) |
| Application log, Application Hang and Application Error 1000 | Readable. 6 and 12 events |
| `powercfg /batteryreport /xml` | Works. 72 recent usage entries, 92 capacity history entries, plus an `EnergyDrains` section |
| `powercfg /lastwake`, `/devicequery wake_armed` | Work |
| `powercfg /waketimers`, `/requests` | Require admin |
| `powercfg /srumutil` | Failed with error 0x1f. Cause not established |
| `SRUDB.dat` | Access denied |
| Diagnostics-Performance/Operational log | Unauthorized |
| TaskScheduler/Operational log | Exists but is disabled here |

What this means for the design:

- A useful first run without admin rights is realistic. Per-app energy, slow-boot culprits and live power
  requests need elevation.
- **Windows does not always know.** One real wake on this laptop has the wake source `Unknown`. Saying so
  is a feature, and it is the reason for an optional recorder.
- Task attribution cannot be retroactive while the Task Scheduler log is off, so the tool must offer to
  turn it on and say what that costs.
- Event IDs 506 and 507 do not exist on this laptop because it uses S3 sleep, not Modern Standby. Both
  paths must work, and Sleep Study cannot be the only source.
- The rendered `Message` text is localized and its timestamps contain invisible direction marks. Parsers
  must read the structured event data, never the message.

## Risks

- Demand on Hacker News is thin. The real audience would be ordinary Windows users, whose demand is
  suggested by support threads but was not measured here.
- Answers may often be "Windows did not record this" until the recorder has run.
- Sleep and wake cannot be exercised on CI runners. That part of the evaluation needs real hardware.
- An unsigned executable triggers SmartScreen warnings. Code signing is an open question.
- Microsoft could ship this itself.

## Other ideas that were rejected

| Idea | Reason |
|---|---|
| #54 Backup forge for GitHub | [gitea-mirror](https://github.com/RayLabsHQ/gitea-mirror) (1,509 stars, active) already mirrors issues, PRs (as issues), labels, milestones, releases and wikis. Only outage failover remains, wanted by about 3 of 11 asks, and it needs a running forge |
| #59 Email and chats archived locally | [msgvault](https://github.com/wesm/msgvault) (2,175 stars, active) covers it |
| #8 Choose what each site may run | The strongest runner-up. Never launched, and old community rule lists such as [umatrix-recipes](https://github.com/kristerkari/umatrix-recipes) are dead. [AutoFR](https://www.usenix.org/conference/usenixsecurity23/presentation/le) shows that automatic rule generation can work for ads. But minimal allowlists go stale, which means crawling forever, and uBlock Origin already provides much of the value |
| #1 Mute button for news feeds | Most asked, but 61 launches, 13% would pay, and per-site upkeep never ends |
| #2 Windows without the junk | The list's own note says most people want Microsoft to sell it, not a third-party tool |
| #60, #85, #47, #48, #65 | Security seatbelts, agent sandboxes and coding agents have many launches, a lot of them from 2026 |
