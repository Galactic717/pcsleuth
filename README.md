# pcsleuth

Ask your Windows PC why it did that.

Why did it wake at 3 a.m.? Why won't it stay asleep? What drained the battery overnight? What was it
doing when it froze? Windows already records most of the answers, scattered across event logs, power
reports and a usage database, in a form nobody should have to read. pcsleuth reads them and answers in
plain language.

**Status: pre-alpha. There is nothing to install yet.** This README describes the goal, not a finished
product. See [docs/RESEARCH.md](docs/RESEARCH.md) for why this project exists and what the evidence is.

## Principles

- **Answers about the past.** The first run works from what Windows has already logged, so you do not
  need to have installed anything before the problem happened.
- **Evidence, not guesses.** Every answer cites the log, event and timestamp behind it. When Windows did
  not record the cause, pcsleuth says so instead of inventing one.
- **Local only.** No account, no telemetry, no network code.
- **Works without admin rights.** Answers get better with elevation, and pcsleuth tells you exactly which
  ones and why.

## License

[Apache-2.0](LICENSE)
