# pcsleuth app

The desktop app: a timeline of answers, each card opening its evidence. Tauri 2 (pinned to 2.12.5), plain
TypeScript and Vite, no UI framework. The Rust side calls `pcsleuth_engine` in process, one Tauri command per
question, on a worker thread.

## Build

```
cd app
npm ci
npm run typecheck && npm test
cargo build -p pcsleuth-cli --release   # the app needs pcsleuth.exe in its own folder, see below
cargo tauri build --no-bundle           # app/src-tauri target: pcsleuth-app.exe
```

`See more with admin` starts `pcsleuth.exe <question> --json --elevate` from the folder the app is in. The app
never asks Windows for elevation itself, and without `pcsleuth.exe` beside it the button reports that and does
nothing else. An installer must put both files in one folder.

## What the page may do

- Call nine commands: the eight questions and `elevated`. `build.rs` lists them and `capabilities/default.json`
  grants exactly those. No plugins, no updater, no shell, no file or network access, `withGlobalTauri` off.
- CSP is `default-src 'self'` with only Tauri's local `ipc:` bridge added. No remote origin, no `unsafe-eval`.
- Text from logs reaches the page through `textContent` only (`src/dom.ts`). `tests/guard.test.ts` fails if a
  markup-parsing API appears in `src/`. The Rust side also removes control and text-direction characters first.
- A fix is shown as a command with a Copy button. There is no apply path.

WebView2 is a browser engine with its own network stack, in its own processes. The claim is scoped as in
ADR 0005: this app's Rust code has no network code and the page loads only bundled assets.
