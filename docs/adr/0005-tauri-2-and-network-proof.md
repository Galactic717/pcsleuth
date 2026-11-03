# ADR-0005: Tauri 2 for the app, and how "no network" is proven

**Date**: 2026-11-03. **Status**: accepted.

## Context

The desktop app needs a timeline, answer cards and accessible evidence views. WebView2 is preinstalled on Windows 11.
On crates.io `tauri` currently resolves to 3.0.0-alpha.5, while npm `@tauri-apps/cli` latest is 2.12.4 and the installed
`cargo-tauri` is 2.10.0. The product also promises no network code, proven by a test.

## Decision

Tauri 2 stable, pinned to a 2.x version, with plain TypeScript and Vite and no UI framework. The app calls the same
`engine` crate in-process. The no-network test has two parts: a denylist over `cargo metadata` for network crates
(`reqwest`, `hyper`, `ureq`, `tokio` with its `net` feature, and similar), and a scan of the built PE import tables for
`ws2_32.dll`, `winhttp.dll`, `wininet.dll`, `urlmon.dll` and `dnsapi.dll`.

## Alternatives considered

- **Tauri 3 alpha**: alpha, and it does not match the installed tooling.
- **Windows App SDK or WinUI**: better native feel, but a C# or COM stack beside the Rust core.
- **Electron**: ships a browser with the app.
- **TUI only**: the product needs a desktop app, and terminal redraws serve screen-reader users worse.

## Consequences

WebView2 is a browser engine with its own network stack, in its own processes. So the claim is scoped: the CLI, the
recorder and the app's Rust code have no network code, and the WebView loads only bundled assets under a strict CSP
with no remote origins and no updater. The README must state this limit in those words. If a Tauri dependency trips the
import scan, the scan's result for the app binary is reported as it is, not hidden.
