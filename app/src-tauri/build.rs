//! Lists the commands the page may call. Anything not listed here has no permission to exist, so
//! the capability file in `capabilities/` is the whole of what the page is allowed to do.

const COMMANDS: &[&str] = &[
    "timeline", "wake", "nosleep", "battery", "crash", "slow", "now", "doctor", "elevated",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run the Tauri build step");
}
