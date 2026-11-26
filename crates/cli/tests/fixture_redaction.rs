//! `fixtures/` holds real captures. They must not carry the owner's machine name, user name,
//! user SID or battery serial. `scripts/capture-fixtures.ps1` redacts and re-checks at capture
//! time; this test keeps them clean afterwards, whoever edits or adds a file (docs/PLAN.md,
//! "Fixtures"). It looks for shapes, so it needs no knowledge of the real names.
//!
//! The `bites_*` tests feed the scan text that does carry each leak, in UTF-8 and UTF-16.

use std::path::{Path, PathBuf};

/// Windows invents machine names of these shapes on a fresh install.
const MACHINE_PREFIXES: &[&str] = &["desktop-", "laptop-"];

/// Profile folders every Windows install has; any other `\Users\<name>` must be the redacted form.
const SYSTEM_PROFILES: &[&str] = &["public", "default", "default user", "all users"];

/// Text as the fixtures hold it. A UTF-16 file with a byte order mark is decoded properly; any
/// other file loses its NUL bytes, which turns BOM-less UTF-16 of ASCII text back into text and
/// changes nothing for UTF-8.
fn decode(bytes: &[u8]) -> String {
    let utf16 = |rest: &[u8], word: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|&c| word(c)).collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        _ => String::from_utf8_lossy(
            &bytes
                .iter()
                .copied()
                .filter(|&b| b != 0)
                .collect::<Vec<_>>(),
        )
        .into_owned(),
    }
}

fn snippet(text: &str, at: usize) -> String {
    text[at..]
        .chars()
        .take(40)
        .collect::<String>()
        .replace(['\r', '\n'], " ")
}

/// One line per leak found in `text`.
fn violations(text: &str) -> Vec<String> {
    // ASCII lower-casing keeps every byte offset, so offsets from `lower` index into `text`.
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut leak = |what: &str, at: usize| found.push(format!("{what}: `{}`", snippet(text, at)));

    for prefix in MACHINE_PREFIXES {
        for (at, _) in lower.match_indices(prefix) {
            leak("machine name", at);
        }
    }
    // Server installs get WIN-, then eleven letters or digits.
    for (at, _) in text.match_indices("WIN-") {
        let tail = &text[at + 4..];
        if tail
            .bytes()
            .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            .count()
            >= 8
        {
            leak("machine name", at);
        }
    }
    for (at, _) in lower.match_indices("s-1-5-21-") {
        if !text[at + 9..].starts_with("REDACTED") {
            leak("user or domain SID", at);
        }
    }
    for (at, _) in lower
        .match_indices("\\users\\")
        .chain(lower.match_indices("/users/"))
    {
        let name_at = at + 7;
        let name = text[name_at..]
            .split(['\\', '/', '<', '>', '"', '\'', '\r', '\n'])
            .next()
            .unwrap_or("");
        let allowed = name.starts_with("REDACTED")
            || name.starts_with('%')
            || SYSTEM_PROFILES.contains(&name.to_ascii_lowercase().as_str());
        if !allowed {
            leak("user profile path", at);
        }
    }
    for (at, tag) in lower.match_indices("<serialnumber>") {
        let value = text[at + tag.len()..]
            .split('<')
            .next()
            .unwrap_or("")
            .trim();
        if value != "REDACTED" {
            leak("battery serial", at);
        }
    }
    found
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files.sort();
    files
}

/// `file: leak` lines for every file under `dir`, and how many files were read.
fn scan_dir(dir: &Path) -> (Vec<String>, usize) {
    let files = files_under(dir);
    let mut found = Vec::new();
    for file in &files {
        let text = decode(&std::fs::read(file).unwrap());
        let name = file.strip_prefix(dir).unwrap_or(file).display().to_string();
        found.extend(
            violations(&text)
                .into_iter()
                .map(|v| format!("{name}: {v}")),
        );
    }
    (found, files.len())
}

#[test]
fn committed_fixtures_carry_no_machine_name_sid_user_path_or_battery_serial() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures");
    let (found, scanned) = scan_dir(&dir);
    assert!(scanned > 0, "no files under {}", dir.display());
    assert!(
        found.is_empty(),
        "{} fixture leak(s):\n  {}",
        found.len(),
        found.join("\n  ")
    );
}

// ---------------------------------------------------------------------------------------------
// The scan bites

const LEAKS: &[(&str, &str, &str)] = &[
    (
        "DESKTOP-AB12CD3",
        "machine name",
        "<Computer>DESKTOP-AB12CD3</Computer>",
    ),
    (
        "laptop-xyz",
        "machine name",
        "<Computer>Laptop-XYZ9876</Computer>",
    ),
    (
        "WIN-",
        "machine name",
        "<Computer>WIN-ABCDEF12345</Computer>",
    ),
    (
        "SID",
        "user or domain SID",
        r#"<Security UserID="S-1-5-21-1004336348-1177238915-682003330-1001"/>"#,
    ),
    ("SID bare", "user or domain SID", "S-1-5-21-"),
    (
        "profile",
        "user profile path",
        r#"<Data>"C:\Users\alice\AppData\x.exe"</Data>"#,
    ),
    (
        "profile slash",
        "user profile path",
        "file:///C:/Users/Alice Smith/x.txt",
    ),
    (
        "serial",
        "battery serial",
        "<SerialNumber>1234ABC</SerialNumber>",
    ),
    (
        "serial empty",
        "battery serial",
        "<SerialNumber></SerialNumber>",
    ),
    (
        "serial case",
        "battery serial",
        "<serialnumber>redacted</serialnumber>",
    ),
];

const CLEAN: &str = r#"<Computer>REDACTED-PC</Computer> <Security UserID="S-1-5-21-REDACTED"/>
<Data>C:\Users\REDACTED-USER\x.exe</Data> <Data>C:\Users\Public\Documents</Data> S-1-5-18 <Data>WIN-1</Data>
<SerialNumber>REDACTED</SerialNumber> <Data>C:\Users\%USERNAME%\x</Data> X:\REDACTED\RedactedApp.exe"#;

#[test]
fn bites_each_kind_of_leak() {
    assert_eq!(violations(CLEAN), Vec::<String>::new());
    for (label, kind, text) in LEAKS {
        let found = violations(text);
        assert!(
            !found.is_empty() && found.iter().all(|f| f.starts_with(kind)),
            "{label}: {found:?}"
        );
    }
}

#[test]
fn bites_in_utf16_with_and_without_a_byte_order_mark() {
    let text = "<Computer>DESKTOP-AB12CD3</Computer>";
    let units: Vec<u16> = text.encode_utf16().collect();
    let le: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    let be: Vec<u8> = units.iter().flat_map(|u| u.to_be_bytes()).collect();
    let with_bom = |bom: [u8; 2], body: &[u8]| [bom.as_slice(), body].concat();

    for (label, bytes) in [
        ("le bom", with_bom([0xFF, 0xFE], &le)),
        ("be bom", with_bom([0xFE, 0xFF], &be)),
        ("le without bom", le.clone()),
        ("be without bom", be.clone()),
        ("utf-8", text.as_bytes().to_vec()),
    ] {
        let found = violations(&decode(&bytes));
        assert_eq!(found.len(), 1, "{label}: {found:?}");
    }
}

#[test]
fn bites_a_leak_in_a_file_inside_a_directory_tree() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("fixture_redaction")
        .join("tree");
    let nested = dir.join("battery");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(dir.join("clean.xml"), CLEAN).unwrap();
    let leaky: Vec<u8> = [
        &[0xFF, 0xFE][..],
        &"<SerialNumber>9Z9Z</SerialNumber>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>(),
    ]
    .concat();
    std::fs::write(nested.join("report.xml"), leaky).unwrap();

    let (found, scanned) = scan_dir(&dir);
    assert_eq!(scanned, 2);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("report.xml") && found[0].contains("battery serial"),
        "{found:?}"
    );
}
