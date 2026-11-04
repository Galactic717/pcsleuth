//! Rule 2 (docs/PLAN.md): no network code, proven by a test rather than promised (ADR 0005).
//!
//! Part one runs `cargo tree --target x86_64-pc-windows-msvc` over the whole workspace, every
//! dependency kind, and fails on a network crate, on tokio's `net` feature, or on a Windows binding
//! feature that exposes sockets, HTTP or DNS. `cargo tree` resolves features for that one target.
//! `Cargo.lock` and `cargo metadata` do not: they list `reqwest`, `hyper` and `tokio` with `net`,
//! because Tauri pulls them for Android and iOS, and they unify features across platforms, so they
//! would flag crates no Windows build contains. Part two builds `pcsleuth.exe`,
//! `pcsleuth-recorder.exe` and `pcsleuth-app.exe`, reads their PE import tables, delay-load imports
//! included, and fails on a network DLL.
//!
//! The `bites_*` tests feed both parts samples that do contain each kind, so a green run means
//! the scan can see, not that it looks away.
//!
//! What this does not cover (ADR 0005): WebView2 is a browser engine with its own network stack,
//! in its own processes. The claim is that this repository's Rust code, the CLI, the recorder and
//! the app's native side, has no network code and that the page loads only bundled assets under a
//! strict CSP. The import tables say nothing about what the WebView process does, and the
//! installer's WebView2 bootstrapper is Microsoft's. A delay-loaded DLL is seen; one loaded by
//! name at run time through `LoadLibrary` is not.
//!
//! `PCSLEUTH_SCAN_TARGET=<triple>` scans another target's tree (`all` shows what the Windows filter
//! leaves out). `PCSLEUTH_SCAN_PROFILE=release` builds and scans release binaries. `PCSLEUTH_SCAN_PREBUILT=<dir>`
//! scans the three executables found in that folder instead of building (the packaging script uses
//! it on the exact files it ships).

#![cfg(windows)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Packages that open sockets, speak HTTP, TLS, DNS or websockets, or run a network runtime.
const DENIED_CRATES: &[&str] = &[
    "reqwest",
    "hyper",
    "hyper-util",
    "hyper-tls",
    "hyper-rustls",
    "h2",
    "ureq",
    "curl",
    "curl-sys",
    "isahc",
    "surf",
    "attohttpc",
    "minreq",
    "tiny_http",
    "axum",
    "warp",
    "actix-web",
    "rocket",
    "tungstenite",
    "tokio-tungstenite",
    "websocket",
    "socket2",
    "mio",
    "net2",
    "async-std",
    "async-net",
    "smol",
    "quinn",
    "quinn-udp",
    "native-tls",
    "rustls",
    "rustls-webpki",
    "openssl",
    "openssl-sys",
    "schannel",
    "hickory-resolver",
    "hickory-proto",
    "trust-dns-resolver",
    "trust-dns-proto",
];

/// Crates that bind the Windows API; a feature that turns on a network area is a socket API.
const WINDOWS_BINDINGS: &[&str] = &["windows", "windows-sys", "winapi"];

/// `winapi` names its features in lower case, one per header.
const WINAPI_NETWORK_FEATURES: &[&str] = &[
    "winsock2", "ws2def", "ws2ipdef", "ws2tcpip", "mswsock", "wininet", "winhttp", "urlmon",
    "dnsapi", "iphlpapi",
];

/// Import names are compared in lower case.
const DENIED_DLLS: &[&str] = &[
    "ws2_32.dll",
    "wsock32.dll",
    "winhttp.dll",
    "wininet.dll",
    "urlmon.dll",
    "dnsapi.dll",
    "iphlpapi.dll",
    "mswsock.dll",
    // Beyond the ADR's list: the HTTP server API, LDAP, web services, and the network store.
    "httpapi.dll",
    "wldap32.dll",
    "webservices.dll",
    "winnsi.dll",
];

fn is_network_feature(package: &str, feature: &str) -> bool {
    match package {
        "winapi" => WINAPI_NETWORK_FEATURES.contains(&feature),
        // Same names in `windows` and `windows-sys`: Win32 areas and the WinRT namespaces.
        _ => {
            feature.starts_with("Win32_Networking_")
                || feature == "Win32_NetworkManagement_IpHelper"
                || feature == "Win32_NetworkManagement_Dns"
                || feature == "Networking"
                || feature.starts_with("Networking_")
                || feature.starts_with("Web_Http")
        }
    }
}

/// One line per problem found in `cargo tree --prefix none -f "{p}|{f}"` output: a package name
/// and version, a bar, the comma-separated features that package is built with for the target.
fn crate_violations(tree: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in tree.lines().filter(|l| !l.trim().is_empty()) {
        let (package, features) = line.split_once('|').unwrap_or((line, ""));
        let mut words = package.split_whitespace();
        let (name, version) = (words.next().unwrap(), words.next().unwrap_or("?"));
        let features = features.trim_end_matches(" (*)").split(',');
        if DENIED_CRATES.contains(&name) {
            found.push(format!("network crate `{name}` {version} is in the tree"));
        }
        for feature in features {
            if name == "tokio" && feature == "net" {
                found.push("`tokio` is built with its `net` feature".to_string());
            } else if WINDOWS_BINDINGS.contains(&name) && is_network_feature(name, feature) {
                found.push(format!(
                    "`{name}` is built with the network feature `{feature}`"
                ));
            }
        }
    }
    found
}

#[derive(Debug, PartialEq)]
struct Import {
    dll: String,
    delayed: bool,
}

fn bytes_at<const N: usize>(pe: &[u8], at: usize) -> Result<[u8; N], String> {
    pe.get(at..at + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| format!("PE file is truncated at {at:#x}"))
}

fn u16_at(pe: &[u8], at: usize) -> Result<u16, String> {
    bytes_at(pe, at).map(u16::from_le_bytes)
}

fn u32_at(pe: &[u8], at: usize) -> Result<u32, String> {
    bytes_at(pe, at).map(u32::from_le_bytes)
}

/// The DLLs a 64-bit PE file imports: the import directory and the delay-load directory.
fn pe_imports(pe: &[u8]) -> Result<Vec<Import>, String> {
    let pe_at = u32_at(pe, 0x3c)? as usize;
    if pe.get(pe_at..pe_at + 4) != Some(b"PE\0\0") {
        return Err("not a PE file".to_string());
    }
    let coff = pe_at + 4;
    let sections = u16_at(pe, coff + 2)? as usize;
    let optional_size = u16_at(pe, coff + 16)? as usize;
    let optional = coff + 20;
    if u16_at(pe, optional)? != 0x20b {
        return Err("only PE32+ (64-bit) files are read".to_string());
    }
    let directory_count = u32_at(pe, optional + 108)? as usize;
    let directories = optional + 112;

    // (virtual address, bytes in memory, file offset) per section.
    let mut table = Vec::new();
    for index in 0..sections {
        let at = optional + optional_size + index * 40;
        let virtual_size = u32_at(pe, at + 8)?;
        let raw_size = u32_at(pe, at + 16)?;
        table.push((
            u32_at(pe, at + 12)?,
            virtual_size.max(raw_size),
            u32_at(pe, at + 20)?,
        ));
    }
    let to_offset = |rva: u32| -> Result<usize, String> {
        table
            .iter()
            .find(|(start, len, _)| rva >= *start && rva - start < *len)
            .map(|(start, _, raw)| (rva - start + raw) as usize)
            .ok_or_else(|| format!("RVA {rva:#x} is outside every section"))
    };
    let name_at = |rva: u32| -> Result<String, String> {
        let from = to_offset(rva)?;
        let tail = pe.get(from..).ok_or("PE file is truncated in a DLL name")?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or("unterminated DLL name")?;
        Ok(String::from_utf8_lossy(&tail[..end]).to_ascii_lowercase())
    };

    let mut found = Vec::new();
    // Directory 1 is the import table, 13 the delay-load import table.
    for (index, delayed, stride, name_field) in [(1, false, 20, 12), (13, true, 32, 4)] {
        if index >= directory_count {
            continue;
        }
        let rva = u32_at(pe, directories + index * 8)?;
        if rva == 0 {
            continue;
        }
        let mut at = to_offset(rva)?;
        loop {
            let descriptor = pe
                .get(at..at + stride)
                .ok_or_else(|| format!("import table at {at:#x} has no terminator"))?;
            if descriptor.iter().all(|&b| b == 0) {
                break;
            }
            // Bit 0 of a delay-load descriptor's attributes says its fields are RVAs. MSVC always
            // sets it for 64-bit images; an old-style descriptor is refused rather than guessed at.
            if delayed && u32_at(pe, at)? & 1 == 0 {
                return Err("delay-load descriptor holds virtual addresses".to_string());
            }
            found.push(Import {
                dll: name_at(u32_at(pe, at + name_field)?)?,
                delayed,
            });
            at += stride;
        }
    }
    Ok(found)
}

/// The imports that are network DLLs, as text for the failure message.
fn denied_imports(imports: &[Import]) -> Vec<String> {
    imports
        .iter()
        .filter(|import| DENIED_DLLS.contains(&import.dll.as_str()))
        .map(|import| {
            format!(
                "{}{}",
                import.dll,
                if import.delayed { " (delay-load)" } else { "" }
            )
        })
        .collect()
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

const SHIPPED: [&str; 3] = ["pcsleuth", "pcsleuth-recorder", "pcsleuth-app"];

/// The shipped executables: the ones in `PCSLEUTH_SCAN_PREBUILT` when it is set, else the ones
/// cargo builds now. Their paths come from cargo's own report, so a stale executable left in a
/// shared target folder is never the one scanned.
fn built_binaries() -> HashMap<String, PathBuf> {
    if let Some(dir) = std::env::var_os("PCSLEUTH_SCAN_PREBUILT") {
        return SHIPPED
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    Path::new(&dir).join(format!("{name}.exe")),
                )
            })
            .collect();
    }
    let mut build = cargo();
    build
        .args([
            "build",
            "--locked",
            "--bins",
            "-p",
            "pcsleuth-cli",
            "-p",
            "pcsleuth-recorder",
            "-p",
            "pcsleuth-app",
        ])
        .arg("--message-format=json-render-diagnostics")
        .current_dir(workspace_root());
    if std::env::var("PCSLEUTH_SCAN_PROFILE").as_deref() == Ok("release") {
        build.arg("--release");
    }
    let output = build.output().expect("cargo starts");
    assert!(
        output.status.success(),
        "cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut binaries = HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let is_bin = message["target"]["kind"]
            .as_array()
            .is_some_and(|k| k.iter().any(|v| v == "bin"));
        if let (true, "compiler-artifact", Some(path), Some(name)) = (
            is_bin,
            message["reason"].as_str().unwrap_or(""),
            message["executable"].as_str(),
            message["target"]["name"].as_str(),
        ) {
            binaries.insert(name.to_string(), PathBuf::from(path));
        }
    }
    binaries
}

/// Compiles a one-file program with the same `rustc` the workspace uses and returns the exe bytes.
fn rustc_sample(name: &str, source: &str, link_args: &[&str]) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no_network");
    std::fs::create_dir_all(&dir).unwrap();
    let (src, exe) = (
        dir.join(format!("{name}.rs")),
        dir.join(format!("{name}.exe")),
    );
    std::fs::write(&src, source).unwrap();
    let output = Command::new("rustc")
        .args(["--edition", "2021", "-O", "-C", "debuginfo=0", "-o"])
        .arg(&exe)
        .args(
            link_args
                .iter()
                .flat_map(|a| ["-C".to_string(), format!("link-arg={a}")]),
        )
        .arg(&src)
        .output()
        .expect("rustc starts");
    assert!(
        output.status.success(),
        "rustc failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(exe).unwrap()
}

// ---------------------------------------------------------------------------------------------
// The real thing

#[test]
fn workspace_has_no_network_crate_or_feature() {
    let target =
        std::env::var("PCSLEUTH_SCAN_TARGET").unwrap_or_else(|_| "x86_64-pc-windows-msvc".into());
    let output = cargo()
        .args(["tree", "--locked", "--workspace", "--target", &target])
        .args([
            "-e",
            "normal,build,dev",
            "--prefix",
            "none",
            "-f",
            "{p}|{f}",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("cargo starts");
    assert!(
        output.status.success(),
        "cargo tree failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);

    // Guard against a vacuous pass: the tree must be the real workspace, Tauri included.
    for member in [
        "pcsleuth-cli ",
        "pcsleuth-recorder ",
        "pcsleuth-app ",
        "tauri ",
    ] {
        assert!(
            tree.lines().any(|l| l.starts_with(member)),
            "`{member}` is not in the tree:\n{tree}"
        );
    }

    let mut found = crate_violations(&tree);
    found.sort();
    found.dedup();
    assert!(
        found.is_empty(),
        "rule 2 broken for {target}:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn shipped_binaries_import_no_network_dll() {
    let binaries = built_binaries();
    let mut problems = Vec::new();
    for name in SHIPPED {
        let path = binaries
            .get(name)
            .unwrap_or_else(|| panic!("cargo built no `{name}` binary"));
        let bytes = std::fs::read(path).unwrap();
        let imports = pe_imports(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        // Guard against a vacuous pass: every Rust program on Windows imports kernel32.
        assert!(
            imports.iter().any(|i| i.dll == "kernel32.dll"),
            "{name}: parser saw {imports:?}"
        );
        let list: Vec<&str> = imports.iter().map(|i| i.dll.as_str()).collect();
        eprintln!("{name} ({}) imports: {}", path.display(), list.join(", "));
        problems.extend(
            denied_imports(&imports)
                .into_iter()
                .map(|d| format!("{name} imports {d}")),
        );
    }
    assert!(
        problems.is_empty(),
        "rule 2 broken:\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------------------------
// The scan bites: samples that do contain each kind

/// `cargo tree --prefix none -f "{p}|{f}"` text for the given packages and features.
fn tree_sample(packages: &[(&str, &[&str])]) -> String {
    let mut text = String::from("pcsleuth-cli v0.1.0 (D:\\work\\crates\\cli)|\n");
    for (name, features) in packages {
        text += &format!("{name} v1.0.0|{}\n", features.join(","));
    }
    text
}

#[test]
fn bites_every_denied_crate() {
    for name in DENIED_CRATES {
        let found = crate_violations(&tree_sample(&[("serde", &[]), (name, &[])]));
        assert_eq!(found.len(), 1, "{name}: {found:?}");
        assert!(found[0].contains(name), "{found:?}");
    }
}

#[test]
fn bites_tokio_net_and_windows_network_features() {
    for (package, feature) in [
        ("tokio", "net"),
        ("windows", "Win32_Networking_WinSock"),
        ("windows", "Win32_Networking_WinHttp"),
        ("windows-sys", "Win32_NetworkManagement_IpHelper"),
        ("windows-sys", "Win32_NetworkManagement_Dns"),
        ("windows", "Networking_Sockets"),
        ("windows", "Web_Http"),
        ("winapi", "winsock2"),
    ] {
        let found = crate_violations(&tree_sample(&[(package, &["std", feature])]));
        assert_eq!(found.len(), 1, "{package} {feature}: {found:?}");
        assert!(found[0].contains(feature), "{found:?}");
    }
}

#[test]
fn reads_the_markers_cargo_tree_adds() {
    // A repeated package ends in ` (*)`, a path package and a proc-macro carry parentheses.
    let tree = "serde_derive v1.0.2 (proc-macro)|\nmio v1.2.4|os-poll,net (*)\npcsleuth-core v0.1.0 (D:\\work)|\n";
    assert_eq!(
        crate_violations(tree),
        vec!["network crate `mio` v1.2.4 is in the tree".to_string()]
    );
    let tokio = "tokio v1.5.0|bytes,net,rt (*)\n";
    assert_eq!(crate_violations(tokio).len(), 1);
}

#[test]
fn tree_scan_passes_a_clean_tree() {
    let clean = tree_sample(&[
        ("tokio", &["rt", "sync"]),
        (
            "windows",
            &[
                "Win32_Foundation",
                "Win32_System_Power",
                "Win32_Storage_Jet",
            ],
        ),
        ("windows-sys", &["Win32_System_EventLog"]),
        ("serde", &["derive"]),
    ]);
    assert_eq!(crate_violations(&clean), Vec::<String>::new());
}

/// A minimal PE32+ file with the given regular and delay-load imports and nothing else.
fn synthetic_pe(regular: &[&str], delayed: &[&str]) -> Vec<u8> {
    const SECTION_RVA: u32 = 0x1000;
    const SECTION_RAW: usize = 0x400;
    let put = |buf: &mut Vec<u8>, at: usize, value: u32, len: usize| {
        buf[at..at + len].copy_from_slice(&value.to_le_bytes()[..len]);
    };

    let regular_len = (regular.len() + 1) * 20;
    let delayed_len = (delayed.len() + 1) * 32;
    let mut section = vec![0u8; regular_len + delayed_len];
    let mut names = Vec::new();
    let name_rva = |names: &mut Vec<u8>, dll: &str| {
        let rva = SECTION_RVA + (regular_len + delayed_len + names.len()) as u32;
        names.extend(dll.bytes());
        names.push(0);
        rva
    };
    for (i, dll) in regular.iter().enumerate() {
        let rva = name_rva(&mut names, dll);
        put(&mut section, i * 20 + 12, rva, 4);
    }
    for (i, dll) in delayed.iter().enumerate() {
        let rva = name_rva(&mut names, dll);
        put(&mut section, regular_len + i * 32, 1, 4);
        put(&mut section, regular_len + i * 32 + 4, rva, 4);
    }
    section.extend(names);

    let mut pe = vec![0u8; SECTION_RAW];
    pe[..2].copy_from_slice(b"MZ");
    put(&mut pe, 0x3c, 0x40, 4);
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    put(&mut pe, coff, 0x8664, 2);
    put(&mut pe, coff + 2, 1, 2);
    put(&mut pe, coff + 16, 240, 2);
    let optional = coff + 20;
    put(&mut pe, optional, 0x20b, 2);
    put(&mut pe, optional + 108, 16, 4);
    put(&mut pe, optional + 112 + 8, SECTION_RVA, 4);
    put(
        &mut pe,
        optional + 112 + 13 * 8,
        SECTION_RVA + regular_len as u32,
        4,
    );
    let header = optional + 240;
    pe[header..header + 6].copy_from_slice(b".idata");
    put(&mut pe, header + 8, section.len() as u32, 4);
    put(&mut pe, header + 12, SECTION_RVA, 4);
    put(&mut pe, header + 16, section.len() as u32, 4);
    put(&mut pe, header + 20, SECTION_RAW as u32, 4);
    pe.extend(section);
    pe
}

#[test]
fn bites_every_denied_dll_regular_and_delay_loaded() {
    for dll in DENIED_DLLS {
        let upper = dll.to_ascii_uppercase();
        let regular = pe_imports(&synthetic_pe(&["KERNEL32.dll", &upper], &[])).unwrap();
        assert_eq!(denied_imports(&regular), vec![dll.to_string()]);
        let delayed = pe_imports(&synthetic_pe(&["KERNEL32.dll"], &[&upper])).unwrap();
        assert_eq!(
            denied_imports(&delayed),
            vec![format!("{dll} (delay-load)")]
        );
    }
}

#[test]
fn pe_scan_passes_a_clean_synthetic_file_and_rejects_garbage() {
    let clean = pe_imports(&synthetic_pe(
        &["KERNEL32.dll", "ntdll.dll"],
        &["advapi32.dll"],
    ))
    .unwrap();
    assert_eq!(clean.len(), 3);
    assert_eq!(denied_imports(&clean), Vec::<String>::new());
    assert!(pe_imports(b"not a pe file at all, not even close, really not one").is_err());
}

const UDP_SAMPLE: &str =
    r#"fn main() { println!("{:?}", std::net::UdpSocket::bind("127.0.0.1:0").is_ok()); }"#;

#[test]
fn bites_a_real_rustc_binary_that_opens_a_socket() {
    let imports = pe_imports(&rustc_sample("udp", UDP_SAMPLE, &[])).unwrap();
    assert_eq!(
        denied_imports(&imports),
        vec!["ws2_32.dll".to_string()],
        "{imports:?}"
    );
}

#[test]
fn bites_a_real_binary_that_delay_loads_a_network_dll() {
    // MSVC's own delay-load import table, which hides the DLL from the regular one.
    let sample = rustc_sample(
        "udp_delayed",
        UDP_SAMPLE,
        &["/DELAYLOAD:ws2_32.dll", "delayimp.lib"],
    );
    let imports = pe_imports(&sample).unwrap();
    assert_eq!(
        denied_imports(&imports),
        vec!["ws2_32.dll (delay-load)".to_string()],
        "{imports:?}"
    );
}

#[test]
fn a_real_rustc_hello_world_imports_no_network_dll() {
    // Evidence that the Rust standard library itself links no network DLL until a socket is used.
    let imports = pe_imports(&rustc_sample(
        "hello",
        r#"fn main() { println!("hello"); }"#,
        &[],
    ))
    .unwrap();
    assert!(
        imports.iter().any(|i| i.dll == "kernel32.dll"),
        "{imports:?}"
    );
    assert_eq!(
        denied_imports(&imports),
        Vec::<String>::new(),
        "{imports:?}"
    );
}
