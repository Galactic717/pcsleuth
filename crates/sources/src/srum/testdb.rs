//! Builds a small ESE database at run time with the same table shape as `SRUDB.dat`, so the reader
//! is tested through ESENT without committing anyone's usage history. Every name, id and number
//! here is made up.

use std::path::{Path, PathBuf};

use super::decode::{Value, coltyp};
use super::energy::{EnergyRecord, encode_energy};
use super::ese::{Instance, Params};

pub(super) const ID_MAP: &str = "SruDbIdMapTable";
pub(super) const RESOURCE: &str = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}";
pub(super) const NETWORK: &str = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
pub(super) const ENERGY: &str = "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}";

pub(super) const ALPHA: &str = r"\Device\HarddiskVolume1\Apps\alpha.exe";
pub(super) const BETA: &str = r"\Device\HarddiskVolume1\Apps\beta.exe";
pub(super) const GAMMA: &str = "Vendor.Gamma_1.0.0.0_x64__0123456789abc";
pub(super) const SID_USER: &str = "S-1-5-21-1111-2222-3333-1001";
pub(super) const SID_SYSTEM: &str = "S-1-5-18";

/// Ids in the made-up id map.
pub(super) const ALPHA_ID: i64 = 1;
pub(super) const BETA_ID: i64 = 2;
pub(super) const GAMMA_ID: i64 = 3;
pub(super) const USER_ID: i64 = 10;
pub(super) const SYSTEM_ID: i64 = 11;

/// What to leave out or break, and whether to leave the file needing log replay.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Shape {
    pub no_energy_table: bool,
    pub no_bytes_sent_column: bool,
    pub no_id_map: bool,
    /// Leave only tables this reader does not know.
    pub unknown_schema: bool,
    /// Add an energy row whose blob has a mask bit the decoder does not know.
    pub unreadable_energy_row: bool,
    /// End the instance abruptly so the file is a dirty shutdown with its logs beside it.
    pub dirty: bool,
}

/// An OLE Automation date for an RFC 3339 time, as SRUM stores `TimeStamp`.
pub(super) fn ole(rfc3339: &str) -> f64 {
    let seconds = rfc3339.parse::<jiff::Timestamp>().unwrap().as_second();
    seconds as f64 / 86_400.0 + 25_569.0
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn sid_bytes(subauthorities: &[u32]) -> Vec<u8> {
    let mut sid = vec![1u8, subauthorities.len() as u8, 0, 0, 0, 0, 0, 5];
    for sub in subauthorities {
        sid.extend(sub.to_le_bytes());
    }
    sid
}

fn int(value: i64) -> Value {
    Value::Int(value)
}

/// Build `SRUDB.dat` (and, when `dirty`, its logs) in `dir` and return its path.
pub(super) fn build(dir: &Path, shape: Shape) -> PathBuf {
    let db = dir.join("SRUDB.dat");
    let scratch = dir.join("scratch");
    let instance = Instance::start(&Params {
        name: "pcsleuth-srum-build",
        recovery: shape.dirty,
        system_dir: dir,
        log_dir: dir,
        temp_dir: &scratch,
        base_name: "SRU",
        page_size: 4096,
        log_file_kb: 64,
        recovery_db_dir: None,
    })
    .unwrap();
    let session = instance.session().unwrap();
    let database = session.create_database(&db, shape.dirty).unwrap();

    if shape.unknown_schema {
        let table = database
            .create_table("SomethingElse", &[("Id", coltyp::LONG)])
            .unwrap();
        table.insert(&[("Id", int(1))]).unwrap();
    } else {
        if !shape.no_id_map {
            fill_id_map(&database);
        }
        fill_resource(&database);
        fill_network(&database, shape);
        if !shape.no_energy_table {
            fill_energy(&database, shape);
        }
    }

    if shape.dirty {
        // Skip the clean close of the handles: a database that is never detached is what a crash
        // leaves behind.
        std::mem::forget(database);
        std::mem::forget(session);
        instance.abandon();
    }
    db
}

fn fill_id_map(database: &super::ese::build::WritableDatabase<'_, '_>) {
    let table = database
        .create_table(
            ID_MAP,
            &[
                ("IdType", coltyp::UNSIGNED_BYTE),
                ("IdIndex", coltyp::LONG),
                ("IdBlob", coltyp::LONG_BINARY),
            ],
        )
        .unwrap();
    let rows = [
        (0, 0, Vec::new()), // the empty entry real databases start with
        (0, ALPHA_ID, utf16z(ALPHA)),
        (0, BETA_ID, utf16z(BETA)),
        (2, GAMMA_ID, utf16z(GAMMA)),
        (3, USER_ID, sid_bytes(&[21, 1111, 2222, 3333, 1001])),
        (3, SYSTEM_ID, sid_bytes(&[18])),
    ];
    for (id_type, index, blob) in rows {
        table
            .insert(&[
                ("IdType", int(id_type)),
                ("IdIndex", int(index)),
                ("IdBlob", Value::Bytes(blob)),
            ])
            .unwrap();
    }
}

struct Resource {
    at: &'static str,
    app: i64,
    user: i64,
    fg_cycles: i64,
    bg_cycles: i64,
    read: (i64, i64),
    written: (i64, i64),
}

fn fill_resource(database: &super::ese::build::WritableDatabase<'_, '_>) {
    let table = database
        .create_table(
            RESOURCE,
            &[
                ("AutoIncId", coltyp::LONG),
                ("TimeStamp", coltyp::DATE_TIME),
                ("AppId", coltyp::LONG),
                ("UserId", coltyp::LONG),
                ("ForegroundCycleTime", coltyp::LONG_LONG),
                ("BackgroundCycleTime", coltyp::LONG_LONG),
                ("ForegroundBytesRead", coltyp::LONG_LONG),
                ("ForegroundBytesWritten", coltyp::LONG_LONG),
                ("BackgroundBytesRead", coltyp::LONG_LONG),
                ("BackgroundBytesWritten", coltyp::LONG_LONG),
            ],
        )
        .unwrap();
    let rows = [
        // Before the window the tests use.
        Resource {
            at: "2026-11-02T23:59:00Z",
            app: ALPHA_ID,
            user: USER_ID,
            fg_cycles: 9_999,
            bg_cycles: 9_999,
            read: (9_999, 0),
            written: (0, 9_999),
        },
        // Two readings in the same hour for the same app and user: they add.
        Resource {
            at: "2026-11-03T10:05:00Z",
            app: ALPHA_ID,
            user: USER_ID,
            fg_cycles: 1_000,
            bg_cycles: 200,
            read: (10, 1),
            written: (20, 2),
        },
        Resource {
            at: "2026-11-03T10:50:00Z",
            app: ALPHA_ID,
            user: USER_ID,
            fg_cycles: 500,
            bg_cycles: 0,
            read: (5, 0),
            written: (0, 0),
        },
        // The next hour.
        Resource {
            at: "2026-11-03T11:10:00Z",
            app: ALPHA_ID,
            user: USER_ID,
            fg_cycles: 70,
            bg_cycles: 7,
            read: (3, 0),
            written: (0, 4),
        },
        // Another app and user, and an app named by a package family.
        Resource {
            at: "2026-11-03T10:30:00Z",
            app: BETA_ID,
            user: SYSTEM_ID,
            fg_cycles: 0,
            bg_cycles: 4_000,
            read: (0, 100),
            written: (0, 200),
        },
        Resource {
            at: "2026-11-03T10:45:00Z",
            app: GAMMA_ID,
            user: USER_ID,
            fg_cycles: 30,
            bg_cycles: 0,
            read: (1, 0),
            written: (0, 0),
        },
        // An id the id map does not know.
        Resource {
            at: "2026-11-03T10:46:00Z",
            app: 77,
            user: USER_ID,
            fg_cycles: 1,
            bg_cycles: 1,
            read: (0, 0),
            written: (0, 0),
        },
    ];
    for (n, row) in rows.iter().enumerate() {
        table
            .insert(&[
                ("AutoIncId", int(n as i64)),
                ("TimeStamp", Value::Date(ole(row.at))),
                ("AppId", int(row.app)),
                ("UserId", int(row.user)),
                ("ForegroundCycleTime", int(row.fg_cycles)),
                ("BackgroundCycleTime", int(row.bg_cycles)),
                ("ForegroundBytesRead", int(row.read.0)),
                ("ForegroundBytesWritten", int(row.written.0)),
                ("BackgroundBytesRead", int(row.read.1)),
                ("BackgroundBytesWritten", int(row.written.1)),
            ])
            .unwrap();
    }
}

fn fill_network(database: &super::ese::build::WritableDatabase<'_, '_>, shape: Shape) {
    let mut columns = vec![
        ("AutoIncId", coltyp::LONG),
        ("TimeStamp", coltyp::DATE_TIME),
        ("AppId", coltyp::LONG),
        ("UserId", coltyp::LONG),
        ("BytesRecvd", coltyp::LONG_LONG),
        ("InterfaceLuid", coltyp::LONG_LONG),
    ];
    if !shape.no_bytes_sent_column {
        columns.push(("BytesSent", coltyp::LONG_LONG));
    }
    let table = database.create_table(NETWORK, &columns).unwrap();
    // (time, app, user, received, sent, interface): two interfaces for one app in one hour.
    let rows = [
        ("2026-11-03T10:10:00Z", ALPHA_ID, USER_ID, 1_000, 100, 1),
        ("2026-11-03T10:40:00Z", ALPHA_ID, USER_ID, 500, 50, 2),
        ("2026-11-03T11:00:00Z", BETA_ID, SYSTEM_ID, 20, 10, 1),
    ];
    for (n, (at, app, user, received, sent, interface)) in rows.into_iter().enumerate() {
        let mut row = vec![
            ("AutoIncId", int(n as i64)),
            ("TimeStamp", Value::Date(ole(at))),
            ("AppId", int(app)),
            ("UserId", int(user)),
            ("BytesRecvd", int(received)),
            ("InterfaceLuid", int(interface)),
        ];
        if !shape.no_bytes_sent_column {
            row.push(("BytesSent", int(sent)));
        }
        table.insert(&row).unwrap();
    }
}

fn fill_energy(database: &super::ese::build::WritableDatabase<'_, '_>, shape: Shape) {
    let table = database
        .create_table(
            ENERGY,
            &[
                ("AutoIncId", coltyp::LONG),
                ("TimeStamp", coltyp::DATE_TIME),
                ("AppId", coltyp::LONG),
                ("UserId", coltyp::LONG),
                ("BinaryData", coltyp::BINARY),
            ],
        )
        .unwrap();
    let battery = EnergyRecord {
        on_battery: true,
        cpu: 100,
        disk: 10,
        loss: 5,
        cpu_attributed: 80,
        ..EnergyRecord::default()
    }; // total 115
    let mains = EnergyRecord {
        cpu: 200,
        ..EnergyRecord::default()
    }; // total 200
    let display = EnergyRecord {
        on_battery: true,
        display: 3_000,
        ..EnergyRecord::default()
    }; // total 3000
    let mut rows = vec![
        (
            "2026-11-03T10:05:00Z",
            ALPHA_ID,
            USER_ID,
            encode_energy(&battery),
        ),
        (
            "2026-11-03T10:50:00Z",
            ALPHA_ID,
            USER_ID,
            encode_energy(&mains),
        ),
        (
            "2026-11-03T11:00:00Z",
            BETA_ID,
            SYSTEM_ID,
            encode_energy(&display),
        ),
    ];
    if shape.unreadable_energy_row {
        let mut odd = encode_energy(&battery);
        odd[8..12].copy_from_slice(&((1u32 << 2) | (1 << 9)).to_le_bytes());
        rows.push(("2026-11-03T10:20:00Z", ALPHA_ID, USER_ID, odd));
    }
    for (n, (at, app, user, blob)) in rows.into_iter().enumerate() {
        table
            .insert(&[
                ("AutoIncId", int(n as i64)),
                ("TimeStamp", Value::Date(ole(at))),
                ("AppId", int(app)),
                ("UserId", int(user)),
                ("BinaryData", Value::Bytes(blob)),
            ])
            .unwrap();
    }
}
