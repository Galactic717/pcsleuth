//! The SRUM database read through ESENT on a shadow copy (ADR 0004).
//!
//! SRUM (the System Resource Usage Monitor) keeps hourly-ish per-app counters in `SRUDB.dat`, an
//! ESE database that a running service locks and that only an administrator can read. This module
//! reads a *copy* of it:
//!
//! - [`snapshot_copy`] (elevated only) copies the database and its logs out of a volume shadow
//!   copy and replays the logs on the copy.
//! - [`read_usage`] opens a copy read-only through `esent.dll` and returns per app, per hour
//!   counters as a [`Sourced`](pcsleuth_core::Sourced). A copy that is still a dirty shutdown has
//!   its logs replayed first, in place, so pass a copy you own.
//! - [`aggregate`] sums those buckets over a time range.
//!
//! The decoding is pure and builds everywhere; only the ESENT calls are `cfg(windows)`.
//!
//! Tables read, by their ESE names (verified against a real Windows 11 build 26300 database):
//!
//! | Table | What | Columns used |
//! |---|---|---|
//! | `SruDbIdMapTable` | id to app, service, package or user SID | `IdIndex`, `IdBlob` |
//! | `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | application resource usage | `TimeStamp`, `AppId`, `UserId`, foreground and background cycle time, bytes read and written |
//! | `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | network data usage | `TimeStamp`, `AppId`, `UserId`, `BytesSent`, `BytesRecvd` |
//! | `{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}` | energy estimation, one packed blob per row | `TimeStamp`, `AppId`, `UserId`, `BinaryData` |
//!
//! `TimeStamp` is the time of the write, not the top of an hour, so readings are floored to the
//! UTC hour here.

// The decoding and bucketing are pure and build and test everywhere. Off Windows nothing reads a
// database, so the parts only the Windows reader calls are unused there by design.
#[cfg_attr(not(windows), allow(dead_code))]
mod decode;
mod energy;
#[cfg_attr(not(windows), allow(dead_code))]
mod usage;

#[cfg(windows)]
mod copy;
#[cfg(windows)]
mod ese;
#[cfg(windows)]
mod reader;
#[cfg(all(windows, test))]
mod testdb;

pub use decode::{IdName, decode_id_blob};
pub use energy::{EnergyBlobError, EnergyRecord, decode_energy};
pub use usage::{AppTotal, AppUsage, Usage, aggregate, hour_start};

#[cfg(windows)]
pub use copy::{TempCopy, snapshot_copy};

/// A table this reader knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrumTable {
    IdMap,
    ResourceUsage,
    NetworkUsage,
    EnergyEstimation,
}

impl SrumTable {
    /// The name of the table inside the ESE file.
    pub const fn table_name(self) -> &'static str {
        match self {
            SrumTable::IdMap => "SruDbIdMapTable",
            SrumTable::ResourceUsage => "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
            SrumTable::NetworkUsage => "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
            SrumTable::EnergyEstimation => "{DA73FB89-2BEA-4DDC-86B8-6E048C6DA477}",
        }
    }
}

/// Something about this database that is not an error but changes what the numbers mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaNote {
    /// The table is not in this database (older or newer Windows), so its counters read zero.
    TableAbsent(SrumTable),
    /// The column is not in the table. Optional columns read zero; a missing required column
    /// makes the whole table unreadable.
    ColumnAbsent { table: SrumTable, column: String },
    /// Energy rows whose blob this reader could not decode were left out of the sums.
    EnergyRecordsSkipped { count: u64 },
    /// The copy was a dirty shutdown and its transaction logs were replayed before reading.
    LogsReplayed,
}

/// Per app, per hour counters with the notes that qualify them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageReport {
    pub usage: pcsleuth_core::Sourced<AppUsage>,
    pub notes: Vec<SchemaNote>,
}

/// Read per app, per hour usage in `[since, until)` from a private copy of `SRUDB.dat`, as the
/// source contract wants it. See [`read_usage_report`] for the schema notes.
#[cfg(windows)]
pub fn read_usage(
    db_copy: &std::path::Path,
    since: jiff::Timestamp,
    until: jiff::Timestamp,
) -> pcsleuth_core::Sourced<AppUsage> {
    read_usage_report(db_copy, since, until).usage
}

/// Like [`read_usage`], with the typed notes about absent tables and columns.
///
/// `db_copy` must be a copy this process may rewrite: if it is a dirty shutdown, its logs (the
/// `SRU*.log` files beside it) are replayed into it first. The database is otherwise opened
/// read-only, and ESE's temporary files go to a private folder that is deleted afterwards, so
/// nothing is written beside a clean copy.
///
/// Never panics on bad input: a missing file is [`Access::Missing`](pcsleuth_core::Access), a
/// locked one is `NeedsAdmin`, and anything else, including a schema this reader does not know, is
/// `Failed` with the reason. If a read fails part way, `usage.data` keeps what was read.
#[cfg(windows)]
pub fn read_usage_report(
    db_copy: &std::path::Path,
    since: jiff::Timestamp,
    until: jiff::Timestamp,
) -> UsageReport {
    use pcsleuth_core::{Access, SourceId, Sourced};

    let report = |access: Access, data: Vec<AppUsage>, notes: Vec<SchemaNote>| UsageReport {
        usage: Sourced {
            source: SourceId::Srum,
            access,
            data,
        },
        notes,
    };
    let fail = |access: Access| report(access, Vec::new(), Vec::new());

    if let Err(err) = std::fs::metadata(db_copy) {
        return fail(copy::io_access(&err));
    }
    let scratch = match copy::ScratchDir::new("srum-read") {
        Ok(scratch) => scratch,
        Err(err) => return fail(copy::io_access(&err)),
    };
    let mut notes = Vec::new();
    match ese::database_is_dirty(db_copy) {
        Ok(false) => {}
        Ok(true) => {
            if let Err(err) = copy::recover(db_copy, scratch.path()) {
                return fail(reader::Failure::Ese(err).access());
            }
            notes.push(SchemaNote::LogsReplayed);
        }
        Err(err) => return fail(reader::Failure::Ese(err).access()),
    }
    let outcome = reader::read_clean(db_copy, scratch.path(), since, until);
    notes.extend(outcome.notes);
    let access = outcome
        .failure
        .map_or(Access::Ok, |failure| failure.access());
    report(access, outcome.usage, notes)
}

#[cfg(all(windows, test))]
mod tests {
    use std::path::{Path, PathBuf};

    use jiff::Timestamp;
    use pcsleuth_core::{Access, SourceId};

    use super::copy::ScratchDir;
    use super::testdb::{self, *};
    use super::*;

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn whole_day() -> (Timestamp, Timestamp) {
        (ts("2026-11-03T00:00:00Z"), ts("2026-11-04T00:00:00Z"))
    }

    fn built(shape: Shape) -> (ScratchDir, PathBuf) {
        let dir = ScratchDir::new("srum-test").unwrap();
        let db = testdb::build(dir.path(), shape);
        (dir, db)
    }

    fn read(db: &Path) -> UsageReport {
        let (since, until) = whole_day();
        read_usage_report(db, since, until)
    }

    fn bucket<'a>(report: &'a UsageReport, app: &str, hour: &str) -> &'a AppUsage {
        report
            .usage
            .data
            .iter()
            .find(|b| b.app == app && b.hour == ts(hour))
            .unwrap_or_else(|| panic!("no bucket for {app} at {hour}"))
    }

    #[test]
    fn reads_hour_buckets_through_esent() {
        let (_dir, db) = built(Shape::default());
        let report = read(&db);
        assert_eq!(report.usage.source, SourceId::Srum);
        assert_eq!(report.usage.access, Access::Ok);
        assert_eq!(report.notes, []);
        // alpha/user at 10:00: two readings add up in every table.
        let alpha = bucket(&report, ALPHA, "2026-11-03T10:00:00Z");
        assert_eq!(alpha.user.as_deref(), Some(SID_USER));
        assert_eq!(
            alpha.usage,
            Usage {
                cpu_cycles_foreground: 1_500,
                cpu_cycles_background: 200,
                bytes_read: 10 + 5 + 1,
                bytes_written: 20 + 2,
                net_sent: 150,
                net_received: 1_500,
                energy: 115 + 200,
                energy_on_battery: 115,
            }
        );
        // The next hour has resource counters only.
        let later = bucket(&report, ALPHA, "2026-11-03T11:00:00Z");
        assert_eq!(later.usage.cpu_cycles(), 77);
        assert_eq!(later.usage.energy, 0);
        // Another app and user; network and energy arrive in a later hour than its resource row.
        let beta = bucket(&report, BETA, "2026-11-03T10:00:00Z");
        assert_eq!(beta.user.as_deref(), Some(SID_SYSTEM));
        assert_eq!(
            (beta.usage.bytes_read, beta.usage.bytes_written),
            (100, 200)
        );
        let beta_later = bucket(&report, BETA, "2026-11-03T11:00:00Z");
        assert_eq!(
            (beta_later.usage.net_sent, beta_later.usage.net_received),
            (10, 20)
        );
        assert_eq!(
            (beta_later.usage.energy, beta_later.usage.energy_on_battery),
            (3_000, 3_000)
        );
        // A package family name decodes like a path, and an unknown id keeps a placeholder.
        assert_eq!(
            bucket(&report, GAMMA, "2026-11-03T10:00:00Z")
                .usage
                .cpu_cycles(),
            30
        );
        assert_eq!(
            bucket(&report, "#77", "2026-11-03T10:00:00Z")
                .user
                .as_deref(),
            Some(SID_USER)
        );
        // The reading from the day before is outside the window.
        assert_eq!(report.usage.data.len(), 6);
    }

    #[test]
    fn the_window_is_half_open_on_the_reading_time() {
        let (_dir, db) = built(Shape::default());
        let report = read_usage_report(&db, ts("2026-11-03T10:50:00Z"), ts("2026-11-03T11:10:00Z"));
        // 10:50 is in, 11:10 is out: only the 10:50 resource, energy and (none) network readings.
        let alpha = bucket(&report, ALPHA, "2026-11-03T10:00:00Z");
        assert_eq!(alpha.usage.cpu_cycles(), 500);
        assert_eq!(alpha.usage.energy, 200);
        assert_eq!(alpha.usage.net_sent, 0);
        assert!(
            report
                .usage
                .data
                .iter()
                .all(|b| b.hour == ts("2026-11-03T10:00:00Z")
                    || b.hour == ts("2026-11-03T11:00:00Z"))
        );
        assert!(!report.usage.data.iter().any(|b| b.usage.cpu_cycles() == 77));
    }

    #[test]
    fn aggregate_over_the_report_sums_per_app() {
        let (_dir, db) = built(Shape::default());
        let report = read(&db);
        let totals = aggregate(
            &report.usage.data,
            ts("2026-11-03T00:00:00Z"),
            ts("2026-11-04T00:00:00Z"),
        );
        // Biggest energy first: beta (3000) then alpha (315).
        assert_eq!(totals[0].app, BETA);
        assert_eq!(totals[1].app, ALPHA);
        assert_eq!(totals[1].hours, 2);
        assert_eq!(totals[1].usage.energy, 315);
        assert_eq!(totals[1].usage.on_battery_share(), Some(115.0 / 315.0));
    }

    #[test]
    fn an_absent_energy_table_is_a_note_and_the_rest_still_reads() {
        let (_dir, db) = built(Shape {
            no_energy_table: true,
            ..Shape::default()
        });
        let report = read(&db);
        assert_eq!(report.usage.access, Access::Ok);
        assert_eq!(
            report.notes,
            [SchemaNote::TableAbsent(SrumTable::EnergyEstimation)]
        );
        let alpha = bucket(&report, ALPHA, "2026-11-03T10:00:00Z");
        assert_eq!(alpha.usage.energy, 0);
        assert_eq!(alpha.usage.cpu_cycles_foreground, 1_500);
    }

    #[test]
    fn an_absent_optional_column_is_a_note_and_reads_as_zero() {
        let (_dir, db) = built(Shape {
            no_bytes_sent_column: true,
            ..Shape::default()
        });
        let report = read(&db);
        assert_eq!(
            report.notes,
            [SchemaNote::ColumnAbsent {
                table: SrumTable::NetworkUsage,
                column: "BytesSent".into()
            }]
        );
        let alpha = bucket(&report, ALPHA, "2026-11-03T10:00:00Z");
        assert_eq!((alpha.usage.net_sent, alpha.usage.net_received), (0, 1_500));
    }

    #[test]
    fn an_absent_id_map_falls_back_to_placeholder_names() {
        let (_dir, db) = built(Shape {
            no_id_map: true,
            ..Shape::default()
        });
        let report = read(&db);
        assert_eq!(report.notes, [SchemaNote::TableAbsent(SrumTable::IdMap)]);
        let alpha = bucket(&report, "#1", "2026-11-03T10:00:00Z");
        assert_eq!(alpha.user, None);
        assert_eq!(alpha.usage.cpu_cycles_foreground, 1_500);
    }

    #[test]
    fn energy_rows_with_an_unknown_layout_are_counted_not_summed() {
        let (_dir, db) = built(Shape {
            unreadable_energy_row: true,
            ..Shape::default()
        });
        let report = read(&db);
        assert_eq!(
            report.notes,
            [SchemaNote::EnergyRecordsSkipped { count: 1 }]
        );
        assert_eq!(
            bucket(&report, ALPHA, "2026-11-03T10:00:00Z").usage.energy,
            315
        );
    }

    #[test]
    fn an_unknown_schema_is_failed_with_a_reason_never_a_panic() {
        let (_dir, db) = built(Shape {
            unknown_schema: true,
            ..Shape::default()
        });
        let report = read(&db);
        assert!(report.usage.data.is_empty());
        match report.usage.access {
            Access::Failed { message, .. } => assert!(message.contains("unrecognized SRUM schema")),
            other => panic!("expected Failed, got {other}"),
        }
    }

    #[test]
    fn a_missing_file_and_a_file_that_is_not_a_database_degrade_cleanly() {
        let dir = ScratchDir::new("srum-test").unwrap();
        let (since, until) = whole_day();
        let missing = read_usage(&dir.path().join("nope.dat"), since, until);
        assert_eq!(missing.access, Access::Missing);

        let garbage = dir.path().join("garbage.dat");
        std::fs::write(&garbage, vec![0x5Au8; 16 * 1024]).unwrap();
        let garbage = read_usage(&garbage, since, until);
        assert!(
            matches!(garbage.access, Access::Failed { .. }),
            "{}",
            garbage.access
        );

        let empty = dir.path().join("empty.dat");
        std::fs::write(&empty, b"").unwrap();
        assert!(matches!(
            read_usage(&empty, since, until).access,
            Access::Failed { .. }
        ));
    }

    #[test]
    fn reading_a_clean_copy_writes_nothing_beside_it_and_leaves_the_file_unchanged() {
        let (dir, db) = built(Shape::default());
        let listing = |dir: &Path| {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            entries.sort();
            entries
        };
        let before_files = listing(dir.path());
        let before_bytes = std::fs::read(&db).unwrap();
        let report = read(&db);
        assert_eq!(report.usage.access, Access::Ok);
        assert_eq!(listing(dir.path()), before_files);
        assert_eq!(std::fs::read(&db).unwrap(), before_bytes);
    }

    #[test]
    fn a_dirty_copy_is_replayed_in_place_and_then_read() {
        let (dir, db) = built(Shape {
            dirty: true,
            ..Shape::default()
        });
        assert!(
            ese::database_is_dirty(&db).unwrap(),
            "the builder should leave a dirty file"
        );
        let report = read(&db);
        assert_eq!(report.usage.access, Access::Ok);
        assert_eq!(report.notes, [SchemaNote::LogsReplayed]);
        assert_eq!(report.usage.data.len(), 6);
        assert_eq!(
            bucket(&report, ALPHA, "2026-11-03T10:00:00Z").usage.energy,
            315
        );
        assert!(!ese::database_is_dirty(&db).unwrap());
        // A second read finds a clean file and replays nothing.
        assert_eq!(read(&db).notes, []);
        drop(dir);
    }

    #[test]
    fn a_dirty_copy_without_its_logs_fails_with_a_reason_and_later_reads_still_work() {
        let (dir, db) = built(Shape {
            dirty: true,
            ..Shape::default()
        });
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|e| e == "log" || e == "chk" || e == "jrs")
            {
                std::fs::remove_file(path).unwrap();
            }
        }
        let report = read(&db);
        assert!(report.usage.data.is_empty());
        assert!(
            matches!(report.usage.access, Access::Failed { .. }),
            "{}",
            report.usage.access
        );

        let (_other, clean) = built(Shape::default());
        assert_eq!(read(&clean).usage.access, Access::Ok);
    }

    /// Needs an elevated shell, because only then can `esentutl /vss` read the live database.
    /// The lead runs it with the owner's permission: `cargo test -p pcsleuth-sources
    /// elevated_srum_snapshot -- --ignored --nocapture`. Never run unelevated or by a tool.
    #[test]
    #[ignore = "needs an elevated process and the owner's permission"]
    fn elevated_srum_snapshot() {
        let copy = snapshot_copy().expect("run this from an elevated shell");
        let db = copy.db_path();
        assert!(db.is_file());
        assert!(
            !ese::database_is_dirty(&db).unwrap(),
            "the copy should be replayed"
        );

        let now = Timestamp::now().as_second();
        let since = Timestamp::from_second(now - 7 * 86_400).unwrap();
        let report = read_usage_report(&db, since, Timestamp::from_second(now + 3_600).unwrap());
        eprintln!(
            "elevated snapshot: access={} buckets={} notes={:?}",
            report.usage.access,
            report.usage.data.len(),
            report.notes
        );
        assert_eq!(report.usage.access, Access::Ok);
        assert!(!report.usage.data.is_empty());

        drop(copy);
        assert!(!db.exists(), "dropping the copy deletes it");
    }

    /// Copy the owner's private SRUM folder (named by `PCSLEUTH_REAL_SRUDB`, a folder or the
    /// `SRUDB.dat` in it) to a scratch folder and read it. Asserts shape and counts only, and
    /// compares energy with the `srumutil.csv` that `powercfg /srumutil /csv` wrote beside it.
    /// Prints numbers, never app or user names.
    #[test]
    #[ignore = "needs PCSLEUTH_REAL_SRUDB, the owner's private SRUM copy"]
    fn real_copy_shape_counts_and_srumutil_oracle() {
        use std::collections::{BTreeMap, BTreeSet};

        let given = PathBuf::from(
            std::env::var_os("PCSLEUTH_REAL_SRUDB")
                .expect("set PCSLEUTH_REAL_SRUDB to the folder holding SRUDB.dat"),
        );
        let source = if given.is_dir() {
            given
        } else {
            given.parent().unwrap().to_path_buf()
        };
        let scratch = ScratchDir::new("srum-real").unwrap();
        for entry in std::fs::read_dir(&source).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name.starts_with("sru") && entry.path().is_file() {
                std::fs::copy(entry.path(), scratch.path().join(entry.file_name())).unwrap();
            }
        }
        let db = scratch.path().join("SRUDB.dat");
        let was_dirty = ese::database_is_dirty(&db).unwrap();

        let started = std::time::Instant::now();
        let report = read_usage_report(&db, ts("1970-01-01T00:00:00Z"), ts("2100-01-01T00:00:00Z"));
        let data = &report.usage.data;
        let apps: BTreeSet<&str> = data.iter().map(|b| b.app.as_str()).collect();
        let users: BTreeSet<Option<&str>> = data.iter().map(|b| b.user.as_deref()).collect();
        let energy: u64 = data.iter().map(|b| b.usage.energy).sum();
        let on_battery: u64 = data.iter().map(|b| b.usage.energy_on_battery).sum();
        eprintln!(
            "real copy: was_dirty={was_dirty} access={} notes={:?} elapsed_ms={} buckets={} apps={} users={} \
             first_hour={} last_hour={} energy={energy} energy_on_battery={on_battery}",
            report.usage.access,
            report.notes,
            started.elapsed().as_millis(),
            data.len(),
            apps.len(),
            users.len(),
            data.first().map_or(String::new(), |b| b.hour.to_string()),
            data.last().map_or(String::new(), |b| b.hour.to_string()),
        );

        // Shape and counts only.
        assert_eq!(report.usage.access, Access::Ok);
        assert!(!data.is_empty());
        assert!(data.iter().all(|b| b.hour.as_second() % 3_600 == 0));
        assert!(data.windows(2).all(|w| w[0].hour <= w[1].hour));
        assert!(
            report.notes.iter().all(|note| matches!(
                note,
                SchemaNote::LogsReplayed | SchemaNote::EnergyRecordsSkipped { .. }
            )),
            "unexpected schema notes: {:?}",
            report.notes
        );
        assert_eq!(report.notes.contains(&SchemaNote::LogsReplayed), was_dirty);
        assert!(data.iter().any(|b| b.usage.cpu_cycles() > 0));
        assert!(data.iter().any(|b| b.usage.bytes_written > 0));
        assert!(data.iter().any(|b| b.usage.net_received > 0));
        assert!(energy > 0 && on_battery > 0 && on_battery < energy);
        assert!(data.iter().all(|b| !b.app.is_empty()));

        // The oracle: `powercfg /srumutil /csv`, taken a little later than the shadow copy, so the
        // newest day is compared only up to the point both could have seen. Compare whole days
        // before the CSV's last day.
        let csv_path = source.join("srumutil.csv");
        let Ok(csv_bytes) = std::fs::read(&csv_path) else {
            eprintln!("oracle: no srumutil.csv beside the database, skipped");
            return;
        };
        let csv = String::from_utf8_lossy(&csv_bytes);
        let mut lines = csv.trim_start_matches('\u{feff}').lines();
        let header: Vec<&str> = lines.next().unwrap().split(',').map(str::trim).collect();
        let col = |name: &str| header.iter().position(|h| *h == name).unwrap();
        let (c_app, c_time, c_bat, c_total) = (
            col("AppId"),
            col("TimeStamp"),
            col("OnBattery"),
            col("TotalEnergyConsumption"),
        );
        let mut rows: Vec<(String, Timestamp, bool, u64)> = Vec::new();
        let mut malformed = 0u32;
        for line in lines {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            let parsed = (fields.len() == header.len())
                .then(|| {
                    let time = format!("{}Z", fields[c_time].get(..19)?);
                    Some((
                        fields[c_app].to_owned(),
                        time.parse::<Timestamp>().ok()?,
                        fields[c_bat].eq_ignore_ascii_case("TRUE"),
                        fields[c_total].parse::<u64>().ok()?,
                    ))
                })
                .flatten();
            match parsed {
                Some(row) => rows.push(row),
                None => malformed += 1,
            }
        }
        let last = rows.iter().map(|r| r.1).max().unwrap();
        let cutoff = hour_start(
            Timestamp::from_second(last.as_second() - last.as_second() % 86_400).unwrap(),
        );

        let mut csv_by_app: BTreeMap<&str, u64> = BTreeMap::new();
        let (mut csv_total, mut csv_battery) = (0u64, 0u64);
        for (app, _, battery, total) in rows.iter().filter(|r| r.1 < cutoff) {
            *csv_by_app.entry(app).or_default() += total;
            csv_total += total;
            if *battery {
                csv_battery += total;
            }
        }
        let mut reader_by_app: BTreeMap<&str, u64> = BTreeMap::new();
        let (mut reader_total, mut reader_battery) = (0u64, 0u64);
        for bucket in data.iter().filter(|b| b.hour < cutoff) {
            *reader_by_app.entry(bucket.app.as_str()).or_default() += bucket.usage.energy;
            reader_total += bucket.usage.energy;
            reader_battery += bucket.usage.energy_on_battery;
        }
        let compared: Vec<_> = csv_by_app
            .iter()
            .filter(|(app, _)| reader_by_app.contains_key(**app))
            .collect();
        let exact = compared
            .iter()
            .filter(|(app, total)| reader_by_app[**app] == **total)
            .count();
        let top = csv_by_app
            .iter()
            .filter(|(app, _)| reader_by_app.contains_key(**app))
            .max_by_key(|(_, total)| **total)
            .map(|(app, total)| (*total, reader_by_app[*app]));
        eprintln!(
            "oracle: csv_rows={} malformed={malformed} days_before_cutoff_end={cutoff} \
             csv_total={csv_total} reader_total={reader_total} csv_on_battery={csv_battery} reader_on_battery={reader_battery} \
             apps_csv={} apps_reader={} apps_in_both={} apps_exact={exact} top_app_csv_vs_reader={top:?}",
            rows.len(),
            csv_by_app.len(),
            reader_by_app.len(),
            compared.len(),
        );
        assert_eq!(
            reader_total, csv_total,
            "whole-day energy must match powercfg exactly"
        );
        assert_eq!(reader_battery, csv_battery);
        assert!(compared.len() > 100 && exact * 100 >= compared.len() * 95);
    }
}
