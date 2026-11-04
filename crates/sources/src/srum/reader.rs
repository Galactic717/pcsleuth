//! Walks the SRUM tables of one clean database file and feeds the pure accumulator.
//!
//! Nothing is dropped without being counted. A row whose time or ids cannot be read, a counter
//! that is null or not a number, and a value too large to read are tallied per table and reported
//! as notes, so the caller can say the numbers are incomplete.

use std::path::Path;

use jiff::Timestamp;
use pcsleuth_core::Access;

use super::decode::{Counter, Value, decode_id_blob};
use super::energy::decode_energy;
use super::ese::{Column, Database, EseError, Instance, Params, Table, database_page_size};
use super::usage::{Accumulator, AppUsage, IdMap, Usage};
use super::{SchemaNote, SrumTable};

/// Why a read stopped before the end.
#[derive(Debug)]
pub(super) enum Failure {
    Ese(EseError),
    /// The file opened but holds none of the tables this reader knows.
    UnknownSchema(String),
}

impl Failure {
    pub(super) fn access(&self) -> Access {
        match self {
            Failure::Ese(err) if err.is_missing_file() => Access::Missing,
            Failure::Ese(err) if err.is_access_denied() => Access::NeedsAdmin,
            Failure::Ese(err) => Access::Failed {
                code: err.code as u32,
                message: err.to_string(),
            },
            Failure::UnknownSchema(message) => Access::Failed {
                code: 0,
                message: format!("unrecognized SRUM schema: {message}"),
            },
        }
    }
}

impl From<EseError> for Failure {
    fn from(err: EseError) -> Self {
        Failure::Ese(err)
    }
}

pub(super) struct Outcome {
    pub usage: Vec<AppUsage>,
    pub notes: Vec<SchemaNote>,
    /// Set when the read stopped early; `usage` then holds what was read before that.
    pub failure: Option<Failure>,
}

/// Read every known table of `db`, which must be a clean copy, into hour buckets in
/// `[since, until)`. `scratch` is where ESE puts its temporary database; nothing is written
/// beside `db`.
pub(super) fn read_clean(db: &Path, scratch: &Path, since: Timestamp, until: Timestamp) -> Outcome {
    let mut notes = Vec::new();
    let mut accumulator = Accumulator::new(since, until);
    let mut names = IdMap::default();
    let result = read_tables(db, scratch, &mut accumulator, &mut names, &mut notes);
    Outcome {
        usage: accumulator.finish(&names),
        notes,
        failure: result.err(),
    }
}

fn read_tables(
    db: &Path,
    scratch: &Path,
    accumulator: &mut Accumulator,
    names: &mut IdMap,
    notes: &mut Vec<SchemaNote>,
) -> Result<(), Failure> {
    let page_size = database_page_size(db)?;
    let instance = Instance::start(&Params {
        name: &format!("pcsleuth-srum-read-{}", std::process::id()),
        recovery: false,
        system_dir: scratch,
        log_dir: scratch,
        temp_dir: scratch,
        base_name: "edb",
        page_size,
        log_file_kb: 64,
        recovery_db_dir: None,
    })?;
    let session = instance.session()?;
    let database = session.open_read_only(db)?;

    let mut read_any = false;
    read_id_map(&database, names, notes)?;
    read_any |= read_resource_usage(&database, accumulator, notes)?;
    read_any |= read_network_usage(&database, accumulator, notes)?;
    read_any |= read_energy(&database, accumulator, notes)?;
    if read_any {
        return Ok(());
    }
    let tables = database.tables()?;
    Err(Failure::UnknownSchema(format!(
        "none of the SRUM usage tables is present or readable in this {}-table database",
        tables.len()
    )))
}

/// What one table gave up on: rows left out, and counter values that read as zero.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    rows: u64,
    values: u64,
}

impl Tally {
    /// Add a note for each kind of loss, if there was any.
    fn report(&self, table: SrumTable, notes: &mut Vec<SchemaNote>) {
        if self.rows > 0 {
            notes.push(SchemaNote::RowsSkipped {
                table,
                count: self.rows,
            });
        }
        if self.values > 0 {
            notes.push(SchemaNote::ValuesUnreadable {
                table,
                count: self.values,
            });
        }
    }
}

/// Open `which`, or note that it is absent.
fn open_table<'d, 's, 'i>(
    database: &'d Database<'s, 'i>,
    which: SrumTable,
    notes: &mut Vec<SchemaNote>,
) -> Result<Option<Table<'d, 's, 'i>>, EseError> {
    let table = database.table(which.table_name())?;
    if table.is_none() {
        notes.push(SchemaNote::TableAbsent(which));
    }
    Ok(table)
}

/// Look up `spec` columns by name. A missing column is noted; `None` comes back when a required
/// one is missing, because the table cannot be read without it.
fn resolve_columns(
    table: &Table<'_, '_, '_>,
    which: SrumTable,
    spec: &[(&'static str, bool)],
    notes: &mut Vec<SchemaNote>,
) -> Result<Option<Vec<Option<Column>>>, EseError> {
    let mut columns = Vec::with_capacity(spec.len());
    let mut usable = true;
    for &(name, required) in spec {
        let column = table.column(name)?;
        if column.is_none() {
            notes.push(SchemaNote::ColumnAbsent {
                table: which,
                column: name.to_owned(),
            });
            usable &= !required;
        }
        columns.push(column);
    }
    Ok(usable.then_some(columns))
}

/// A value of a column that may be absent: absent and null both read as `None`.
fn cell(table: &Table<'_, '_, '_>, column: &Option<Column>) -> Result<Option<Value>, EseError> {
    match column {
        Some(column) => table.value(column).map(Some),
        None => Ok(None),
    }
}

/// A counter. A column the table lacks reads zero (that is already a `ColumnAbsent` note). A value
/// that is null, negative or not a number also reads zero, but is tallied.
fn count(
    table: &Table<'_, '_, '_>,
    column: &Option<Column>,
    tally: &mut Tally,
) -> Result<u64, EseError> {
    let Some(column) = column else {
        return Ok(0);
    };
    Ok(match table.value(column)?.counter() {
        Counter::Count(n) => n,
        Counter::Null | Counter::Invalid => {
            tally.values += 1;
            0
        }
    })
}

fn read_id_map(
    database: &Database<'_, '_>,
    names: &mut IdMap,
    notes: &mut Vec<SchemaNote>,
) -> Result<(), Failure> {
    let which = SrumTable::IdMap;
    let Some(mut table) = open_table(database, which, notes)? else {
        return Ok(());
    };
    let spec = [("IdIndex", true), ("IdBlob", true)];
    let Some(columns) = resolve_columns(&table, which, &spec, notes)? else {
        return Ok(());
    };
    let mut tally = Tally::default();
    let mut more = table.first()?;
    while more {
        let id = cell(&table, &columns[0])?.and_then(|v| v.as_i64());
        match (id, cell(&table, &columns[1])?) {
            (Some(id), Some(Value::Bytes(blob))) => names.insert(id, decode_id_blob(&blob)),
            // An entry with no name is how SRUM leaves an id unnamed.
            (Some(_), Some(Value::Null)) => {}
            _ => tally.rows += 1,
        }
        more = table.next()?;
    }
    tally.report(which, notes);
    Ok(())
}

/// `Ok(true)` when the table existed and could be read.
fn read_resource_usage(
    database: &Database<'_, '_>,
    accumulator: &mut Accumulator,
    notes: &mut Vec<SchemaNote>,
) -> Result<bool, Failure> {
    let which = SrumTable::ResourceUsage;
    let Some(mut table) = open_table(database, which, notes)? else {
        return Ok(false);
    };
    let spec = [
        ("TimeStamp", true),
        ("AppId", true),
        ("UserId", true),
        ("ForegroundCycleTime", false),
        ("BackgroundCycleTime", false),
        ("ForegroundBytesRead", false),
        ("ForegroundBytesWritten", false),
        ("BackgroundBytesRead", false),
        ("BackgroundBytesWritten", false),
    ];
    let Some(c) = resolve_columns(&table, which, &spec, notes)? else {
        return Ok(false);
    };
    let mut tally = Tally::default();
    let mut more = table.first()?;
    while more {
        match key(&table, &c[0], &c[1], &c[2], accumulator)? {
            Key::Row(at, app, user) => {
                let delta = Usage {
                    cpu_cycles_foreground: count(&table, &c[3], &mut tally)?,
                    cpu_cycles_background: count(&table, &c[4], &mut tally)?,
                    bytes_read: count(&table, &c[5], &mut tally)?
                        .saturating_add(count(&table, &c[7], &mut tally)?),
                    bytes_written: count(&table, &c[6], &mut tally)?
                        .saturating_add(count(&table, &c[8], &mut tally)?),
                    ..Usage::default()
                };
                accumulator.add(at, app, user, &delta);
            }
            Key::Outside => {}
            Key::Unreadable => tally.rows += 1,
        }
        more = table.next()?;
    }
    tally.report(which, notes);
    Ok(true)
}

fn read_network_usage(
    database: &Database<'_, '_>,
    accumulator: &mut Accumulator,
    notes: &mut Vec<SchemaNote>,
) -> Result<bool, Failure> {
    let which = SrumTable::NetworkUsage;
    let Some(mut table) = open_table(database, which, notes)? else {
        return Ok(false);
    };
    let spec = [
        ("TimeStamp", true),
        ("AppId", true),
        ("UserId", true),
        ("BytesSent", false),
        ("BytesRecvd", false),
    ];
    let Some(c) = resolve_columns(&table, which, &spec, notes)? else {
        return Ok(false);
    };
    let mut tally = Tally::default();
    let mut more = table.first()?;
    while more {
        match key(&table, &c[0], &c[1], &c[2], accumulator)? {
            Key::Row(at, app, user) => {
                let delta = Usage {
                    net_sent: count(&table, &c[3], &mut tally)?,
                    net_received: count(&table, &c[4], &mut tally)?,
                    ..Usage::default()
                };
                accumulator.add(at, app, user, &delta);
            }
            Key::Outside => {}
            Key::Unreadable => tally.rows += 1,
        }
        more = table.next()?;
    }
    tally.report(which, notes);
    Ok(true)
}

fn read_energy(
    database: &Database<'_, '_>,
    accumulator: &mut Accumulator,
    notes: &mut Vec<SchemaNote>,
) -> Result<bool, Failure> {
    let which = SrumTable::EnergyEstimation;
    let Some(mut table) = open_table(database, which, notes)? else {
        return Ok(false);
    };
    let spec = [
        ("TimeStamp", true),
        ("AppId", true),
        ("UserId", true),
        ("BinaryData", true),
    ];
    let Some(c) = resolve_columns(&table, which, &spec, notes)? else {
        return Ok(false);
    };
    let mut tally = Tally::default();
    let mut skipped = 0u64;
    let mut more = table.first()?;
    while more {
        match key(&table, &c[0], &c[1], &c[2], accumulator)? {
            Key::Row(at, app, user) => match cell(&table, &c[3])? {
                Some(Value::Bytes(blob)) => match decode_energy(&blob) {
                    Ok(record) => {
                        let total = record.total();
                        let delta = Usage {
                            energy: total,
                            energy_on_battery: if record.on_battery { total } else { 0 },
                            ..Usage::default()
                        };
                        accumulator.add(at, app, user, &delta);
                    }
                    Err(_) => skipped += 1,
                },
                _ => skipped += 1,
            },
            Key::Outside => {}
            Key::Unreadable => tally.rows += 1,
        }
        more = table.next()?;
    }
    if skipped > 0 {
        notes.push(SchemaNote::EnergyRecordsSkipped { count: skipped });
    }
    tally.report(which, notes);
    Ok(true)
}

/// What the time and ids of the current row say about it.
enum Key {
    /// A reading in the window.
    Row(Timestamp, i64, i64),
    /// A reading with a readable time outside the window. Not an error.
    Outside,
    /// No readable time, app id or user id: the row cannot be placed, so it is counted.
    Unreadable,
}

/// The time and ids of the current row. Checking the time first skips the other columns of rows
/// outside the window.
fn key(
    table: &Table<'_, '_, '_>,
    time: &Option<Column>,
    app: &Option<Column>,
    user: &Option<Column>,
    accumulator: &Accumulator,
) -> Result<Key, EseError> {
    let Some(at) = cell(table, time)?.and_then(|v| v.as_timestamp()) else {
        return Ok(Key::Unreadable);
    };
    if !accumulator.contains(at) {
        return Ok(Key::Outside);
    }
    let app = cell(table, app)?.and_then(|v| v.as_i64());
    let user = cell(table, user)?.and_then(|v| v.as_i64());
    Ok(match app.zip(user) {
        Some((app, user)) => Key::Row(at, app, user),
        None => Key::Unreadable,
    })
}
