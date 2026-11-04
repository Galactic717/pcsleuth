//! A thin RAII layer over `esent.dll`, just enough to open a database read-only and walk tables.
//!
//! Handles close in the right order on every path, including errors: an [`Instance`] owns the
//! process-wide gate, a [`Session`] borrows it, a [`Database`] borrows the session and a [`Table`]
//! borrows the database. Every `unsafe` block is a single ESENT call whose pointers point at locals
//! that outlive it.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use windows::Win32::Storage::Jet as jet;
use windows::Win32::Storage::StructuredStorage::JET_TABLEID;

use super::decode::{Value, utf16_units};

/// ESENT keeps some parameters (the page size) per process, not per instance, so at most one
/// [`Instance`] exists at a time. A single global lock is enough until a caller needs two
/// databases open at once.
static GATE: Mutex<()> = Mutex::new(());

// `JET_ColInfo*` and `JET_ObjInfo*` are C macros the bindings do not carry.
const COL_INFO: u32 = 0;
const OBJ_INFO_LIST_NO_STATS: u32 = 1;
const MOVE_FIRST: i32 = jet::JET_MoveFirst as i32;
const MOVE_NEXT: i32 = 1;

/// An ESENT call that returned a negative `JET_err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EseError {
    pub code: i32,
    pub call: &'static str,
}

impl EseError {
    /// The `JET_err` name when it is one this reader meets, so a message is searchable.
    pub(super) fn name(self) -> &'static str {
        match self.code {
            jet::JET_errDatabaseDirtyShutdown => "JET_errDatabaseDirtyShutdown",
            jet::JET_errFileNotFound => "JET_errFileNotFound",
            jet::JET_errFileAccessDenied => "JET_errFileAccessDenied",
            jet::JET_errDatabaseNotFound => "JET_errDatabaseNotFound",
            jet::JET_errPageSizeMismatch => "JET_errPageSizeMismatch",
            jet::JET_errLogFileSizeMismatch => "JET_errLogFileSizeMismatch",
            jet::JET_errMissingLogFile => "JET_errMissingLogFile",
            jet::JET_errMissingPreviousLogFile => "JET_errMissingPreviousLogFile",
            jet::JET_errBadLogSignature => "JET_errBadLogSignature",
            jet::JET_errDatabaseInUse => "JET_errDatabaseInUse",
            jet::JET_errInvalidParameter => "JET_errInvalidParameter",
            jet::JET_errRecoveredWithoutUndo => "JET_errRecoveredWithoutUndo",
            JET_ERR_OBJECT_NOT_FOUND => "JET_errObjectNotFound",
            JET_ERR_COLUMN_NOT_FOUND => "JET_errColumnNotFound",
            _ => "unnamed JET_err",
        }
    }

    pub(super) fn is_missing_file(self) -> bool {
        matches!(
            self.code,
            jet::JET_errFileNotFound | jet::JET_errDatabaseNotFound
        )
    }

    pub(super) fn is_access_denied(self) -> bool {
        self.code == jet::JET_errFileAccessDenied
    }
}

impl std::fmt::Display for EseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {} ({})", self.call, self.name(), self.code)
    }
}

const JET_ERR_OBJECT_NOT_FOUND: i32 = -1305;
const JET_ERR_COLUMN_NOT_FOUND: i32 = -1507;

/// Negative codes are errors; zero and positive codes are success and warnings.
fn check(code: i32, call: &'static str) -> Result<i32, EseError> {
    if code < 0 {
        Err(EseError { code, call })
    } else {
        Ok(code)
    }
}

fn wide(text: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    text.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// A directory parameter: ESE wants the trailing backslash.
fn wide_dir(dir: &Path) -> Vec<u16> {
    let mut units: Vec<u16> = dir.as_os_str().encode_wide().collect();
    if units.last() != Some(&u16::from(b'\\')) {
        units.push(u16::from(b'\\'));
    }
    units.push(0);
    units
}

/// How to start an instance.
pub(super) struct Params<'a> {
    pub name: &'a str,
    /// Replay logs on start. Off for a clean copy, which then needs no log files at all.
    pub recovery: bool,
    /// Where the checkpoint file lives.
    pub system_dir: &'a Path,
    pub log_dir: &'a Path,
    pub temp_dir: &'a Path,
    /// The three-letter log prefix; the copy of SRUM's own logs is `SRU`.
    pub base_name: &'a str,
    pub page_size: u32,
    pub log_file_kb: u32,
    /// Replay against databases in this directory instead of the paths recorded in the logs,
    /// which for SRUM name the live `C:\Windows\System32\SRU\SRUDB.dat`.
    pub recovery_db_dir: Option<&'a Path>,
}

/// A running ESE instance. Dropping it terminates the instance.
pub(super) struct Instance {
    id: jet::JET_INSTANCE,
    crash: bool,
    _gate: MutexGuard<'static, ()>,
}

impl Instance {
    pub(super) fn start(params: &Params<'_>) -> Result<Instance, EseError> {
        let gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let name = wide(params.name);
        let mut id = jet::JET_INSTANCE::default();
        // SAFETY: `id` and `name` outlive the call.
        check(
            unsafe { jet::JetCreateInstanceW(&mut id, Some(name.as_ptr())) },
            "JetCreateInstanceW",
        )?;
        let mut instance = Instance {
            id,
            crash: false,
            _gate: gate,
        };
        instance.configure(params)?;
        // SAFETY: `instance.id` is the handle just created.
        check(unsafe { jet::JetInit(Some(&mut instance.id)) }, "JetInit")?;
        Ok(instance)
    }

    fn configure(&mut self, params: &Params<'_>) -> Result<(), EseError> {
        // Global parameters first (instance pointer null), per the ESENT documentation.
        set_param(
            None,
            jet::JET_paramDatabasePageSize,
            params.page_size as usize,
            None,
        )?;
        let id = self.id;
        let number = |param: u32, value: usize| set_param(Some(id), param, value, None);
        number(jet::JET_paramLogFileSize, params.log_file_kb as usize)?;
        number(jet::JET_paramCreatePathIfNotExist, 1)?;
        // Do not write to the Windows event log from a diagnostics tool.
        number(jet::JET_paramNoInformationEvent, 1)?;
        number(jet::JET_paramEventLoggingLevel, 0)?;
        let text = |param: u32, value: &[u16]| set_param(Some(id), param, 0, Some(value));
        text(
            jet::JET_paramRecovery,
            &wide(if params.recovery { "on" } else { "off" }),
        )?;
        text(jet::JET_paramBaseName, &wide(params.base_name))?;
        text(jet::JET_paramSystemPath, &wide_dir(params.system_dir))?;
        text(jet::JET_paramLogFilePath, &wide_dir(params.log_dir))?;
        text(jet::JET_paramTempPath, &wide_dir(params.temp_dir))?;
        if let Some(dir) = params.recovery_db_dir {
            text(jet::JET_paramAlternateDatabaseRecoveryPath, &wide_dir(dir))?;
        }
        Ok(())
    }

    /// Terminate as if the process crashed, leaving any attached database dirty. Test-only: it is
    /// how the tests make a database that needs log replay.
    #[cfg(test)]
    pub(super) fn abandon(mut self) {
        self.crash = true;
    }

    pub(super) fn session(&self) -> Result<Session<'_>, EseError> {
        let mut id = jet::JET_SESID::default();
        // SAFETY: `id` outlives the call; no user name or password is used.
        check(
            unsafe { jet::JetBeginSessionW(self.id, &mut id, None, None) },
            "JetBeginSessionW",
        )?;
        Ok(Session {
            id,
            _instance: PhantomData,
        })
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        let flag = if self.crash {
            jet::JET_bitTermDirty
        } else {
            jet::JET_bitTermComplete
        };
        // SAFETY: `self.id` is a live instance handle owned by this value.
        let _ = unsafe { jet::JetTerm2(self.id, flag) };
    }
}

fn set_param(
    instance: Option<jet::JET_INSTANCE>,
    param: u32,
    number: usize,
    text: Option<&[u16]>,
) -> Result<(), EseError> {
    let mut instance = instance;
    let instance = instance.as_mut().map(|i| i as *mut jet::JET_INSTANCE);
    // SAFETY: the instance pointer and string point at caller-owned values that outlive the call.
    let code = unsafe {
        jet::JetSetSystemParameterW(
            instance,
            None,
            param,
            Some(windows::Win32::Storage::StructuredStorage::JET_API_PTR(
                number,
            )),
            text.map(<[u16]>::as_ptr),
        )
    };
    check(code, "JetSetSystemParameterW").map(drop)
}

/// The size of the page ESE used when it made the file, from the file's own header.
pub(super) fn database_page_size(path: &Path) -> Result<u32, EseError> {
    let path = wide(path);
    let mut size = 0u32;
    // SAFETY: the buffer is a `u32` and `cbmax` says so.
    check(
        unsafe {
            jet::JetGetDatabaseFileInfoW(
                path.as_ptr(),
                (&mut size as *mut u32).cast::<c_void>(),
                std::mem::size_of::<u32>() as u32,
                jet::JET_DbInfoPageSize,
            )
        },
        "JetGetDatabaseFileInfoW(page size)",
    )?;
    Ok(size)
}

/// True when the file was not shut down cleanly and needs its logs replayed before it can attach.
pub(super) fn database_is_dirty(path: &Path) -> Result<bool, EseError> {
    let path = wide(path);
    let mut info = jet::JET_DBINFOMISC::default();
    // SAFETY: the buffer is a `JET_DBINFOMISC` and `cbmax` says so.
    check(
        unsafe {
            jet::JetGetDatabaseFileInfoW(
                path.as_ptr(),
                (&mut info as *mut jet::JET_DBINFOMISC).cast::<c_void>(),
                std::mem::size_of::<jet::JET_DBINFOMISC>() as u32,
                jet::JET_DbInfoMisc,
            )
        },
        "JetGetDatabaseFileInfoW(state)",
    )?;
    Ok(info.dbstate != jet::JET_dbstateCleanShutdown)
}

pub(super) struct Session<'i> {
    id: jet::JET_SESID,
    _instance: PhantomData<&'i Instance>,
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // SAFETY: `self.id` is a live session handle owned by this value.
        let _ = unsafe { jet::JetEndSession(self.id, 0) };
    }
}

impl<'i> Session<'i> {
    /// Attach and open one database file read-only.
    pub(super) fn open_read_only<'s>(&'s self, path: &Path) -> Result<Database<'s, 'i>, EseError> {
        let path = wide(path);
        // SAFETY: `path` is NUL terminated and outlives the call.
        check(
            unsafe { jet::JetAttachDatabaseW(self.id, path.as_ptr(), jet::JET_bitDbReadOnly) },
            "JetAttachDatabaseW",
        )?;
        let mut dbid = 0u32;
        // SAFETY: `path` and `dbid` outlive the call.
        let opened = check(
            unsafe {
                jet::JetOpenDatabaseW(
                    self.id,
                    path.as_ptr(),
                    None,
                    &mut dbid,
                    jet::JET_bitDbReadOnly,
                )
            },
            "JetOpenDatabaseW",
        );
        if let Err(err) = opened {
            // SAFETY: undo the attach above on the same session and path.
            let _ = unsafe { jet::JetDetachDatabaseW(self.id, Some(path.as_ptr())) };
            return Err(err);
        }
        Ok(Database {
            session: self,
            dbid,
            path,
        })
    }
}

pub(super) struct Database<'s, 'i> {
    session: &'s Session<'i>,
    dbid: u32,
    path: Vec<u16>,
}

impl Drop for Database<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: close then detach what `open_read_only` opened, on its own session.
        let _ = unsafe { jet::JetCloseDatabase(self.session.id, self.dbid, 0) };
        // SAFETY: as above; `path` is NUL terminated.
        let _ = unsafe { jet::JetDetachDatabaseW(self.session.id, Some(self.path.as_ptr())) };
    }
}

/// A column of an open table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Column {
    pub name: String,
    pub id: u32,
    pub coltyp: u32,
}

impl<'s, 'i> Database<'s, 'i> {
    /// Names of every user table.
    pub(super) fn tables(&self) -> Result<Vec<String>, EseError> {
        let mut list = jet::JET_OBJECTLIST {
            cbStruct: std::mem::size_of::<jet::JET_OBJECTLIST>() as u32,
            ..Default::default()
        };
        // SAFETY: `list` is a `JET_OBJECTLIST` and `cbmax` says so.
        check(
            unsafe {
                jet::JetGetObjectInfoW(
                    self.session.id,
                    self.dbid,
                    jet::JET_objtypTable,
                    None,
                    None,
                    (&mut list as *mut jet::JET_OBJECTLIST).cast::<c_void>(),
                    std::mem::size_of::<jet::JET_OBJECTLIST>() as u32,
                    OBJ_INFO_LIST_NO_STATS,
                )
            },
            "JetGetObjectInfoW",
        )?;
        let mut cursor = ListCursor {
            session: self.session,
            id: list.tableid,
        };
        let mut names = Vec::new();
        let mut more = cursor.first()?;
        while more {
            if let Some(raw) = cursor.raw(list.columnidobjectname)? {
                names.push(utf16_or_ansi(&raw));
            }
            more = cursor.next()?;
        }
        Ok(names)
    }

    /// Open a table read-only, or `None` when this database has no table of that name.
    pub(super) fn table<'d>(&'d self, name: &str) -> Result<Option<Table<'d, 's, 'i>>, EseError> {
        let name = wide(name);
        let mut id = JET_TABLEID::default();
        // SAFETY: `name` and `id` outlive the call; no open parameters are passed.
        let code = unsafe {
            jet::JetOpenTableW(
                self.session.id,
                self.dbid,
                name.as_ptr(),
                None,
                0,
                jet::JET_bitTableReadOnly | jet::JET_bitTableSequential,
                &mut id,
            )
        };
        if code == JET_ERR_OBJECT_NOT_FOUND {
            return Ok(None);
        }
        check(code, "JetOpenTableW")?;
        Ok(Some(Table {
            database: self,
            id,
            positioned: false,
        }))
    }
}

pub(super) struct Table<'d, 's, 'i> {
    database: &'d Database<'s, 'i>,
    id: JET_TABLEID,
    positioned: bool,
}

impl Drop for Table<'_, '_, '_> {
    fn drop(&mut self) {
        // SAFETY: `self.id` is an open cursor owned by this value, on the database's session.
        let _ = unsafe { jet::JetCloseTable(self.database.session.id, self.id) };
    }
}

impl Table<'_, '_, '_> {
    fn session_id(&self) -> jet::JET_SESID {
        self.database.session.id
    }

    /// One column by name, or `None` when the table lacks it.
    pub(super) fn column(&self, name: &str) -> Result<Option<Column>, EseError> {
        let wide_name = wide(name);
        let mut def = jet::JET_COLUMNDEF {
            cbStruct: std::mem::size_of::<jet::JET_COLUMNDEF>() as u32,
            ..Default::default()
        };
        // SAFETY: `def` is a `JET_COLUMNDEF` and `cbmax` says so; `wide_name` outlives the call.
        let code = unsafe {
            jet::JetGetTableColumnInfoW(
                self.session_id(),
                self.id,
                Some(wide_name.as_ptr()),
                (&mut def as *mut jet::JET_COLUMNDEF).cast::<c_void>(),
                std::mem::size_of::<jet::JET_COLUMNDEF>() as u32,
                COL_INFO,
            )
        };
        if code == JET_ERR_COLUMN_NOT_FOUND {
            return Ok(None);
        }
        check(code, "JetGetTableColumnInfoW")?;
        Ok(Some(Column {
            name: name.to_owned(),
            id: def.columnid,
            coltyp: def.coltyp,
        }))
    }

    /// Move to the first row. `false` when the table is empty.
    pub(super) fn first(&mut self) -> Result<bool, EseError> {
        self.positioned = true;
        move_cursor(self.session_id(), self.id, MOVE_FIRST)
    }

    /// Move to the next row. `false` after the last one.
    pub(super) fn next(&mut self) -> Result<bool, EseError> {
        if !self.positioned {
            return self.first();
        }
        move_cursor(self.session_id(), self.id, MOVE_NEXT)
    }

    /// The current row's value for `column`, widened by its type.
    pub(super) fn value(&self, column: &Column) -> Result<Value, EseError> {
        let raw = retrieve(self.session_id(), self.id, column.id)?;
        Ok(match raw {
            None => Value::Null,
            Some(bytes) => Value::from_raw(column.coltyp, &bytes),
        })
    }
}

/// A cursor over one of ESE's own result tables (the table and column lists).
struct ListCursor<'a, 'i> {
    session: &'a Session<'i>,
    id: JET_TABLEID,
}

impl Drop for ListCursor<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: the list table was created for this session by the call that returned it.
        let _ = unsafe { jet::JetCloseTable(self.session.id, self.id) };
    }
}

impl ListCursor<'_, '_> {
    fn first(&mut self) -> Result<bool, EseError> {
        move_cursor(self.session.id, self.id, MOVE_FIRST)
    }

    fn next(&mut self) -> Result<bool, EseError> {
        move_cursor(self.session.id, self.id, MOVE_NEXT)
    }

    fn raw(&self, column: u32) -> Result<Option<Vec<u8>>, EseError> {
        retrieve(self.session.id, self.id, column)
    }
}

fn move_cursor(session: jet::JET_SESID, table: JET_TABLEID, by: i32) -> Result<bool, EseError> {
    // SAFETY: plain call on a live session and cursor.
    let code = unsafe { jet::JetMove(session, table, by, 0) };
    if code == jet::JET_errNoCurrentRecord {
        return Ok(false);
    }
    check(code, "JetMove").map(|_| true)
}

/// The raw bytes of one column of the current row, or `None` for a null column.
fn retrieve(
    session: jet::JET_SESID,
    table: JET_TABLEID,
    column: u32,
) -> Result<Option<Vec<u8>>, EseError> {
    let mut stack = [0u8; 64];
    let mut actual = 0u32;
    // SAFETY: the buffer and its length match; `actual` outlives the call.
    let code = unsafe {
        jet::JetRetrieveColumn(
            session,
            table,
            column,
            Some(stack.as_mut_ptr().cast::<c_void>()),
            stack.len() as u32,
            Some(&mut actual),
            0,
            None,
        )
    };
    let code = check(code, "JetRetrieveColumn")?;
    if code == jet::JET_wrnColumnNull as i32 {
        return Ok(None);
    }
    let actual = actual as usize;
    if code == jet::JET_wrnBufferTruncated as i32 && actual > stack.len() {
        let mut heap = vec![0u8; actual];
        let mut again = 0u32;
        // SAFETY: the buffer and its length match; `again` outlives the call.
        check(
            unsafe {
                jet::JetRetrieveColumn(
                    session,
                    table,
                    column,
                    Some(heap.as_mut_ptr().cast::<c_void>()),
                    heap.len() as u32,
                    Some(&mut again),
                    0,
                    None,
                )
            },
            "JetRetrieveColumn",
        )?;
        heap.truncate(again as usize);
        return Ok(Some(heap));
    }
    Ok(Some(stack[..actual.min(stack.len())].to_vec()))
}

/// ESE's own name columns hold UTF-16 for the `W` calls; fall back to single bytes if they do not.
fn utf16_or_ansi(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw.len().is_multiple_of(2) && raw[1] == 0 {
        let units: Vec<u16> = utf16_units(raw)
            .into_iter()
            .take_while(|&u| u != 0)
            .collect();
        return String::from_utf16_lossy(&units);
    }
    raw.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect()
}

/// Writing side, only to build the small databases the tests read back. It lives in this file so
/// it can use the handles above; nothing outside the tests can reach it.
#[cfg(test)]
pub(super) mod build {
    use super::*;

    impl<'i> Session<'i> {
        /// Create a new database file. With `logging` off the file is a plain clean database; with
        /// it on, writes go through the log, so an abrupt end leaves a database that needs replay.
        pub(in crate::srum) fn create_database<'s>(
            &'s self,
            path: &Path,
            logging: bool,
        ) -> Result<WritableDatabase<'s, 'i>, EseError> {
            let path = wide(path);
            let mut dbid = 0u32;
            let grbit = if logging {
                0
            } else {
                jet::JET_bitDbRecoveryOff
            };
            // SAFETY: `path` and `dbid` outlive the call.
            check(
                unsafe { jet::JetCreateDatabaseW(self.id, path.as_ptr(), None, &mut dbid, grbit) },
                "JetCreateDatabaseW",
            )?;
            Ok(WritableDatabase {
                session: self,
                dbid,
                path,
            })
        }
    }

    pub(in crate::srum) struct WritableDatabase<'s, 'i> {
        session: &'s Session<'i>,
        dbid: u32,
        path: Vec<u16>,
    }

    impl Drop for WritableDatabase<'_, '_> {
        fn drop(&mut self) {
            // SAFETY: close then detach what `create_database` made, on its own session.
            let _ = unsafe { jet::JetCloseDatabase(self.session.id, self.dbid, 0) };
            // SAFETY: as above; `path` is NUL terminated.
            let _ = unsafe { jet::JetDetachDatabaseW(self.session.id, Some(self.path.as_ptr())) };
        }
    }

    impl WritableDatabase<'_, '_> {
        /// Create a table with the given `(name, coltyp)` columns.
        pub(in crate::srum) fn create_table(
            &self,
            name: &str,
            columns: &[(&str, u32)],
        ) -> Result<WritableTable<'_, '_, '_>, EseError> {
            let session = self.session.id;
            let table_name = wide(name);
            let mut id = JET_TABLEID::default();
            // SAFETY: `table_name` and `id` outlive the call.
            check(
                unsafe {
                    jet::JetCreateTableW(session, self.dbid, table_name.as_ptr(), 16, 100, &mut id)
                },
                "JetCreateTableW",
            )?;
            let mut table = WritableTable {
                database: self,
                id,
                columns: Vec::new(),
            };
            for &(column_name, coltyp) in columns {
                let def = jet::JET_COLUMNDEF {
                    cbStruct: std::mem::size_of::<jet::JET_COLUMNDEF>() as u32,
                    coltyp,
                    ..Default::default()
                };
                let wide_name = wide(column_name);
                let mut column_id = 0u32;
                // SAFETY: `def`, `wide_name` and `column_id` outlive the call.
                check(
                    unsafe {
                        jet::JetAddColumnW(
                            session,
                            id,
                            wide_name.as_ptr(),
                            &def,
                            None,
                            0,
                            Some(&mut column_id),
                        )
                    },
                    "JetAddColumnW",
                )?;
                table.columns.push(Column {
                    name: column_name.to_owned(),
                    id: column_id,
                    coltyp,
                });
            }
            Ok(table)
        }
    }

    pub(in crate::srum) struct WritableTable<'d, 's, 'i> {
        database: &'d WritableDatabase<'s, 'i>,
        id: JET_TABLEID,
        columns: Vec<Column>,
    }

    impl Drop for WritableTable<'_, '_, '_> {
        fn drop(&mut self) {
            // SAFETY: `self.id` is an open cursor owned by this value.
            let _ = unsafe { jet::JetCloseTable(self.database.session.id, self.id) };
        }
    }

    impl WritableTable<'_, '_, '_> {
        /// Insert one row. Columns not named stay null.
        pub(in crate::srum) fn insert(&self, row: &[(&str, Value)]) -> Result<(), EseError> {
            let session = self.database.session.id;
            // SAFETY: plain call on this value's own session.
            check(
                unsafe { jet::JetBeginTransaction(session) },
                "JetBeginTransaction",
            )?;
            // SAFETY: plain call on this value's own session and cursor.
            check(
                unsafe { jet::JetPrepareUpdate(session, self.id, jet::JET_prepInsert) },
                "JetPrepareUpdate",
            )?;
            for (name, value) in row {
                let column = self
                    .columns
                    .iter()
                    .find(|c| c.name == *name)
                    .expect("the test names a column it created");
                let raw = value.to_raw(column.coltyp);
                // SAFETY: the pointer and length describe `raw`, which outlives the call.
                check(
                    unsafe {
                        jet::JetSetColumn(
                            session,
                            self.id,
                            column.id,
                            (!raw.is_empty()).then(|| raw.as_ptr().cast::<c_void>()),
                            raw.len() as u32,
                            0,
                            None,
                        )
                    },
                    "JetSetColumn",
                )?;
            }
            // SAFETY: plain call; no bookmark is requested.
            check(
                unsafe { jet::JetUpdate(session, self.id, None, 0, None) },
                "JetUpdate",
            )?;
            // SAFETY: plain call on this value's own session.
            check(
                unsafe { jet::JetCommitTransaction(session, 0) },
                "JetCommitTransaction",
            )?;
            Ok(())
        }
    }
}
