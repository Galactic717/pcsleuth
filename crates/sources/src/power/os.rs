//! The Windows side of `power`: every function here is one read through a Windows API.

use std::ffi::c_void;

use jiff::Timestamp;
use pcsleuth_core::{Access, SourceId, Sourced};
use windows::Win32::Foundation::{ERROR_SUCCESS, GetLastError, HLOCAL, LocalFree, NTSTATUS};
use windows::Win32::System::Power::{
    CallNtPowerInformation, DEVICEPOWER_FILTER_DEVICES_PRESENT, DEVICEPOWER_FILTER_WAKEENABLED,
    DevicePowerEnumDevices, GetPowerRequestList, GetSystemPowerStatus, POWER_INFORMATION_LEVEL,
    PowerGetActiveScheme, PowerReadACValueIndex, PowerReadDCValueIndex, SYSTEM_POWER_CAPABILITIES,
    SYSTEM_POWER_STATUS, SystemExecutionState, SystemPowerCapabilities, WakeTimerList,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetTickCount};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::core::{GUID, HRESULT};

use super::layout::{self, REQUEST_TYPES_V4};
use super::{
    AcDc, ArmedDevice, ExecutionState, LastInput, PowerRequest, PowerSource, SleepModel,
    SleepSettings, Timeout, WakeTimer, WakeTimerPolicy, access_from_ntstatus, idle_from_ticks,
    setting_value,
};

// `powrprof!CallNtPowerInformation` refuses levels it does not document (it answers
// STATUS_INVALID_PARAMETER for 45 and 50, checked on this machine), so the two undocumented levels
// go to `ntdll!NtPowerInformation`, the function `powercfg` itself ends up in.
windows::core::link!("ntdll.dll" "system" fn NtPowerInformation(level: i32, input: *const c_void, input_len: u32, output: *mut c_void, output_len: u32) -> i32);

/// `ERROR_NO_MORE_ITEMS`, `ERROR_MORE_DATA` and `ERROR_INSUFFICIENT_BUFFER`.
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_INVALID_DATA: u32 = 13;
/// The statuses Windows uses for "give me a bigger buffer": too small, length mismatch, overflow.
const STATUS_GROW_BUFFER: [u32; 3] = [0xC000_0023, 0xC000_0004, 0x8000_0005];

/// A Win32 error code as `Access`: denied means "run elevated", missing means absent.
pub(crate) fn access_from_win32(code: u32) -> Access {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;
    match code {
        ERROR_ACCESS_DENIED => Access::NeedsAdmin,
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Access::Missing,
        code => Access::Failed {
            code,
            message: windows::core::Error::from(HRESULT::from_win32(code)).message(),
        },
    }
}

/// An `HRESULT` as `Access`. `HRESULT_FROM_WIN32` values map as the Win32 code inside them.
pub(crate) fn access_from_hresult(hr: i32) -> Access {
    let bits = hr as u32;
    if bits & 0xFFFF_0000 == 0x8007_0000 {
        return access_from_win32(bits & 0xFFFF);
    }
    Access::Failed {
        code: bits,
        message: windows::core::Error::from(HRESULT(hr)).message(),
    }
}

/// The Windows system directory (`C:\Windows\System32`), from `GetSystemDirectoryW`.
///
/// Use this, not the `SystemRoot` or `windir` environment variables, to find a system executable
/// such as `powercfg.exe`. An elevated copy inherits its environment from a process that is not
/// elevated, and a user can set these variables for their own account, so the environment must not
/// choose which program runs elevated.
pub fn system_directory() -> std::io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    let mut buf = vec![0u16; 260];
    loop {
        // SAFETY: the slice is valid and writable for its whole length.
        let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len < buf.len() {
            return Ok(std::ffi::OsString::from_wide(&buf[..len]).into());
        }
        // The buffer was too small; `len` is the size needed including the terminator.
        buf.resize(len + 1, 0);
    }
}

// GUIDs of the settings read below, from `winnt.h`.
const GUID_SLEEP_SUBGROUP: GUID = GUID::from_u128(0x238c9fa8_0aad_41ed_83f4_97be242c8f20);
const GUID_STANDBY_TIMEOUT: GUID = GUID::from_u128(0x29f6c1db_86da_48c5_9fdb_f2b67b1f44da);
const GUID_HIBERNATE_TIMEOUT: GUID = GUID::from_u128(0x9d7815a6_7ee4_497e_8888_515a05f02364);
const GUID_ALLOW_RTC_WAKE: GUID = GUID::from_u128(0xbd3b718a_0680_4d9d_8ab2_e1d2b4ac806d);

fn guid_text(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

/// Standby, hibernate and wake timer settings of the active power scheme, for mains and battery.
///
/// A setting the scheme does not have (`ERROR_FILE_NOT_FOUND`) is `None` in the result and the
/// read stays [`Access::Ok`]. Any other failure to read a setting leaves it `None` too but sets the
/// read's access to that failure, with the other settings still in `data`. Failing to find the
/// active scheme makes the whole read unreadable.
pub fn sleep_settings() -> Sourced<SleepSettings> {
    let source = SourceId::PowerSettings;
    let mut scheme_ptr: *mut GUID = std::ptr::null_mut();
    // SAFETY: `scheme_ptr` is a valid out-pointer; on success the OS allocates the GUID.
    let status = unsafe { PowerGetActiveScheme(None, &mut scheme_ptr) };
    if status != ERROR_SUCCESS || scheme_ptr.is_null() {
        return Sourced::unreadable(source, access_from_win32(status.0));
    }
    // SAFETY: on success `scheme_ptr` points to an initialised GUID.
    let scheme = unsafe { *scheme_ptr };
    // SAFETY: the buffer came from PowerGetActiveScheme, which documents LocalFree.
    let _ = unsafe { LocalFree(Some(HLOCAL(scheme_ptr.cast()))) };

    // The first failure other than "this scheme has no such setting".
    let mut failure: Option<Access> = None;
    let mut read = |setting: &GUID| -> AcDc<u32> {
        let mut ac = 0u32;
        let mut dc = 0u32;
        // SAFETY: all GUID pointers are to live locals and the out-pointers are valid.
        let ac_status = unsafe {
            PowerReadACValueIndex(
                None,
                Some(&scheme),
                Some(&GUID_SLEEP_SUBGROUP),
                Some(setting),
                &mut ac,
            )
        };
        // SAFETY: as above.
        let dc_status = unsafe {
            PowerReadDCValueIndex(
                None,
                Some(&scheme),
                Some(&GUID_SLEEP_SUBGROUP),
                Some(setting),
                &mut dc,
            )
        };
        let mut value = |status: u32, value: u32| match setting_value(status, value) {
            Ok(value) => value,
            Err(code) => {
                failure.get_or_insert_with(|| access_from_win32(code));
                None
            }
        };
        AcDc {
            ac: value(ac_status.0, ac),
            dc: value(dc_status, dc),
        }
    };
    let timeout = |v: AcDc<u32>| AcDc {
        ac: v.ac.map(Timeout::from_secs),
        dc: v.dc.map(Timeout::from_secs),
    };
    let wake = read(&GUID_ALLOW_RTC_WAKE);
    let standby = read(&GUID_STANDBY_TIMEOUT);
    let hibernate = read(&GUID_HIBERNATE_TIMEOUT);
    Sourced {
        source,
        access: failure.unwrap_or(Access::Ok),
        data: vec![SleepSettings {
            scheme: guid_text(&scheme),
            standby_timeout: timeout(standby),
            hibernate_timeout: timeout(hibernate),
            allow_wake_timers: AcDc {
                ac: wake.ac.map(WakeTimerPolicy::from_index),
                dc: wake.dc.map(WakeTimerPolicy::from_index),
            },
        }],
    }
}

/// Call `CallNtPowerInformation` for a fixed-size output.
fn query_fixed<T>(level: POWER_INFORMATION_LEVEL, out: &mut T) -> Result<(), Access> {
    // SAFETY: `out` is a valid, writable T and its exact size is passed as the output length.
    let status: NTSTATUS = unsafe {
        CallNtPowerInformation(
            level,
            None,
            0,
            Some(std::ptr::from_mut(out).cast::<c_void>()),
            size_of::<T>() as u32,
        )
    };
    if status.0 >= 0 {
        Ok(())
    } else {
        Err(access_from_ntstatus(status.0))
    }
}

/// Which sleep states this machine supports: S3, S4 (hibernate) and Modern Standby.
pub fn sleep_model() -> Sourced<SleepModel> {
    let source = SourceId::PowerState;
    let mut caps = SYSTEM_POWER_CAPABILITIES::default();
    match query_fixed(SystemPowerCapabilities, &mut caps) {
        Ok(()) => Sourced::ok(
            source,
            vec![SleepModel {
                s1: caps.SystemS1,
                s2: caps.SystemS2,
                s3: caps.SystemS3,
                s4: caps.SystemS4,
                modern_standby: caps.AoAc,
                hiberfile_present: caps.HiberFilePresent,
                lid_present: caps.LidPresent,
                battery_present: caps.SystemBatteriesPresent,
            }],
        ),
        Err(access) => Sourced::unreadable(source, access),
    }
}

/// The execution state flags Windows currently holds, which show whether something is keeping the
/// system or display awake. It does not say who.
pub fn execution_state() -> Sourced<ExecutionState> {
    let source = SourceId::PowerState;
    let mut raw = 0u32;
    match query_fixed(SystemExecutionState, &mut raw) {
        Ok(()) => Sourced::ok(source, vec![ExecutionState::from_bits(raw)]),
        Err(access) => Sourced::unreadable(source, access),
    }
}

/// Time since the last keyboard or mouse input in this session.
pub fn last_input() -> Sourced<LastInput> {
    let source = SourceId::PowerState;
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is initialised with its size, as the API requires.
    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() }.0;
        return Sourced::unreadable(source, access_from_win32(code));
    }
    // SAFETY: no arguments, no preconditions.
    let now_tick = unsafe { GetTickCount() };
    let idle = idle_from_ticks(now_tick, info.dwTime);
    let at = Timestamp::now()
        .checked_sub(idle)
        .unwrap_or(Timestamp::UNIX_EPOCH);
    Sourced::ok(source, vec![LastInput { idle, at }])
}

/// Mains or battery, charge level and battery saver.
pub fn power_source() -> Sourced<PowerSource> {
    let source = SourceId::PowerState;
    let mut status = SYSTEM_POWER_STATUS::default();
    // SAFETY: `status` is a valid out-pointer.
    match unsafe { GetSystemPowerStatus(&mut status) } {
        Ok(()) => Sourced::ok(
            source,
            vec![PowerSource::from_raw(
                status.ACLineStatus,
                status.BatteryFlag,
                status.BatteryLifePercent,
                status.SystemStatusFlag,
                status.BatteryLifeTime,
            )],
        ),
        Err(e) => Sourced::unreadable(source, access_from_hresult(e.code().0)),
    }
}

/// Devices currently allowed to wake the machine (`powercfg /devicequery wake_armed`), present
/// devices only. Readable without admin.
pub fn armed_devices() -> Sourced<ArmedDevice> {
    let source = SourceId::ArmedDevices;
    // A machine has tens of devices; the cap only stops a runaway loop.
    const MAX_DEVICES: u32 = 4096;
    // The filter flags go in the interpretation argument; in the query-flags argument they match
    // nothing. Checked on this machine: this pair returns the same devices, in the same order, as
    // `powercfg /devicequery wake_armed`.
    let filter = DEVICEPOWER_FILTER_WAKEENABLED | DEVICEPOWER_FILTER_DEVICES_PRESENT;
    let mut devices = Vec::new();
    let mut buf = vec![0u8; 1024];
    for index in 0..MAX_DEVICES {
        let name = loop {
            let mut size = buf.len() as u32;
            // SAFETY: `buf` is writable for `size` bytes and `size` is a valid in/out pointer.
            let found = unsafe {
                DevicePowerEnumDevices(index, filter, 0, Some(buf.as_mut_ptr()), &mut size)
            };
            if found {
                break Some(utf16_prefix(&buf[..(size as usize).min(buf.len())]));
            }
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { GetLastError() }.0;
            match code {
                ERROR_MORE_DATA | ERROR_INSUFFICIENT_BUFFER if (size as usize) > buf.len() => {
                    buf.resize(size as usize, 0);
                }
                ERROR_NO_MORE_ITEMS => break None,
                code => {
                    return Sourced {
                        source,
                        access: access_from_win32(code),
                        data: devices,
                    };
                }
            }
        };
        match name {
            Some(name) => devices.push(ArmedDevice { name }),
            None => break,
        }
    }
    Sourced::ok(source, devices)
}

/// A NUL-terminated UTF-16 string at the start of `bytes`.
fn utf16_prefix(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Fill a buffer from an undocumented `NtPowerInformation` level that returns a variable-size
/// structure, doubling it while Windows says it is too small.
fn query_variable(level: i32) -> Result<Vec<u8>, Access> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let mut bytes = 16 * 1024usize;
    loop {
        // Words, so the buffer is 8-aligned whatever the allocator does.
        let mut words = vec![0u64; bytes / 8];
        // SAFETY: `words` is writable for exactly `bytes` bytes, which is passed as the length.
        let status = unsafe {
            NtPowerInformation(
                level,
                std::ptr::null(),
                0,
                words.as_mut_ptr().cast::<c_void>(),
                bytes as u32,
            )
        };
        if status >= 0 {
            return Ok(words.iter().flat_map(|w| w.to_le_bytes()).collect());
        }
        if STATUS_GROW_BUFFER.contains(&(status as u32)) && bytes < MAX_BYTES {
            bytes *= 2;
            continue;
        }
        return Err(access_from_ntstatus(status));
    }
}

fn layout_failed(e: &layout::LayoutError) -> Access {
    Access::Failed {
        code: ERROR_INVALID_DATA,
        message: e.to_string(),
    }
}

/// Every power request that is holding the system, display or other mode, with its owner and
/// reason (`powercfg /requests`). Needs admin: without it this is [`Access::NeedsAdmin`].
///
/// The layout is read as documented in `power::layout`. The owner path is unverified until the
/// `elevated_power_requests` test has run elevated.
pub fn power_requests() -> Sourced<PowerRequest> {
    let source = SourceId::PowerRequests;
    if cfg!(not(target_pointer_width = "64")) {
        return Sourced::unreadable(
            source,
            layout_failed(&layout::LayoutError::Inconsistent("32-bit layout")),
        );
    }
    match query_variable(GetPowerRequestList.0) {
        Err(access) => Sourced::unreadable(source, access),
        Ok(buf) => match layout::parse_power_requests(&buf, REQUEST_TYPES_V4) {
            Ok(requests) => Sourced::ok(source, requests),
            Err(e) => Sourced::unreadable(source, layout_failed(&e)),
        },
    }
}

/// Every pending wake timer with its owner (`powercfg /waketimers`). Needs admin.
///
/// The entry layout and the empty-list answer are unverified until the `elevated_wake_timers`
/// test has run elevated.
pub fn wake_timers() -> Sourced<WakeTimer> {
    let source = SourceId::WakeTimers;
    if cfg!(not(target_pointer_width = "64")) {
        return Sourced::unreadable(
            source,
            layout_failed(&layout::LayoutError::Inconsistent("32-bit layout")),
        );
    }
    match query_variable(WakeTimerList.0) {
        Err(access) => Sourced::unreadable(source, access),
        Ok(buf) => match layout::parse_wake_timers(&buf) {
            Ok(timers) => Sourced::ok(source, timers),
            Err(e) => Sourced::unreadable(source, layout_failed(&e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::{AcLine, is_elevated};
    use super::*;

    #[test]
    fn win32_and_hresult_codes_become_access() {
        assert_eq!(access_from_win32(5), Access::NeedsAdmin);
        assert_eq!(access_from_win32(2), Access::Missing);
        assert_eq!(
            access_from_hresult(0x8007_0005u32 as i32),
            Access::NeedsAdmin
        );
        assert_eq!(access_from_hresult(0x8007_0002u32 as i32), Access::Missing);
        match access_from_win32(87) {
            Access::Failed { code, message } => {
                assert_eq!(code, 87);
                assert!(!message.is_empty());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            access_from_hresult(0x8000_4005u32 as i32),
            Access::Failed {
                code: 0x8000_4005,
                ..
            }
        ));
    }

    #[test]
    fn system_directory_is_system32() {
        let dir = system_directory().unwrap();
        assert!(dir.join("powercfg.exe").is_file(), "{dir:?}");
        assert!(dir.join("esentutl.exe").is_file(), "{dir:?}");
        assert!(
            dir.file_name().unwrap().eq_ignore_ascii_case("system32"),
            "{dir:?}"
        );
    }

    #[test]
    fn guid_text_matches_powercfg_spelling() {
        assert_eq!(
            guid_text(&GUID_SLEEP_SUBGROUP),
            "238c9fa8-0aad-41ed-83f4-97be242c8f20"
        );
        assert_eq!(utf16_prefix(&[b'h', 0, b'i', 0, 0, 0, b'x', 0]), "hi");
    }

    #[test]
    fn live_sleep_settings() {
        let read = sleep_settings();
        assert_eq!(read.access, Access::Ok, "{read:?}");
        let s = &read.data[0];
        assert_eq!(s.scheme.len(), 36);
        // Every Windows power scheme has a standby timeout on at least one of the two sources.
        assert!(s.standby_timeout.ac.is_some() || s.standby_timeout.dc.is_some());
        eprintln!("sleep_settings: {s:?}");
    }

    #[test]
    fn live_sleep_model() {
        let read = sleep_model();
        assert_eq!(read.access, Access::Ok, "{read:?}");
        assert_eq!(read.data.len(), 1);
        eprintln!("sleep_model: {:?}", read.data[0]);
    }

    #[test]
    fn live_execution_state() {
        let read = execution_state();
        assert_eq!(read.access, Access::Ok, "{read:?}");
        eprintln!("execution_state: {:?}", read.data[0]);
    }

    #[test]
    fn live_last_input() {
        let read = last_input();
        // A session with no desktop (a service, some CI) can fail; anything else is a bug.
        if read.access == Access::Ok {
            let input = read.data[0];
            assert!(input.idle < Duration::from_secs(49 * 86_400));
            assert!(input.at <= Timestamp::now());
            eprintln!("last_input: idle {:?}", input.idle);
        } else {
            eprintln!("last_input: {}", read.access);
        }
    }

    #[test]
    fn live_power_source() {
        let read = power_source();
        assert_eq!(read.access, Access::Ok, "{read:?}");
        let p = read.data[0];
        assert_ne!(p.ac_line, AcLine::Unknown, "{p:?}");
        eprintln!("power_source: {p:?}");
    }

    #[test]
    fn live_armed_devices() {
        let read = armed_devices();
        assert_eq!(read.access, Access::Ok, "{read:?}");
        assert!(read.data.iter().all(|d| !d.name.is_empty()));
        eprintln!("armed_devices: {:?}", read.data);
    }

    /// Unelevated, the kernel refuses both lists. Elevated (a CI runner is admin) the result is
    /// unverified, so only the ignored tests below judge it.
    #[test]
    fn live_admin_only_reads_say_needs_admin_or_return_data() {
        for (name, access) in [
            ("power_requests", power_requests().access),
            ("wake_timers", wake_timers().access),
        ] {
            eprintln!("{name}: {access}");
            if !is_elevated() {
                assert_eq!(access, Access::NeedsAdmin, "{name}");
            }
        }
    }

    /// Run by hand, elevated: `cargo test -p pcsleuth-sources -- --ignored --nocapture
    /// elevated_power_requests`. Compare the output with `powercfg /requests`.
    #[test]
    #[ignore = "needs an elevated shell; the owner runs it"]
    fn elevated_power_requests() {
        assert!(is_elevated(), "run this test from an elevated shell");
        let read = power_requests();
        eprintln!("{:#?}", read);
        assert_eq!(read.access, Access::Ok);
        for request in &read.data {
            assert!(!request.active.is_empty());
        }
    }

    /// Run by hand, elevated. Compare with `powercfg /waketimers`. An empty list passes; a layout
    /// error does not.
    #[test]
    #[ignore = "needs an elevated shell; the owner runs it"]
    fn elevated_wake_timers() {
        assert!(is_elevated(), "run this test from an elevated shell");
        let read = wake_timers();
        eprintln!("{:#?}", read);
        assert_eq!(read.access, Access::Ok);
    }
}
