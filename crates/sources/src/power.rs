//! Power requests, wake timers, armed devices, sleep settings, execution state and last input.
//!
//! The types and the byte-level parsers are pure and build on any platform. The functions that call
//! Windows are behind `#[cfg(windows)]` and each returns a [`Sourced`]. Nothing here changes a
//! setting or triggers sleep: every call is a read.
//!
//! - [`sleep_settings`]: active scheme, standby, hibernate and wake timer policy for AC and DC.
//! - [`sleep_model`]: S3, S4 and Modern Standby support.
//! - [`execution_state`], [`last_input`], [`power_source`]: what the machine is doing now.
//! - [`armed_devices`]: devices allowed to wake the machine.
//! - [`power_requests`], [`wake_timers`]: live, owner-attributed, admin only.
//! - [`is_elevated`], [`create_output_dir`], [`relaunch_elevated`], [`open_output_file`]: ADR 0003.
//!   Read the `elevate` module notes on the output file before wiring `--elevate`.
//! - [`system_directory`]: where to find a system executable that may run elevated.

mod elevate;
mod layout;
#[cfg(windows)]
mod os;

use std::time::Duration;

use jiff::Timestamp;

pub use elevate::{
    OUT_FILE_ARG, RelaunchError, command_line, is_output_path, open_output_file, output_dir_name,
    quote_arg,
};
#[cfg(windows)]
pub use elevate::{create_output_dir, is_elevated, relaunch_elevated};
pub use layout::{
    LayoutError, PowerRequest, REQUEST_TYPES_V4, Reason, RequestType, Requester, WakeTimer,
    filetime_to_timestamp, parse_power_requests, parse_wake_timers,
};
#[cfg(windows)]
pub(crate) use os::access_from_hresult;
#[cfg(windows)]
pub use os::{
    armed_devices, execution_state, last_input, power_requests, power_source, sleep_model,
    sleep_settings, system_directory, wake_timers,
};

/// A sleep timeout from a power scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timeout {
    /// The scheme stores 0, which means the action never happens on its own.
    Never,
    After(Duration),
}

impl Timeout {
    pub fn from_secs(secs: u32) -> Timeout {
        if secs == 0 {
            Timeout::Never
        } else {
            Timeout::After(Duration::from_secs(u64::from(secs)))
        }
    }
}

/// The "Allow wake timers" setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeTimerPolicy {
    Disable,
    Enable,
    /// "Important wake timers only".
    ImportantOnly,
    /// A value this code does not know, kept as stored.
    Other(u32),
}

impl WakeTimerPolicy {
    pub fn from_index(index: u32) -> WakeTimerPolicy {
        match index {
            0 => WakeTimerPolicy::Disable,
            1 => WakeTimerPolicy::Enable,
            2 => WakeTimerPolicy::ImportantOnly,
            other => WakeTimerPolicy::Other(other),
        }
    }
}

/// One setting on mains power (AC) and on battery (DC). `None` means the scheme has no such
/// setting on this machine, which is normal: hibernate off removes its timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcDc<T> {
    pub ac: Option<T>,
    pub dc: Option<T>,
}

/// Sleep related values of the active power scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleepSettings {
    /// GUID of the active scheme, lower case with hyphens, as `powercfg /list` writes it.
    pub scheme: String,
    /// Idle time before the system goes to sleep (S3 or Modern Standby).
    pub standby_timeout: AcDc<Timeout>,
    /// Idle time before the system hibernates.
    pub hibernate_timeout: AcDc<Timeout>,
    pub allow_wake_timers: AcDc<WakeTimerPolicy>,
}

/// What kinds of sleep this machine supports, from `SYSTEM_POWER_CAPABILITIES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleepModel {
    pub s1: bool,
    pub s2: bool,
    /// Classic sleep (suspend to RAM).
    pub s3: bool,
    /// Hibernate.
    pub s4: bool,
    /// Modern Standby (S0 low power idle), reported by Windows as "always on, always connected".
    pub modern_standby: bool,
    pub hiberfile_present: bool,
    pub lid_present: bool,
    pub battery_present: bool,
}

/// The `EXECUTION_STATE` flags Windows currently holds the system in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionState {
    /// The value as returned.
    pub raw: u32,
    /// `ES_SYSTEM_REQUIRED`: something is keeping the system awake.
    pub system_required: bool,
    /// `ES_DISPLAY_REQUIRED`: something is keeping the display on.
    pub display_required: bool,
    /// `ES_USER_PRESENT`.
    pub user_present: bool,
    /// `ES_AWAYMODE_REQUIRED`.
    pub away_mode_required: bool,
    /// `ES_CONTINUOUS`.
    pub continuous: bool,
}

impl ExecutionState {
    pub fn from_bits(raw: u32) -> ExecutionState {
        ExecutionState {
            raw,
            system_required: raw & 0x0000_0001 != 0,
            display_required: raw & 0x0000_0002 != 0,
            user_present: raw & 0x0000_0004 != 0,
            away_mode_required: raw & 0x0000_0040 != 0,
            continuous: raw & 0x8000_0000 != 0,
        }
    }
}

/// How long the user has been idle, from `GetLastInputInfo`. Keyboard and mouse only; a process
/// that injects input counts as the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastInput {
    pub idle: Duration,
    /// `now - idle`.
    pub at: Timestamp,
}

/// Idle time from two 32-bit tick counts. The counter wraps every 49.7 days, which the wrapping
/// subtraction absorbs as long as the idle time is shorter than one wrap.
pub fn idle_from_ticks(now_tick: u32, last_input_tick: u32) -> Duration {
    Duration::from_millis(u64::from(now_tick.wrapping_sub(last_input_tick)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcLine {
    Offline,
    Online,
    Unknown,
}

/// Mains or battery, from `GetSystemPowerStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerSource {
    pub ac_line: AcLine,
    /// `None` when Windows does not know.
    pub battery_present: Option<bool>,
    pub charging: bool,
    pub battery_percent: Option<u8>,
    /// Remaining time on battery, `None` while on mains or when unknown.
    pub battery_remaining: Option<Duration>,
    /// Battery saver is on.
    pub battery_saver: bool,
}

impl PowerSource {
    /// Build from the raw `SYSTEM_POWER_STATUS` fields. 255 and `u32::MAX` mean "unknown".
    pub fn from_raw(
        ac_line: u8,
        battery_flag: u8,
        battery_percent: u8,
        status_flag: u8,
        battery_life_secs: u32,
    ) -> PowerSource {
        let battery_known = battery_flag != 255;
        PowerSource {
            ac_line: match ac_line {
                0 => AcLine::Offline,
                1 => AcLine::Online,
                _ => AcLine::Unknown,
            },
            battery_present: battery_known.then_some(battery_flag & 128 == 0),
            charging: battery_known && battery_flag & 8 != 0,
            battery_percent: (battery_percent <= 100).then_some(battery_percent),
            battery_remaining: (battery_life_secs != u32::MAX)
                .then(|| Duration::from_secs(u64::from(battery_life_secs))),
            battery_saver: status_flag & 1 != 0,
        }
    }
}

/// A device that is allowed to wake the machine. The name is the device's own, opaque and
/// possibly localized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmedDevice {
    pub name: String,
}

/// The outcome of reading one power setting, from the Win32 status and the value it filled in.
///
/// `Ok(None)` is a scheme that has no such setting (`ERROR_FILE_NOT_FOUND`), which is normal: a
/// machine with hibernate off has no hibernate timeout. Any other failure is `Err(code)`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn setting_value(status: u32, value: u32) -> Result<Option<u32>, u32> {
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    match status {
        ERROR_SUCCESS => Ok(Some(value)),
        ERROR_FILE_NOT_FOUND => Ok(None),
        code => Err(code),
    }
}

/// The `NTSTATUS` values that mean "run elevated", as `Access`.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn access_from_ntstatus(status: i32) -> pcsleuth_core::Access {
    use pcsleuth_core::Access;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
    match status as u32 {
        STATUS_ACCESS_DENIED | STATUS_PRIVILEGE_NOT_HELD => Access::NeedsAdmin,
        code => Access::Failed {
            code,
            message: format!("NTSTATUS 0x{code:08X}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use pcsleuth_core::Access;

    use super::*;

    #[test]
    fn timeout_zero_means_never() {
        assert_eq!(Timeout::from_secs(0), Timeout::Never);
        assert_eq!(
            Timeout::from_secs(900),
            Timeout::After(Duration::from_secs(900))
        );
    }

    #[test]
    fn wake_timer_policy_values() {
        assert_eq!(WakeTimerPolicy::from_index(0), WakeTimerPolicy::Disable);
        assert_eq!(WakeTimerPolicy::from_index(1), WakeTimerPolicy::Enable);
        assert_eq!(
            WakeTimerPolicy::from_index(2),
            WakeTimerPolicy::ImportantOnly
        );
        assert_eq!(WakeTimerPolicy::from_index(7), WakeTimerPolicy::Other(7));
    }

    #[test]
    fn execution_state_flags() {
        let state = ExecutionState::from_bits(0x8000_0003);
        assert!(state.system_required && state.display_required && state.continuous);
        assert!(!state.user_present && !state.away_mode_required);
        let idle = ExecutionState::from_bits(0);
        assert!(!idle.system_required && !idle.display_required && !idle.continuous);
        assert!(ExecutionState::from_bits(0x44).user_present);
        assert!(ExecutionState::from_bits(0x44).away_mode_required);
    }

    #[test]
    fn idle_time_survives_the_tick_counter_wrapping() {
        assert_eq!(idle_from_ticks(5_000, 2_000), Duration::from_secs(3));
        assert_eq!(idle_from_ticks(7, 7), Duration::ZERO);
        // The counter wrapped between the last input and now: 10 ms before and 90 ms after.
        assert_eq!(
            idle_from_ticks(90, u32::MAX - 9),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn power_source_on_battery_and_on_mains() {
        let battery = PowerSource::from_raw(0, 0, 63, 0, 7_200);
        assert_eq!(battery.ac_line, AcLine::Offline);
        assert_eq!(battery.battery_present, Some(true));
        assert!(!battery.charging);
        assert_eq!(battery.battery_percent, Some(63));
        assert_eq!(battery.battery_remaining, Some(Duration::from_secs(7_200)));

        let charging = PowerSource::from_raw(1, 8, 40, 1, u32::MAX);
        assert_eq!(charging.ac_line, AcLine::Online);
        assert!(charging.charging && charging.battery_saver);
        assert_eq!(charging.battery_remaining, None);
    }

    #[test]
    fn power_source_without_a_battery_or_with_unknown_values() {
        let desktop = PowerSource::from_raw(1, 128, 255, 0, u32::MAX);
        assert_eq!(desktop.battery_present, Some(false));
        assert_eq!(desktop.battery_percent, None);
        assert!(!desktop.charging);

        let unknown = PowerSource::from_raw(255, 255, 255, 0, u32::MAX);
        assert_eq!(unknown.ac_line, AcLine::Unknown);
        assert_eq!(unknown.battery_present, None);
        assert!(!unknown.charging);
    }

    #[test]
    fn only_a_missing_setting_reads_as_none() {
        assert_eq!(setting_value(0, 600), Ok(Some(600)));
        assert_eq!(setting_value(2, 0), Ok(None));
        assert_eq!(setting_value(5, 0), Err(5));
        assert_eq!(setting_value(87, 0), Err(87));
    }

    #[test]
    fn ntstatus_access_denied_is_needs_admin() {
        assert_eq!(
            access_from_ntstatus(0xC000_0022u32 as i32),
            Access::NeedsAdmin
        );
        assert_eq!(
            access_from_ntstatus(0xC000_0061u32 as i32),
            Access::NeedsAdmin
        );
        assert_eq!(
            access_from_ntstatus(0xC000_0001u32 as i32),
            Access::Failed {
                code: 0xC000_0001,
                message: "NTSTATUS 0xC0000001".into()
            }
        );
    }
}
