//! Sleep and wake events in the System channel: Power-Troubleshooter 1, Kernel-Power 42, 107,
//! 41, 105, 172, 506, 507 and Kernel-Processor-Power 37.
//!
//! Where a number has a name, the comment says where the name was proven. Proofs marked
//! "rendered" come from rendering the event `Message` on the development machine (Windows 11
//! 26300, uk-UA, S3 laptop, 3 November 2026) with an en-US message table. That was done once, by
//! hand; no code here reads `Message`.

use jiff::Timestamp;
use pcsleuth_core::{Evidence, SourceId};

use super::common::{
    EvidenceExt, FromRawError, Meta, coded_enum, number_or_bool, parameters_text, req_u32,
};
use super::raw::RawEvent;

const POWER_TROUBLESHOOTER: &[&str] = &["Microsoft-Windows-Power-Troubleshooter"];
const KERNEL_POWER: &[&str] = &["Microsoft-Windows-Kernel-Power"];
const KERNEL_PROCESSOR_POWER: &[&str] = &["Microsoft-Windows-Kernel-Processor-Power"];
const SYSTEM: SourceId = SourceId::EventLogSystem;

coded_enum!(
    /// `WakeSourceType` of Power-Troubleshooter 1. Rendered: 0 for record 364927, 1 for 360285,
    /// 3 for 364908 and 344155, 5 for 360247 and 358340. Other values have not been seen.
    WakeSourceType {
        Unknown = 0 => "unknown",
        PowerButton = 1 => "power button",
        S4DozeToHibernate = 3 => "S4 doze to hibernate",
        Device = 5 => "device",
    }
);

coded_enum!(
    /// A system power state in `TargetState`, `EffectiveState` and `WakeFromState`. These are
    /// `SYSTEM_POWER_STATE` values from winnt.h (PowerSystemSleeping3 = 4, PowerSystemHibernate = 5).
    /// Seen on this machine: 4 on a plain sleep (no hibernate file written, record 360285), 5 on a
    /// resume that read the hibernate file (record 364927) and on Kernel-Power 42 record 364909
    /// whose rendered reason is "Hibernate from Sleep". 0 is the S4 doze timer record (364908).
    PowerState {
        Unspecified = 0 => "unspecified",
        Sleep = 4 => "sleep (S3)",
        Hibernate = 5 => "hibernate (S4)",
    }
);

coded_enum!(
    /// `Reason` of Kernel-Power 42. Rendered: 6 for record 364909, 7 for records 360273, 360235
    /// and 364895.
    SleepReason {
        HibernateFromSleepFixedTimeout = 6 => "hibernate from sleep, fixed timeout",
        SystemIdle = 7 => "system idle",
    }
);

coded_enum!(
    /// `State` of Kernel-Power 172. Rendered: 2 for record 365422.
    StandbyConnectivityState {
        Disconnected = 2 => "disconnected",
    }
);

coded_enum!(
    /// `Reason` of Kernel-Power 172. Rendered: 6 for record 365422.
    StandbyConnectivityReason {
        NicCompliance = 6 => "NIC compliance",
    }
);

coded_enum!(
    /// `Reason` of Kernel-Power 506 and 507. No value is proven: this machine has no Modern
    /// Standby, so every code stays "type N" until someone with that hardware renders one.
    ModernStandbyReason {}
);

/// Power-Troubleshooter 1: the system returned from a low power state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerTroubleshooterWake {
    pub meta: Meta,
    pub sleep_time: Option<Timestamp>,
    pub wake_time: Option<Timestamp>,
    pub target_state: Option<PowerState>,
    pub effective_state: Option<PowerState>,
    pub source: WakeSourceType,
    /// For a device wake, the device name. Display text, possibly localized, never branched on.
    pub source_text: Option<String>,
    pub timer_owner: Option<String>,
    pub timer_context: Option<String>,
}

impl PowerTroubleshooterWake {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Power-Troubleshooter 1", POWER_TROUBLESHOOTER, &[1])?;
        Ok(Self {
            meta,
            sleep_time: raw.timestamp("SleepTime"),
            wake_time: raw.timestamp("WakeTime"),
            target_state: raw.u32("TargetState").map(PowerState::from_code),
            effective_state: raw.u32("EffectiveState").map(PowerState::from_code),
            source: WakeSourceType::from_code(req_u32(raw, "WakeSourceType")?),
            source_text: raw.text("WakeSourceText"),
            timer_owner: raw.text("WakeTimerOwner"),
            timer_context: raw.text("WakeTimerContext"),
        })
    }

    /// The S4 doze timer record: Windows logs it when the doze timer moves a sleeping machine to
    /// hibernate, with `SleepTime == WakeTime` and `TargetState` 0. It is not a user-visible sleep.
    pub fn is_doze_timer(&self) -> bool {
        self.sleep_time.is_some()
            && self.sleep_time == self.wake_time
            && self.target_state == Some(PowerState::Unspecified)
    }

    /// The device name of a device wake.
    pub fn device_name(&self) -> Option<&str> {
        if self.source == WakeSourceType::Device {
            self.source_text.as_deref()
        } else {
            None
        }
    }

    pub fn to_evidence(&self) -> Evidence {
        let mut e = self
            .meta
            .evidence(SYSTEM, 1)
            .opt("sleep_time", self.sleep_time)
            .opt("wake_time", self.wake_time)
            .code("wake_source", self.source)
            .opt("wake_source_text", self.source_text.as_deref())
            .opt("wake_timer_owner", self.timer_owner.as_deref())
            .opt("wake_timer_context", self.timer_context.as_deref());
        if let Some(s) = self.target_state {
            e = e.code("target_state", s);
        }
        if let Some(s) = self.effective_state {
            e = e.code("effective_state", s);
        }
        if self.is_doze_timer() {
            e = e.with_field("doze_timer", "true");
        }
        e
    }
}

/// Kernel-Power 42: the system is entering sleep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleepEntered {
    pub meta: Meta,
    pub target_state: PowerState,
    pub effective_state: Option<PowerState>,
    pub reason: Option<SleepReason>,
    pub flags: Option<u32>,
    pub transitions_to_on: Option<u32>,
}

impl SleepEntered {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 42", KERNEL_POWER, &[42])?;
        Ok(Self {
            meta,
            target_state: PowerState::from_code(req_u32(raw, "TargetState")?),
            effective_state: raw.u32("EffectiveState").map(PowerState::from_code),
            reason: raw.u32("Reason").map(SleepReason::from_code),
            flags: raw.u32("Flags"),
            transitions_to_on: raw.u32("TransitionsToOn"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        let mut e = self
            .meta
            .evidence(SYSTEM, 42)
            .code("target_state", self.target_state)
            .opt("flags", self.flags)
            .opt("transitions_to_on", self.transitions_to_on);
        if let Some(s) = self.effective_state {
            e = e.code("effective_state", s);
        }
        if let Some(r) = self.reason {
            e = e.code("sleep_reason", r);
        }
        e
    }
}

/// Kernel-Power 107: the system resumed from sleep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleepResumed {
    pub meta: Meta,
    pub target_state: PowerState,
    pub effective_state: Option<PowerState>,
    pub wake_from_state: Option<PowerState>,
    /// The wake time armed when the system went to sleep, on AC and on battery. `None` when the
    /// log wrote a FILETIME of zero.
    pub programmed_wake_ac: Option<Timestamp>,
    pub programmed_wake_dc: Option<Timestamp>,
    /// `WakeRequesterTypeAc` and `...Dc`. NOT PROVEN: the message does not render them. On this
    /// machine 4 appeared exactly when a 3 hour wake was programmed after a "system idle" sleep, and
    /// 0 when none was, but nothing records what the number means, so it is carried as a number.
    pub wake_requester_type_ac: Option<u32>,
    pub wake_requester_type_dc: Option<u32>,
}

impl SleepResumed {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 107", KERNEL_POWER, &[107])?;
        Ok(Self {
            meta,
            target_state: PowerState::from_code(req_u32(raw, "TargetState")?),
            effective_state: raw.u32("EffectiveState").map(PowerState::from_code),
            wake_from_state: raw.u32("WakeFromState").map(PowerState::from_code),
            programmed_wake_ac: raw.timestamp("ProgrammedWakeTimeAc"),
            programmed_wake_dc: raw.timestamp("ProgrammedWakeTimeDc"),
            wake_requester_type_ac: raw.u32("WakeRequesterTypeAc"),
            wake_requester_type_dc: raw.u32("WakeRequesterTypeDc"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        let mut e = self
            .meta
            .evidence(SYSTEM, 107)
            .code("target_state", self.target_state)
            .opt("programmed_wake_ac", self.programmed_wake_ac)
            .opt("programmed_wake_dc", self.programmed_wake_dc)
            .opt("wake_requester_type_ac", self.wake_requester_type_ac)
            .opt("wake_requester_type_dc", self.wake_requester_type_dc);
        if let Some(s) = self.wake_from_state {
            e = e.code("wake_from_state", s);
        }
        e
    }
}

/// Kernel-Power 41: the system rebooted without a clean shutdown.
///
/// `SleepInProgress` is a boolean in version 2 and a number from version 3, and versions 0 to 10
/// differ in which fields exist, so every field except the identity is optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncleanReboot {
    pub meta: Meta,
    pub bugcheck_code: Option<u32>,
    /// `BugcheckParameter1` to `4` in order. `None` marks one the record lacks, so the ones after
    /// it keep their position. Trailing absent ones are dropped.
    pub bugcheck_parameters: Vec<Option<u64>>,
    /// Zero when no sleep was in progress. A boolean `true` reads as 1.
    pub sleep_in_progress: Option<u32>,
    pub power_button_pressed: Option<Timestamp>,
    pub connected_standby_in_progress: Option<bool>,
    pub long_power_button_press: Option<bool>,
    pub checkpoint: Option<u32>,
}

impl UncleanReboot {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 41", KERNEL_POWER, &[41])?;
        let mut bugcheck_parameters: Vec<Option<u64>> = (1..=4)
            .map(|n| raw.u64(&format!("BugcheckParameter{n}")))
            .collect();
        while bugcheck_parameters.last() == Some(&None) {
            bugcheck_parameters.pop();
        }
        Ok(Self {
            meta,
            bugcheck_code: raw.u32("BugcheckCode"),
            bugcheck_parameters,
            sleep_in_progress: number_or_bool(raw, "SleepInProgress"),
            power_button_pressed: raw.filetime("PowerButtonTimestamp"),
            connected_standby_in_progress: raw.bool("ConnectedStandbyInProgress"),
            long_power_button_press: raw.bool("LongPowerButtonPressDetected"),
            checkpoint: raw.u32("Checkpoint"),
        })
    }

    /// True when the record names a bugcheck. Zero means Windows did not know a cause.
    pub fn bugcheck_recorded(&self) -> bool {
        self.bugcheck_code.is_some_and(|c| c != 0)
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 41)
            .opt(
                "bugcheck_code",
                self.bugcheck_code.map(|c| format!("0x{c:08x}")),
            )
            .opt(
                "bugcheck_parameters",
                parameters_text(&self.bugcheck_parameters),
            )
            .opt("sleep_in_progress", self.sleep_in_progress)
            .opt("power_button_pressed", self.power_button_pressed)
            .opt(
                "connected_standby_in_progress",
                self.connected_standby_in_progress,
            )
            .opt("long_power_button_press", self.long_power_button_press)
            .opt("checkpoint", self.checkpoint)
    }
}

/// Kernel-Power 105: the power source changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerSourceChanged {
    pub meta: Meta,
    pub on_ac: bool,
    /// Version 1 and later. Units are those of the battery driver, so only compare them to each
    /// other.
    pub remaining_capacity: Option<u32>,
    pub full_charge_capacity: Option<u32>,
}

impl PowerSourceChanged {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 105", KERNEL_POWER, &[105])?;
        Ok(Self {
            meta,
            on_ac: raw
                .bool("AcOnline")
                .ok_or(FromRawError::MissingField("AcOnline"))?,
            remaining_capacity: raw.u32("RemainingCapacity"),
            full_charge_capacity: raw.u32("FullChargeCapacity"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 105)
            .with_field("on_ac", self.on_ac.to_string())
            .opt("remaining_capacity", self.remaining_capacity)
            .opt("full_charge_capacity", self.full_charge_capacity)
    }
}

/// Kernel-Power 172: connectivity state in standby.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandbyConnectivity {
    pub meta: Meta,
    pub state: StandbyConnectivityState,
    pub reason: Option<StandbyConnectivityReason>,
}

impl StandbyConnectivity {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 172", KERNEL_POWER, &[172])?;
        Ok(Self {
            meta,
            state: StandbyConnectivityState::from_code(req_u32(raw, "State")?),
            reason: raw.u32("Reason").map(StandbyConnectivityReason::from_code),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        let mut e = self.meta.evidence(SYSTEM, 172).code("state", self.state);
        if let Some(r) = self.reason {
            e = e.code("reason", r);
        }
        e
    }
}

/// Kernel-Power 506: the system is entering Modern Standby.
///
/// Built from the manifest only; this machine has never logged one (see the synthetic fixture).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModernStandbyEntered {
    pub meta: Meta,
    pub reason: ModernStandbyReason,
    pub lid_open: Option<bool>,
    pub external_monitor_connected: Option<bool>,
    pub battery_remaining_on_enter: Option<u32>,
    pub battery_full_charge_on_enter: Option<u32>,
}

impl ModernStandbyEntered {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 506", KERNEL_POWER, &[506])?;
        Ok(Self {
            meta,
            reason: ModernStandbyReason::from_code(req_u32(raw, "Reason")?),
            lid_open: raw.bool("LidOpenState"),
            external_monitor_connected: raw.bool("ExternalMonitorConnectedState"),
            battery_remaining_on_enter: raw.u32("BatteryRemainingCapacityOnEnter"),
            battery_full_charge_on_enter: raw.u32("BatteryFullChargeCapacityOnEnter"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 506)
            .code("reason", self.reason)
            .opt("lid_open", self.lid_open)
            .opt(
                "external_monitor_connected",
                self.external_monitor_connected,
            )
            .opt(
                "battery_remaining_on_enter",
                self.battery_remaining_on_enter,
            )
            .opt(
                "battery_full_charge_on_enter",
                self.battery_full_charge_on_enter,
            )
    }
}

/// Kernel-Power 507: the system is exiting Modern Standby.
///
/// Built from the manifest only. Durations are microseconds (the field names end in `InUs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModernStandbyExited {
    pub meta: Meta,
    pub reason: ModernStandbyReason,
    pub energy_drain: Option<u32>,
    pub duration_us: Option<u64>,
    pub active_residency_us: Option<u64>,
    pub drips_residency_us: Option<u64>,
    pub hw_drips_residency_us: Option<u64>,
    pub drips_transitions: Option<u32>,
    pub audio_playing: Option<bool>,
    pub power_state_ac: Option<bool>,
    pub disconnected_standby: Option<bool>,
    pub battery_remaining_on_exit: Option<u32>,
    pub battery_full_charge_on_exit: Option<u32>,
}

impl ModernStandbyExited {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(raw, "Kernel-Power 507", KERNEL_POWER, &[507])?;
        Ok(Self {
            meta,
            reason: ModernStandbyReason::from_code(req_u32(raw, "Reason")?),
            energy_drain: raw.u32("EnergyDrain"),
            duration_us: raw.u64("DurationInUs"),
            active_residency_us: raw.u64("ActiveResidencyInUs"),
            drips_residency_us: raw.u64("DripsResidencyInUs"),
            hw_drips_residency_us: raw.u64("HwDripsResidencyInUs"),
            drips_transitions: raw.u32("DripsTransitions"),
            audio_playing: raw.bool("AudioPlaying"),
            power_state_ac: raw.bool("PowerStateAc"),
            disconnected_standby: raw.bool("DisconnectedStandby"),
            battery_remaining_on_exit: raw.u32("BatteryRemainingCapacityOnExit"),
            battery_full_charge_on_exit: raw.u32("BatteryFullChargeCapacityOnExit"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 507)
            .code("reason", self.reason)
            .opt("energy_drain", self.energy_drain)
            .opt("duration_us", self.duration_us)
            .opt("active_residency_us", self.active_residency_us)
            .opt("drips_residency_us", self.drips_residency_us)
            .opt("hw_drips_residency_us", self.hw_drips_residency_us)
            .opt("drips_transitions", self.drips_transitions)
            .opt("audio_playing", self.audio_playing)
            .opt("power_state_ac", self.power_state_ac)
            .opt("disconnected_standby", self.disconnected_standby)
            .opt("battery_remaining_on_exit", self.battery_remaining_on_exit)
            .opt(
                "battery_full_charge_on_exit",
                self.battery_full_charge_on_exit,
            )
    }
}

/// Any of the Kernel-Power events this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelPowerEvent {
    SleepEntered(SleepEntered),
    SleepResumed(SleepResumed),
    UncleanReboot(UncleanReboot),
    PowerSourceChanged(PowerSourceChanged),
    StandbyConnectivity(StandbyConnectivity),
    ModernStandbyEntered(ModernStandbyEntered),
    ModernStandbyExited(ModernStandbyExited),
}

impl KernelPowerEvent {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        match raw.event_id {
            Some(42) => SleepEntered::from_raw(raw).map(Self::SleepEntered),
            Some(107) => SleepResumed::from_raw(raw).map(Self::SleepResumed),
            Some(41) => UncleanReboot::from_raw(raw).map(Self::UncleanReboot),
            Some(105) => PowerSourceChanged::from_raw(raw).map(Self::PowerSourceChanged),
            Some(172) => StandbyConnectivity::from_raw(raw).map(Self::StandbyConnectivity),
            Some(506) => ModernStandbyEntered::from_raw(raw).map(Self::ModernStandbyEntered),
            Some(507) => ModernStandbyExited::from_raw(raw).map(Self::ModernStandbyExited),
            _ => Err(FromRawError::WrongEvent {
                expected: "Kernel-Power 41, 42, 105, 107, 172, 506 or 507",
                provider: raw.provider.clone(),
                event_id: raw.event_id,
            }),
        }
    }

    pub fn meta(&self) -> &Meta {
        match self {
            Self::SleepEntered(e) => &e.meta,
            Self::SleepResumed(e) => &e.meta,
            Self::UncleanReboot(e) => &e.meta,
            Self::PowerSourceChanged(e) => &e.meta,
            Self::StandbyConnectivity(e) => &e.meta,
            Self::ModernStandbyEntered(e) => &e.meta,
            Self::ModernStandbyExited(e) => &e.meta,
        }
    }

    pub fn to_evidence(&self) -> Evidence {
        match self {
            Self::SleepEntered(e) => e.to_evidence(),
            Self::SleepResumed(e) => e.to_evidence(),
            Self::UncleanReboot(e) => e.to_evidence(),
            Self::PowerSourceChanged(e) => e.to_evidence(),
            Self::StandbyConnectivity(e) => e.to_evidence(),
            Self::ModernStandbyEntered(e) => e.to_evidence(),
            Self::ModernStandbyExited(e) => e.to_evidence(),
        }
    }
}

/// Kernel-Processor-Power 37: firmware is limiting the speed of a processor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorCapped {
    pub meta: Meta,
    pub group: Option<u32>,
    pub processor: u32,
    pub cap_duration_seconds: Option<u32>,
    pub ppc_changes: Option<u32>,
    pub tpc_changes: Option<u32>,
    pub pcc_changes: Option<u32>,
}

impl ProcessorCapped {
    pub fn from_raw(raw: &RawEvent) -> Result<Self, FromRawError> {
        let meta = Meta::expect(
            raw,
            "Kernel-Processor-Power 37",
            KERNEL_PROCESSOR_POWER,
            &[37],
        )?;
        Ok(Self {
            meta,
            group: raw.u32("Group"),
            processor: req_u32(raw, "Number")?,
            cap_duration_seconds: raw.u32("CapDurationInSeconds"),
            ppc_changes: raw.u32("PpcChanges"),
            tpc_changes: raw.u32("TpcChanges"),
            pcc_changes: raw.u32("PccChanges"),
        })
    }

    pub fn to_evidence(&self) -> Evidence {
        self.meta
            .evidence(SYSTEM, 37)
            .opt("group", self.group)
            .with_field("processor", self.processor.to_string())
            .opt("cap_duration_seconds", self.cap_duration_seconds)
            .opt("ppc_changes", self.ppc_changes)
            .opt("tpc_changes", self.tpc_changes)
            .opt("pcc_changes", self.pcc_changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::testutil::{first_with_id, fixture_events, record};

    const WAKES: &str = "power-troubleshooter-1.xml";

    fn wake(record_id: u64) -> PowerTroubleshooterWake {
        PowerTroubleshooterWake::from_raw(&record(WAKES, record_id)).unwrap()
    }

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    /// The first real check from docs/PLAN.md: a Power Button wake from sleep.
    #[test]
    fn golden_record_360285_is_a_power_button_wake() {
        let w = wake(360285);
        assert_eq!(w.source, WakeSourceType::PowerButton);
        assert_eq!(w.target_state, Some(PowerState::Sleep));
        assert_eq!(w.wake_time, Some(ts("2026-10-28T14:30:32.4608457Z")));
        assert_eq!(w.sleep_time, Some(ts("2026-10-28T13:02:56.2098645Z")));
        assert_eq!(w.meta.record_id, Some(360285));
        assert!(!w.is_doze_timer());
        assert_eq!(w.device_name(), None);
        // To the second, as the plan words it.
        assert!(
            w.wake_time
                .unwrap()
                .to_string()
                .starts_with("2026-10-28T14:30:32")
        );
        assert!(
            w.sleep_time
                .unwrap()
                .to_string()
                .starts_with("2026-10-28T13:02:56")
        );

        let e = w.to_evidence();
        assert_eq!(e.source, SourceId::EventLogSystem);
        assert_eq!(e.record_id.as_deref(), Some("360285"));
        // The record is stamped with its TimeCreated (14:30:33 in the plan); the wake moment is a field.
        assert_eq!(e.timestamp, Some(ts("2026-10-28T14:30:33.5068879Z")));
        assert_eq!(e.fields["wake_time"], "2026-10-28T14:30:32.4608457Z");
        assert_eq!(e.fields["sleep_time"], "2026-10-28T13:02:56.2098645Z");
        assert_eq!(e.fields["wake_source"], "power button");
        assert_eq!(e.fields["wake_source_code"], "1");
        assert_eq!(e.fields["target_state"], "sleep (S3)");
    }

    /// The second real check: Unknown, from hibernate (`TargetState` 5).
    #[test]
    fn golden_record_364927_is_an_unknown_wake_from_hibernate() {
        let w = wake(364927);
        assert_eq!(w.source, WakeSourceType::Unknown);
        assert_eq!(w.target_state, Some(PowerState::Hibernate));
        assert_eq!(w.effective_state, Some(PowerState::Hibernate));
        assert!(
            w.wake_time
                .unwrap()
                .to_string()
                .starts_with("2026-11-03T12:33:07")
        );
        assert!(
            w.sleep_time
                .unwrap()
                .to_string()
                .starts_with("2026-11-03T12:11:52")
        );
        assert!(!w.is_doze_timer());
        assert_eq!(w.to_evidence().fields["wake_source"], "unknown");
    }

    #[test]
    fn s4_doze_record_is_distinguishable() {
        let doze = wake(364908);
        assert_eq!(doze.source, WakeSourceType::S4DozeToHibernate);
        assert_eq!(doze.target_state, Some(PowerState::Unspecified));
        assert_eq!(doze.sleep_time, doze.wake_time);
        assert!(doze.is_doze_timer());
        assert_eq!(doze.to_evidence().fields["doze_timer"], "true");
        assert!(wake(344155).is_doze_timer());
        // Every other wake in the file is a real resume.
        let others = fixture_events(WAKES)
            .iter()
            .filter(|r| r.record_id != Some(364908) && r.record_id != Some(344155))
            .map(|r| PowerTroubleshooterWake::from_raw(r).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(others.len(), 9);
        assert!(others.iter().all(|w| !w.is_doze_timer()));
        // A doze record needs both conditions, not just the source type.
        let mut not_doze = doze.clone();
        not_doze.target_state = Some(PowerState::Hibernate);
        assert!(!not_doze.is_doze_timer());
    }

    #[test]
    fn device_wakes_carry_the_device_name() {
        let usb = wake(360247);
        assert_eq!(usb.source, WakeSourceType::Device);
        assert_eq!(
            usb.device_name(),
            Some("Intel(R) USB 3.10 eXtensible Host Controller - 1.20 (Microsoft)")
        );
        assert_eq!(wake(358340).device_name(), Some("USB Input Device"));
        assert_eq!(
            wake(358340).to_evidence().fields["wake_source_text"],
            "USB Input Device"
        );
        assert_eq!(wake(360285).device_name(), None);
    }

    #[test]
    fn unseen_wake_source_types_stay_numbers() {
        let mut raw = record(WAKES, 360285);
        for d in raw
            .data
            .iter_mut()
            .filter(|d| d.name.as_deref() == Some("WakeSourceType"))
        {
            d.value = "7".into();
        }
        let w = PowerTroubleshooterWake::from_raw(&raw).unwrap();
        assert_eq!(w.source, WakeSourceType::Other(7));
        assert_eq!(w.to_evidence().fields["wake_source"], "type 7");
    }

    #[test]
    fn every_power_troubleshooter_version_parses() {
        // Versions 0 to 3 add fields; only WakeSourceType is required. The oldest shape:
        let mut raw = record(WAKES, 360285);
        raw.version = Some(0);
        raw.data.retain(|d| {
            !matches!(
                d.name.as_deref(),
                Some(
                    "WakeTimerOwner"
                        | "WakeTimerContext"
                        | "NoMultiStageResumeReason"
                        | "CheckpointDuration"
                )
            )
        });
        assert!(PowerTroubleshooterWake::from_raw(&raw).is_ok());
        raw.data
            .retain(|d| d.name.as_deref() != Some("WakeSourceType"));
        assert_eq!(
            PowerTroubleshooterWake::from_raw(&raw),
            Err(FromRawError::MissingField("WakeSourceType"))
        );
    }

    #[test]
    fn wrong_provider_is_refused() {
        let raw = first_with_id("kernel-power-41.xml", 41);
        assert!(matches!(
            PowerTroubleshooterWake::from_raw(&raw),
            Err(FromRawError::WrongEvent { .. })
        ));
    }

    #[test]
    fn sleep_entered_names_only_proven_reasons() {
        let idle =
            SleepEntered::from_raw(&record("kernel-power-sleep-resume.xml", 360273)).unwrap();
        assert_eq!(idle.target_state, PowerState::Sleep);
        assert_eq!(idle.reason, Some(SleepReason::SystemIdle));
        assert_eq!(idle.transitions_to_on, Some(2));
        let hib = SleepEntered::from_raw(&record("kernel-power-sleep-resume.xml", 364909)).unwrap();
        assert_eq!(hib.target_state, PowerState::Hibernate);
        assert_eq!(
            hib.reason,
            Some(SleepReason::HibernateFromSleepFixedTimeout)
        );
        assert_eq!(
            hib.to_evidence().fields["sleep_reason"],
            "hibernate from sleep, fixed timeout"
        );
        let mut raw = record("kernel-power-sleep-resume.xml", 360273);
        raw.data.iter_mut().for_each(|d| {
            if d.name.as_deref() == Some("Reason") {
                d.value = "2".into();
            }
        });
        assert_eq!(
            SleepEntered::from_raw(&raw).unwrap().to_evidence().fields["sleep_reason"],
            "type 2"
        );
    }

    #[test]
    fn sleep_resumed_reads_the_programmed_wake_and_treats_1601_as_none() {
        let armed =
            SleepResumed::from_raw(&record("kernel-power-sleep-resume.xml", 360274)).unwrap();
        assert_eq!(
            armed.programmed_wake_ac,
            Some(ts("2026-10-28T16:02:57.7983014Z"))
        );
        assert_eq!(armed.wake_requester_type_ac, Some(4));
        assert_eq!(armed.wake_from_state, Some(PowerState::Sleep));
        let none =
            SleepResumed::from_raw(&record("kernel-power-sleep-resume.xml", 364910)).unwrap();
        assert_eq!(none.programmed_wake_ac, None);
        assert_eq!(none.programmed_wake_dc, None);
        assert_eq!(none.wake_from_state, Some(PowerState::Hibernate));
        assert!(!none.to_evidence().fields.contains_key("programmed_wake_ac"));
    }

    #[test]
    fn power_source_and_standby_connectivity() {
        let events = fixture_events("kernel-power-105-172.xml");
        let ac = PowerSourceChanged::from_raw(&events[5]).unwrap();
        assert!(ac.on_ac);
        assert_eq!(
            (ac.remaining_capacity, ac.full_charge_capacity),
            (Some(53370), Some(69310))
        );
        let battery = PowerSourceChanged::from_raw(&events[1]).unwrap();
        assert!(!battery.on_ac);
        let c = StandbyConnectivity::from_raw(&events[0]).unwrap();
        assert_eq!(c.state, StandbyConnectivityState::Disconnected);
        assert_eq!(c.reason, Some(StandbyConnectivityReason::NicCompliance));
        assert_eq!(c.to_evidence().fields["state"], "disconnected");
    }

    #[test]
    fn kernel_power_41_real_records_have_no_bugcheck() {
        let events = fixture_events("kernel-power-41.xml");
        let reboots: Vec<_> = events
            .iter()
            .map(|r| UncleanReboot::from_raw(r).unwrap())
            .collect();
        assert_eq!(reboots.len(), 3);
        assert!(reboots.iter().all(|r| !r.bugcheck_recorded()));
        assert_eq!(reboots[0].sleep_in_progress, Some(4));
        assert_eq!(
            reboots[0].power_button_pressed,
            Some(ts("2026-10-31T22:04:01.8214252Z"))
        );
        assert_eq!(reboots[1].sleep_in_progress, Some(0));
        assert_eq!(reboots[1].power_button_pressed, None);
        assert_eq!(
            reboots[0].bugcheck_parameters,
            [Some(0), Some(0), Some(0), Some(0)]
        );
        assert_eq!(reboots[0].checkpoint, Some(16));
    }

    #[test]
    fn kernel_power_41_parameters_keep_their_position_when_one_is_absent() {
        let mut raw = fixture_events("synthetic-kernel-power-41-versions.xml").remove(2);
        let full = UncleanReboot::from_raw(&raw).unwrap().bugcheck_parameters;
        assert!(full.iter().all(Option::is_some) && full.len() == 4);
        raw.data
            .retain(|d| d.name.as_deref() != Some("BugcheckParameter2"));
        let gap = UncleanReboot::from_raw(&raw).unwrap();
        assert_eq!(gap.bugcheck_parameters, [full[0], None, full[2], full[3]]);
        assert!(gap.to_evidence().fields["bugcheck_parameters"].contains(", ?, "));
        raw.data
            .retain(|d| d.name.as_deref() != Some("BugcheckParameter4"));
        let short = UncleanReboot::from_raw(&raw).unwrap();
        assert_eq!(short.bugcheck_parameters, [full[0], None, full[2]]);
    }

    /// Versions 0 to 10 of event 41 differ. Built from the manifest, not real validation.
    #[test]
    fn kernel_power_41_versions_do_not_break_parsing() {
        let events = fixture_events("synthetic-kernel-power-41-versions.xml");
        let versions: Vec<_> = events.iter().map(|r| r.version.unwrap()).collect();
        assert_eq!(versions, [0, 1, 2, 3, 5]);
        let parsed: Vec<_> = events
            .iter()
            .map(|r| UncleanReboot::from_raw(r).unwrap())
            .collect();
        // v0 has no data at all.
        assert_eq!(parsed[0].bugcheck_code, None);
        assert!(parsed[0].bugcheck_parameters.is_empty());
        assert_eq!(parsed[0].sleep_in_progress, None);
        // v1 has only the bugcheck code.
        assert_eq!(parsed[1].bugcheck_code, Some(0));
        // v2 writes SleepInProgress as a boolean, and a real bugcheck code.
        assert_eq!(parsed[2].sleep_in_progress, Some(1));
        assert!(parsed[2].bugcheck_recorded());
        assert_eq!(parsed[2].bugcheck_code, Some(0x9f));
        assert_eq!(parsed[2].bugcheck_parameters.len(), 4);
        assert_eq!(parsed[2].bugcheck_parameters[0], Some(3));
        // v3 and later write a number.
        assert_eq!(parsed[3].sleep_in_progress, Some(4));
        assert_eq!(parsed[4].connected_standby_in_progress, Some(true));
        assert_eq!(
            parsed[2].to_evidence().fields["bugcheck_code"],
            "0x0000009f"
        );
    }

    /// Built from the manifest of Kernel-Power 506 and 507, not real validation: this machine has
    /// no Modern Standby.
    #[test]
    fn synthetic_modern_standby_events_parse_across_versions() {
        let events = fixture_events("synthetic-kernel-power-modern-standby.xml");
        let entered: Vec<_> = events
            .iter()
            .filter(|r| r.event_id == Some(506))
            .map(|r| ModernStandbyEntered::from_raw(r).unwrap())
            .collect();
        assert_eq!(entered.len(), 2);
        assert_eq!(entered[0].meta.version, Some(0));
        assert_eq!(entered[0].lid_open, None);
        assert_eq!(entered[1].meta.version, Some(3));
        assert_eq!(entered[1].lid_open, Some(false));
        assert_eq!(entered[1].battery_remaining_on_enter, Some(61230));
        assert_eq!(entered[1].reason, ModernStandbyReason::Other(2));
        assert_eq!(entered[1].to_evidence().fields["reason"], "type 2");

        let exited: Vec<_> = events
            .iter()
            .filter(|r| r.event_id == Some(507))
            .map(|r| ModernStandbyExited::from_raw(r).unwrap())
            .collect();
        assert_eq!(exited.len(), 2);
        assert_eq!(exited[0].hw_drips_residency_us, None);
        assert_eq!(exited[1].hw_drips_residency_us, Some(6_900_000_000));
        assert_eq!(exited[1].drips_residency_us, Some(7_100_000_000));
        assert_eq!(exited[1].duration_us, Some(7_200_000_000));
        assert_eq!(exited[1].energy_drain, Some(3120));
        assert_eq!(exited[1].disconnected_standby, Some(false));
        assert_eq!(exited[1].to_evidence().record_id.as_deref(), Some("900004"));
    }

    #[test]
    fn family_dispatch_covers_every_kernel_power_event() {
        for name in [
            "kernel-power-41.xml",
            "kernel-power-105-172.xml",
            "kernel-power-sleep-resume.xml",
            "synthetic-kernel-power-modern-standby.xml",
            "synthetic-kernel-power-41-versions.xml",
        ] {
            for raw in fixture_events(name) {
                let event =
                    KernelPowerEvent::from_raw(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(event.meta().record_id, raw.record_id);
                assert_eq!(
                    event.to_evidence().record_id,
                    raw.record_id.map(|r| r.to_string())
                );
            }
        }
        assert!(KernelPowerEvent::from_raw(&record(WAKES, 360285)).is_err());
    }

    #[test]
    fn processor_capped() {
        let events = fixture_events("kernel-processor-power-37.xml");
        let c = ProcessorCapped::from_raw(&events[0]).unwrap();
        assert_eq!(
            (c.group, c.processor, c.cap_duration_seconds),
            (Some(0), 19, Some(71))
        );
        assert_eq!(c.pcc_changes, Some(1));
        assert_eq!(c.to_evidence().fields["processor"], "19");
    }
}
