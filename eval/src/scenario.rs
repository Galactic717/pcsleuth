//! The scenarios: a known true cause, a question, and whether Windows records the cause in a place
//! the tool can read under the current privileges. Pure data; the runner executes it.

use pcsleuth_core::{Question, SourceId};

use crate::score::{Cause, Observable};

/// One injector. Its exe name is the cause the engine must name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    PowerRequest,
    WakeTimer,
    Cpu,
    Disk,
    Crash,
    Hang,
}

impl Fault {
    pub const ALL: [Fault; 6] = [
        Fault::PowerRequest,
        Fault::WakeTimer,
        Fault::Cpu,
        Fault::Disk,
        Fault::Crash,
        Fault::Hang,
    ];

    /// The exe base name, `pcsleuth-fault-cpu` for `pcsleuth-fault-cpu.exe`.
    pub const fn exe(self) -> &'static str {
        match self {
            Fault::PowerRequest => "pcsleuth-fault-power-request",
            Fault::WakeTimer => "pcsleuth-fault-wake-timer",
            Fault::Cpu => "pcsleuth-fault-cpu",
            Fault::Disk => "pcsleuth-fault-disk",
            Fault::Crash => "pcsleuth-fault-crash",
            Fault::Hang => "pcsleuth-fault-hang",
        }
    }

    pub fn cause(self) -> Cause {
        Cause::process(self.exe())
    }
}

/// How the cause is produced before the question is asked.
#[derive(Debug, Clone, Copy)]
pub enum Inject {
    /// The fault is running when the question is asked. `settle_secs` lets a sampler see it.
    Live {
        fault: Fault,
        secs: u64,
        settle_secs: u64,
    },
    /// The fault ran for `secs` and has exited when the question is asked.
    Past { fault: Fault, secs: u64 },
    /// The fault ends in a logged event. The runner waits for it and keeps its record id.
    Event {
        fault: Fault,
        provider: &'static str,
        event_id: u32,
    },
    /// The machine sleeps (or hibernates) and a timer wakes it. Needs `--sleep`, never default.
    Sleep { fault: Fault, hibernate: bool },
}

/// What the scenario needs for its cause to be observable.
#[derive(Debug, Clone, Copy)]
pub enum Needs {
    /// Windows records it where an unelevated read finds it.
    Nothing,
    /// Readable only when elevated.
    Admin { limit: SourceId, adds: &'static str },
    /// Never recorded, elevated or not.
    Never {
        reason: &'static str,
        limit: Option<SourceId>,
    },
    /// Not known until a run on real hardware.
    Unverified(&'static str),
}

impl Needs {
    pub fn observable(&self, elevated: bool) -> Observable {
        match *self {
            Needs::Nothing => Observable::Yes,
            Needs::Admin { limit, adds } => {
                if elevated {
                    Observable::Yes
                } else {
                    Observable::No {
                        reason: format!("needs admin: {adds}"),
                        limit: Some(limit),
                    }
                }
            }
            Needs::Never { reason, limit } => Observable::No {
                reason: reason.to_owned(),
                limit,
            },
            Needs::Unverified(why) => Observable::Unverified(why.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub name: &'static str,
    pub question: Question,
    pub summary: &'static str,
    pub inject: Inject,
    pub needs: Needs,
}

impl Scenario {
    pub fn fault(&self) -> Fault {
        match self.inject {
            Inject::Live { fault, .. }
            | Inject::Past { fault, .. }
            | Inject::Event { fault, .. }
            | Inject::Sleep { fault, .. } => fault,
        }
    }

    /// Sleep scenarios stop the machine. They run only with `--sleep` and a typed confirmation.
    pub fn sleeps(&self) -> bool {
        matches!(self.inject, Inject::Sleep { .. })
    }
}

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "crash-app-error",
        question: Question::Crash,
        summary: "A program dies on an unhandled exception; Windows logs Application Error 1000.",
        inject: Inject::Event {
            fault: Fault::Crash,
            provider: "Application Error",
            event_id: 1000,
        },
        needs: Needs::Nothing,
    },
    Scenario {
        name: "hang-app-hang",
        question: Question::Crash,
        summary: "A program stops answering and is reported hung; Windows logs Application Hang 1002. \
                  The trigger is the program reporting itself, see docs/EVAL.md.",
        inject: Inject::Event {
            fault: Fault::Hang,
            provider: "Application Hang",
            event_id: 1002,
        },
        needs: Needs::Nothing,
    },
    Scenario {
        name: "cpu-hog-live",
        question: Question::Now,
        summary: "A process is using several cores right now.",
        inject: Inject::Live {
            fault: Fault::Cpu,
            secs: 40,
            settle_secs: 4,
        },
        needs: Needs::Nothing,
    },
    Scenario {
        name: "disk-hog-live",
        question: Question::Now,
        summary: "A process is writing to disk right now.",
        inject: Inject::Live {
            fault: Fault::Disk,
            secs: 40,
            settle_secs: 3,
        },
        needs: Needs::Nothing,
    },
    Scenario {
        name: "power-request-live",
        question: Question::NoSleep,
        summary: "A process holds a system-required power request right now. \
                  Unelevated, Windows hides the owner: an honesty scenario.",
        inject: Inject::Live {
            fault: Fault::PowerRequest,
            secs: 40,
            settle_secs: 1,
        },
        needs: Needs::Admin {
            limit: SourceId::PowerRequests,
            adds: "live power requests with their owners",
        },
    },
    Scenario {
        name: "wake-timer-live",
        question: Question::Wake,
        summary: "A process has armed a wake timer, far in the future. \
                  Unelevated, Windows hides it: an honesty scenario.",
        inject: Inject::Live {
            fault: Fault::WakeTimer,
            secs: 40,
            settle_secs: 1,
        },
        needs: Needs::Admin {
            limit: SourceId::WakeTimers,
            adds: "live wake timers",
        },
    },
    Scenario {
        name: "power-request-past",
        question: Question::NoSleep,
        summary: "A process held a power request and released it before the question.",
        inject: Inject::Past {
            fault: Fault::PowerRequest,
            secs: 3,
        },
        needs: Needs::Never {
            reason: "a released power request leaves no record; only the recorder keeps them",
            limit: Some(SourceId::Recorder),
        },
    },
    Scenario {
        name: "cpu-hog-past",
        question: Question::Slow,
        summary: "A process hogged the CPU and exited before the question, recorder off.",
        inject: Inject::Past {
            fault: Fault::Cpu,
            secs: 5,
        },
        needs: Needs::Never {
            reason: "a finished CPU hog leaves no record unless the recorder ran",
            limit: Some(SourceId::Recorder),
        },
    },
    Scenario {
        name: "sleep-timer-wake",
        question: Question::Wake,
        summary: "The machine sleeps and a timer set by a process wakes it. Needs --sleep.",
        inject: Inject::Sleep {
            fault: Fault::WakeTimer,
            hibernate: false,
        },
        needs: Needs::Unverified(
            "Windows names the wake source type; whether it names the timer owner is unknown \
             until run on hardware",
        ),
    },
    Scenario {
        name: "sleep-hibernate-timer-wake",
        question: Question::Wake,
        summary: "The machine hibernates and a timer wakes it. Needs --sleep.",
        inject: Inject::Sleep {
            fault: Fault::WakeTimer,
            hibernate: true,
        },
        needs: Needs::Never {
            reason: "a hibernate resume usually reports an unknown wake source; the firmware does not say",
            limit: None,
        },
    },
];

pub fn find(name: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|scenario| scenario.name == name)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;
    use crate::fault::EXE_PREFIX;

    #[test]
    fn names_are_unique_and_findable() {
        let names: BTreeSet<_> = SCENARIOS.iter().map(|s| s.name).collect();
        assert_eq!(names.len(), SCENARIOS.len());
        for scenario in SCENARIOS {
            assert_eq!(find(scenario.name).map(|s| s.name), Some(scenario.name));
        }
        assert!(find("no-such-scenario").is_none());
    }

    #[test]
    fn every_fault_has_an_injector_source_file_named_after_its_exe() {
        let bin = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("bin");
        for fault in Fault::ALL {
            assert!(fault.exe().starts_with(EXE_PREFIX), "{}", fault.exe());
            assert!(
                bin.join(format!("{}.rs", fault.exe())).is_file(),
                "no injector file for {}",
                fault.exe()
            );
        }
        let files = std::fs::read_dir(&bin).unwrap().count();
        assert_eq!(files, Fault::ALL.len(), "an injector has no Fault entry");
    }

    #[test]
    fn exe_names_are_distinct_and_normalize_to_the_expected_cause() {
        let exes: BTreeSet<_> = Fault::ALL.iter().map(|f| f.exe()).collect();
        assert_eq!(exes.len(), Fault::ALL.len());
        assert_eq!(Fault::Cpu.cause(), Cause::process("PCSLEUTH-FAULT-CPU.EXE"));
    }

    #[test]
    fn only_the_sleep_scenarios_sleep() {
        let sleepers: Vec<_> = SCENARIOS
            .iter()
            .filter(|s| s.sleeps())
            .map(|s| s.name)
            .collect();
        assert_eq!(sleepers, ["sleep-timer-wake", "sleep-hibernate-timer-wake"]);
    }

    #[test]
    fn admin_scenarios_are_honesty_scenarios_until_elevated() {
        let needs = Needs::Admin {
            limit: SourceId::PowerRequests,
            adds: "x",
        };
        assert!(matches!(needs.observable(false), Observable::No { .. }));
        assert_eq!(needs.observable(true), Observable::Yes);
        assert_eq!(Needs::Nothing.observable(false), Observable::Yes);
        assert!(matches!(
            Needs::Never {
                reason: "r",
                limit: None
            }
            .observable(true),
            Observable::No { .. }
        ));
    }

    #[test]
    fn there_are_both_kinds_of_scenario() {
        let unelevated: Vec<_> = SCENARIOS
            .iter()
            .map(|s| s.needs.observable(false))
            .collect();
        assert!(unelevated.contains(&Observable::Yes));
        assert!(
            unelevated
                .iter()
                .any(|o| matches!(o, Observable::No { .. }))
        );
    }
}
