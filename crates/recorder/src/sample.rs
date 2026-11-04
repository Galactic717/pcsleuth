//! Turning what the sources return into the sample the ring stores. Pure, so it builds anywhere.

use jiff::Timestamp;
use pcsleuth_core::{RecordedProcess, RecordedRequest, RecorderRow, Sourced};
use pcsleuth_sources::power::{PowerRequest, Reason, RequestType, Requester};
use pcsleuth_sources::processes::{ProcessRate, Top};

use crate::ring::{MAX_PER_LIST, Sample};

/// The sample for one tick.
///
/// `top` is the ranking between the last two process samples and `at` the time of the later one.
/// `interval_secs` is the span the rates cover, which is longer than the configured interval when
/// the machine slept between ticks, so a finding states what the rates really average over.
///
/// `requests` is the read of live power requests. Anything but a full read (no admin, in practice)
/// sets `requests_visible` to false, so an empty list is never mistaken for "none held".
pub fn build_sample(at: Timestamp, top: &Top, requests: &Sourced<PowerRequest>) -> Sample {
    let list = |rates: &[ProcessRate]| -> Vec<RecordedProcess> {
        rates.iter().take(MAX_PER_LIST).map(recorded).collect()
    };
    let interval_secs = top
        .interval
        .as_secs_f64()
        .round()
        .clamp(1.0, f64::from(u32::MAX));
    Sample {
        row: RecorderRow {
            at,
            interval_secs: interval_secs as u32,
            top_cpu: list(&top.by_cpu),
            top_io: list(&top.by_io),
            power_requests: requests.data.iter().flat_map(recorded_requests).collect(),
            requests_visible: requests.access.is_ok(),
        },
        truncated: false,
    }
}

fn recorded(rate: &ProcessRate) -> RecordedProcess {
    RecordedProcess {
        name: rate.name.clone(),
        cpu_permille: (rate.cpu_percent * 10.0).round() as u32,
        io_bytes_per_sec: (rate.io_read_bytes_per_sec + rate.io_write_bytes_per_sec).round() as u64,
    }
}

/// One recorded request per mode the request holds.
fn recorded_requests(request: &PowerRequest) -> Vec<RecordedRequest> {
    let owner = owner(&request.requester);
    let reason = request.reason.as_ref().map(|r| match r {
        Reason::Text(text) => text.clone(),
        // The usual way to write a string resource: `@file,-id`.
        Reason::Resource { file, id } => format!("@{file},-{id}"),
    });
    request
        .active
        .iter()
        .map(|(kind, _count)| RecordedRequest {
            owner: owner.clone(),
            kind: kind_name(*kind).into(),
            reason: reason.clone(),
        })
        .collect()
}

fn kind_name(kind: RequestType) -> &'static str {
    match kind {
        RequestType::Display => "display",
        RequestType::System => "system",
        RequestType::AwayMode => "away_mode",
        RequestType::Execution => "execution",
        RequestType::PerfBoost => "perf_boost",
        RequestType::ActiveLockScreen => "active_lock_screen",
    }
}

/// The file name of an NT or Win32 path.
fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn owner(requester: &Requester) -> String {
    match requester {
        Requester::Process { pid, image } => image
            .as_deref()
            .map_or_else(|| format!("pid {pid}"), |path| base_name(path).to_owned()),
        Requester::Service { pid, image, tag } => {
            let name = image
                .as_deref()
                .map_or_else(|| format!("pid {pid}"), |path| base_name(path).to_owned());
            format!("{name} (service tag {tag})")
        }
        Requester::Driver {
            description,
            device_path,
        } => description
            .clone()
            .or_else(|| device_path.clone())
            .unwrap_or_else(|| "driver".into()),
        Requester::Unknown(kind) => format!("unknown requester type {kind}"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pcsleuth_core::{Access, SourceId};

    use super::*;

    fn rate(name: &str, percent: f64, read: f64, write: f64) -> ProcessRate {
        ProcessRate {
            pid: 1,
            name: name.into(),
            cpu_cores: 0.0,
            cpu_percent: percent,
            working_set_bytes: 0,
            private_bytes: 0,
            io_read_bytes_per_sec: read,
            io_write_bytes_per_sec: write,
        }
    }

    fn top(secs: f64) -> Top {
        Top {
            interval: Duration::from_secs_f64(secs),
            by_cpu: vec![rate("busy.exe", 12.34, 10.0, 0.0)],
            by_io: vec![rate("disk.exe", 0.04, 1_000.4, 2_000.4)],
            by_memory: vec![],
        }
    }

    fn at() -> Timestamp {
        Timestamp::from_second(1_793_692_800).unwrap()
    }

    fn holding(
        requester: Requester,
        active: &[RequestType],
        reason: Option<Reason>,
    ) -> PowerRequest {
        PowerRequest {
            requester,
            active: active.iter().map(|t| (*t, 1)).collect(),
            reason,
        }
    }

    #[test]
    fn processes_become_permille_and_bytes_per_second() {
        let ok = Sourced::ok(SourceId::PowerRequests, vec![]);
        let s = build_sample(at(), &top(60.2), &ok);
        assert_eq!(s.row.interval_secs, 60);
        assert_eq!(
            s.row.top_cpu,
            vec![RecordedProcess {
                name: "busy.exe".into(),
                cpu_permille: 123,
                io_bytes_per_sec: 10,
            }]
        );
        assert_eq!(s.row.top_io[0].io_bytes_per_sec, 3_001);
        assert_eq!(s.row.top_io[0].cpu_permille, 0);
        assert!(s.row.requests_visible && !s.truncated);
    }

    #[test]
    fn the_interval_is_what_the_rates_cover_and_never_zero() {
        let ok = Sourced::ok(SourceId::PowerRequests, vec![]);
        // The machine slept: the rates are averages over three hours.
        assert_eq!(
            build_sample(at(), &top(10_800.4), &ok).row.interval_secs,
            10_800
        );
        assert_eq!(build_sample(at(), &top(0.0), &ok).row.interval_secs, 1);
    }

    #[test]
    fn without_admin_the_row_says_requests_were_not_visible() {
        let denied = Sourced::unreadable(SourceId::PowerRequests, Access::NeedsAdmin);
        let s = build_sample(at(), &top(60.0), &denied);
        assert!(s.row.power_requests.is_empty());
        assert!(!s.row.requests_visible);
        // A read that listed nothing is a real "none held".
        let none = Sourced::ok(SourceId::PowerRequests, vec![]);
        assert!(build_sample(at(), &top(60.0), &none).row.requests_visible);
        // A partial read is not a full one either.
        let partial = Sourced {
            source: SourceId::PowerRequests,
            access: Access::Partial {
                message: "x".into(),
            },
            data: vec![],
        };
        assert!(
            !build_sample(at(), &top(60.0), &partial)
                .row
                .requests_visible
        );
    }

    #[test]
    fn requests_name_their_owner_and_one_row_per_mode() {
        let requests = Sourced::ok(
            SourceId::PowerRequests,
            vec![
                holding(
                    Requester::Process {
                        pid: 4,
                        image: Some(
                            r"\Device\HarddiskVolume3\Program Files\Teams\teams.exe".into(),
                        ),
                    },
                    &[RequestType::Display, RequestType::System],
                    Some(Reason::Text("In a call".into())),
                ),
                holding(
                    Requester::Service {
                        pid: 8,
                        image: Some(r"C:\Windows\System32\svchost.exe".into()),
                        tag: 7,
                    },
                    &[RequestType::Execution],
                    Some(Reason::Resource {
                        file: "x.dll".into(),
                        id: 12,
                    }),
                ),
                holding(
                    Requester::Driver {
                        description: None,
                        device_path: Some(r"\Device\Audio".into()),
                    },
                    &[RequestType::AwayMode],
                    None,
                ),
                holding(
                    Requester::Process {
                        pid: 99,
                        image: None,
                    },
                    &[RequestType::PerfBoost],
                    None,
                ),
                holding(
                    Requester::Unknown(3),
                    &[RequestType::ActiveLockScreen],
                    None,
                ),
            ],
        );
        let got = build_sample(at(), &top(60.0), &requests).row.power_requests;
        let flat: Vec<_> = got
            .iter()
            .map(|r| (r.owner.as_str(), r.kind.as_str(), r.reason.as_deref()))
            .collect();
        assert_eq!(
            flat,
            vec![
                ("teams.exe", "display", Some("In a call")),
                ("teams.exe", "system", Some("In a call")),
                (
                    "svchost.exe (service tag 7)",
                    "execution",
                    Some("@x.dll,-12")
                ),
                (r"\Device\Audio", "away_mode", None),
                ("pid 99", "perf_boost", None),
                ("unknown requester type 3", "active_lock_screen", None),
            ]
        );
    }

    #[test]
    fn at_most_five_processes_per_list() {
        let mut t = top(60.0);
        t.by_cpu = (0..9)
            .map(|i| rate(&format!("p{i}"), 1.0, 0.0, 0.0))
            .collect();
        let ok = Sourced::ok(SourceId::PowerRequests, vec![]);
        let s = build_sample(at(), &t, &ok);
        assert_eq!(s.row.top_cpu.len(), MAX_PER_LIST);
        assert!(!s.truncated);
    }
}
