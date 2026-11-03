//! Pins the JSON shape of `Answer`. If this fails, the contract changed: bump `SCHEMA_VERSION`,
//! tell the packages that read it, then regenerate with `PCSLEUTH_UPDATE_GOLDEN=1 cargo test -p
//! pcsleuth-core --test golden`.

use pcsleuth_core::{
    Access, Answer, Evidence, Finding, Fix, NotRecorded, Question, SourceId, Sourced, Timestamp,
    merge_timeline,
};

const GOLDEN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/answer.json");

fn ts(text: &str) -> Timestamp {
    text.parse().unwrap()
}

fn sample_answer() -> Answer {
    // Real record 360285 from fixtures/eventlog: a Power Button wake. The device name keeps
    // non-ASCII text on purpose, since the contract must carry it unescaped.
    let power_button = Finding::recorded(
        "wake.power_button",
        Question::Wake,
        "Woke because the power button was pressed",
        "Windows recorded the power button as the wake source.",
        [Evidence::new(SourceId::EventLogSystem)
            .with_record_id("360285")
            .at(ts("2026-10-28T14:30:33Z"))
            .with_field("provider", "Microsoft-Windows-Power-Troubleshooter")
            .with_field("event_id", "1")
            .with_field("WakeSourceType", "1")
            .with_field("note", "\u{41f}\u{440}\u{438}\u{432}\u{456}\u{442}")],
    )
    .unwrap()
    .at(ts("2026-10-28T14:30:33Z"));

    // Real record 364927: a hibernate resume, where the firmware does not say what woke it.
    let hibernate = Finding::correlated(
        "wake.hibernate_resume",
        Question::Wake,
        "Woke from hibernate, cause unknown",
        "Hibernate resume usually reports an unknown source.",
        [Evidence::new(SourceId::EventLogSystem)
            .with_record_id("364927")
            .at(ts("2026-11-03T12:33:08Z"))
            .with_field("WakeSourceType", "0")],
    )
    .unwrap()
    .at(ts("2026-11-03T12:33:08Z"))
    .with_gap(NotRecorded::new(
        "what woke the machine from hibernate",
        "nothing in Windows; the firmware does not report it",
    ))
    .unwrap();

    let busy = Finding::sampled(
        "slow.cpu_hog",
        Question::Slow,
        "One process used most of the CPU",
        "Seen in 9 of 10 recorder samples, taken 5 seconds apart.",
        [Evidence::new(SourceId::Recorder).with_field("samples", "9/10")],
    )
    .unwrap();

    let blockers = Finding::not_recorded(
        "nosleep.past_blockers",
        Question::NoSleep,
        "Windows did not record what kept it awake",
        "Past power requests are not logged.",
        NotRecorded::new(
            "which program held a power request in the past",
            "the recorder, or `powercfg /requests` while it is happening",
        ),
    )
    .unwrap()
    .with_fix(Fix::new(
        "powercfg /requests",
        "Lists the current power requests and who holds them.",
        true,
    ));

    let limits = [
        Sourced::<()>::unreadable(SourceId::PowerRequests, Access::NeedsAdmin),
        Sourced::<()>::unreadable(SourceId::ScheduledTasks, Access::LogDisabled),
        Sourced::<()>::unreadable(SourceId::Recorder, Access::Missing),
        Sourced::<()>::unreadable(
            SourceId::Srum,
            Access::Failed {
                code: 0x1f,
                message: "A device attached to the system is not functioning.".into(),
            },
        ),
        Sourced::ok(SourceId::EventLogSystem, vec![()]),
    ]
    .iter()
    .filter_map(Sourced::limit)
    .collect();

    Answer::new(
        Question::Timeline,
        ts("2026-11-03T13:00:00Z"),
        merge_timeline([busy, blockers, hibernate, power_button]),
        limits,
    )
}

fn read_golden() -> String {
    // Git may check the file out with CRLF on Windows.
    std::fs::read_to_string(GOLDEN_PATH)
        .unwrap()
        .replace("\r\n", "\n")
}

#[test]
fn answer_json_matches_the_golden_file() {
    let json = serde_json::to_string_pretty(&sample_answer()).unwrap() + "\n";
    if std::env::var_os("PCSLEUTH_UPDATE_GOLDEN").is_some() {
        std::fs::write(GOLDEN_PATH, &json).unwrap();
    }
    assert_eq!(json, read_golden(), "the JSON shape of Answer changed");
}

#[test]
fn golden_file_round_trips_through_the_types() {
    let parsed: Answer = serde_json::from_str(&read_golden()).unwrap();
    assert_eq!(parsed, sample_answer());
}

#[test]
fn timestamps_are_rfc3339_utc() {
    let value = serde_json::to_value(sample_answer()).unwrap();
    assert_eq!(value["generated_at"], "2026-11-03T13:00:00Z");
    assert_eq!(value["schema_version"], 1);
}

#[test]
fn timeline_is_oldest_first_with_untimed_last() {
    let ids: Vec<_> = sample_answer()
        .findings
        .iter()
        .map(|f| f.id().to_owned())
        .collect();
    assert_eq!(
        ids,
        [
            "wake.power_button",
            "wake.hibernate_resume",
            "slow.cpu_hog",
            "nosleep.past_blockers"
        ]
    );
}
