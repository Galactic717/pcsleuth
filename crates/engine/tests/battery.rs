//! `battery` over the real battery report in `fixtures/battery`.

mod support;

use pcsleuth_core::{Access, Confidence, SourceId, Sourced};
use pcsleuth_engine::battery;
use pcsleuth_sources::battery::{BatteryReport, EnergyDrain, parse_battery_report_bytes};
use pcsleuth_sources::srum::{AppUsage, Usage};
use support::{by_id, fixture_path, ts, window};

fn report() -> BatteryReport {
    let bytes = std::fs::read(fixture_path("battery", "battery-report.xml")).unwrap();
    parse_battery_report_bytes(&bytes).unwrap()
}

fn input(report: BatteryReport) -> battery::Input {
    battery::Input {
        report: Sourced::ok(SourceId::BatteryReport, vec![report]),
        srum: Sourced::unreadable(SourceId::Srum, Access::NeedsAdmin),
    }
}

fn biggest_drains(report: &BatteryReport) -> Vec<EnergyDrain> {
    let mut drains = report.energy_drains.clone();
    drains.retain(|d| d.drained_mwh().is_some_and(|mwh| mwh > 0));
    drains.sort_by_key(|d| std::cmp::Reverse(d.drained_mwh()));
    drains.truncate(3);
    drains
}

#[test]
fn wear_comes_from_the_report_and_is_explained() {
    let answer = battery::answer(&input(report()), &window("2026-10-27T00:00:00Z"));
    let wear = by_id(&answer.findings, "battery.wear")[0];
    assert_eq!(wear.confidence(), Confidence::Recorded);
    assert_eq!(
        wear.headline(),
        "The battery holds 87% of its original capacity"
    );
    assert!(wear.explanation().contains("69.3 Wh"));
    assert!(wear.explanation().contains("80.0 Wh when new"));
    assert!(wear.explanation().contains("184 charge cycles"));
    // The history says how it got there.
    assert!(wear.explanation().contains("fell from 78.6 Wh"));
    let evidence = &wear.evidence()[0];
    assert_eq!(evidence.source, SourceId::BatteryReport);
    assert_eq!(evidence.fields["design_capacity_mwh"], "80000");
    assert_eq!(evidence.fields["full_charge_capacity_mwh"], "69340");
    assert!(!evidence.fields.contains_key("process"));
}

#[test]
fn the_biggest_drains_are_the_ones_from_the_report() {
    let report = report();
    let expected = biggest_drains(&report);
    assert!(!expected.is_empty());
    let answer = battery::answer(&input(report), &window("2026-10-27T00:00:00Z"));
    let drains = by_id(&answer.findings, "battery.drain");
    assert_eq!(drains.len(), expected.len());
    for drain in &drains {
        assert_eq!(drain.confidence(), Confidence::Recorded);
        assert!(drain.headline().starts_with("The battery dropped"));
        assert!(drain.time().is_some());
    }
    // The biggest one is there, found by its start time.
    let first = &expected[0];
    assert!(drains.iter().any(|d| d.time() == Some(first.start)));
}

#[test]
fn a_drain_before_the_window_is_not_used() {
    let report = report();
    let answer = battery::answer(&input(report), &window("2026-11-03T00:00:00Z"));
    for drain in by_id(&answer.findings, "battery.drain") {
        assert!(drain.time().unwrap() >= ts("2026-11-02T00:00:00Z"));
    }
}

#[test]
fn without_admin_the_per_app_energy_is_not_recorded_and_says_how_to_get_it() {
    let answer = battery::answer(&input(report()), &window("2026-10-27T00:00:00Z"));
    let gap = by_id(&answer.findings, "battery.app_energy")[0];
    assert_eq!(gap.confidence(), Confidence::NotRecorded);
    assert!(gap.gap().unwrap().would_capture.contains("--elevate"));
    assert!(answer.limits.iter().any(|l| l.source == SourceId::Srum));
    // No app is named when SRUM was not read.
    assert!(by_id(&answer.findings, "battery.drain_apps").is_empty());
    for finding in &answer.findings {
        for evidence in finding.evidence() {
            assert!(!evidence.fields.contains_key("process"));
        }
    }
}

fn bucket(app: &str, hour: &str, energy: u64) -> AppUsage {
    AppUsage {
        app: app.into(),
        user: None,
        hour: ts(hour),
        usage: Usage {
            energy,
            energy_on_battery: energy,
            ..Usage::default()
        },
    }
}

/// A drain that is two and a half hours long so that whole hours fit inside it.
fn report_with_long_drain() -> BatteryReport {
    let mut report = report();
    report.energy_drains = vec![EnergyDrain {
        start: ts("2026-11-02T10:15:00Z"),
        end: ts("2026-11-02T12:45:00Z"),
        start_charge_mwh: Some(60_000),
        start_full_charge_mwh: Some(70_000),
        end_charge_mwh: Some(50_000),
        end_full_charge_mwh: Some(70_000),
    }];
    report
}

#[test]
fn srum_energy_is_correlated_only_for_hours_inside_the_drain() {
    let mut input = input(report_with_long_drain());
    input.srum = Sourced::ok(
        SourceId::Srum,
        vec![
            // Fully inside 10:15-12:45: the 11:00 and 12:00 hours... 12:00-13:00 sticks out past 12:45.
            bucket(
                r"\Device\HarddiskVolume3\Apps\render.exe",
                "2026-11-02T11:00:00Z",
                900,
            ),
            bucket("calm.exe", "2026-11-02T11:00:00Z", 100),
            // Partly outside, so not used even though it is huge.
            bucket("edge.exe", "2026-11-02T10:00:00Z", 100_000),
            bucket("edge.exe", "2026-11-02T12:00:00Z", 100_000),
            // Another day entirely.
            bucket("other.exe", "2026-11-01T11:00:00Z", 100_000),
        ],
    );
    let answer = battery::answer(&input, &window("2026-11-01T00:00:00Z"));
    let finding = by_id(&answer.findings, "battery.drain_apps")[0];
    assert_eq!(finding.confidence(), Confidence::Correlated);
    assert_eq!(
        finding.headline(),
        "During that drain, render.exe likely used the most energy"
    );
    assert!(finding.explanation().contains("likely"));
    assert!(finding.explanation().contains("90%"));
    // It cites the drain from the report and the SRUM hour it relied on.
    let sources: Vec<_> = finding.evidence().iter().map(|e| e.source).collect();
    assert_eq!(sources[0], SourceId::BatteryReport);
    assert!(sources.contains(&SourceId::Srum));
    let named: Vec<_> = finding
        .evidence()
        .iter()
        .filter_map(|e| e.fields.get("process"))
        .collect();
    assert_eq!(named, ["render.exe"]);
    for evidence in finding.evidence() {
        let at = evidence.timestamp.unwrap();
        assert!(at >= ts("2026-11-02T10:15:00Z"));
    }
    // The gap note is gone because SRUM was read.
    assert!(by_id(&answer.findings, "battery.app_energy").is_empty());
}

#[test]
fn a_drain_with_no_whole_srum_hour_inside_it_names_no_app() {
    let mut report = report_with_long_drain();
    report.energy_drains[0].start = ts("2026-11-02T11:10:00Z");
    report.energy_drains[0].end = ts("2026-11-02T11:50:00Z");
    let mut input = input(report);
    input.srum = Sourced::ok(
        SourceId::Srum,
        vec![bucket("render.exe", "2026-11-02T11:00:00Z", 900)],
    );
    let answer = battery::answer(&input, &window("2026-11-01T00:00:00Z"));
    assert!(by_id(&answer.findings, "battery.drain_apps").is_empty());
    assert_eq!(by_id(&answer.findings, "battery.drain").len(), 1);
}

#[test]
fn a_pc_without_a_battery_says_so_and_still_answers() {
    let input = battery::Input {
        report: Sourced::unreadable(SourceId::BatteryReport, Access::Missing),
        srum: Sourced::unreadable(SourceId::Srum, Access::NeedsAdmin),
    };
    let answer = battery::answer(&input, &window("2026-10-27T00:00:00Z"));
    let none = by_id(&answer.findings, "battery.no_report")[0];
    assert_eq!(none.confidence(), Confidence::NotRecorded);
    assert!(none.headline().contains("no battery report"));
    assert!(
        answer
            .limits
            .iter()
            .any(|l| l.source == SourceId::BatteryReport)
    );
}
