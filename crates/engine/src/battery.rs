//! `battery`: what wore the battery out, and what drained it?
//!
//! Wear and the biggest drains come from the battery report. Which app used the energy comes from
//! SRUM, which only an administrator can read, and is shown as "likely" and only for the whole
//! hours that fit inside a drain, because SRUM keeps hourly totals.

use std::collections::BTreeMap;

use jiff::{SignedDuration, Timestamp};
use pcsleuth_core::{
    Answer, Evidence, Finding, FindingError, NotRecorded, Question, SourceId, Sourced,
};
use pcsleuth_sources::battery::{Battery, BatteryReport, EnergyDrain};
use pcsleuth_sources::srum::AppUsage;

use crate::common::{Findings, Limits, Window, between, duration, exe_name, finish};

pub struct Input {
    pub report: Sourced<BatteryReport>,
    pub srum: Sourced<AppUsage>,
}

/// How many of the biggest drains are shown.
const DRAINS_SHOWN: usize = 3;

pub fn answer(input: &Input, window: &Window) -> Answer {
    let mut limits = Limits::default();
    limits.note(&input.report);
    limits.note(&input.srum);

    let mut out = Findings::default();
    match input.report.data.first() {
        Some(report) => {
            for battery in &report.batteries {
                wear(battery, report, window, &mut out);
            }
            drains(report, &input.srum, window, &mut out);
        }
        None => out.push(Finding::not_recorded(
            "battery.no_report",
            Question::Battery,
            "Windows gave pcsleuth no battery report",
            "The battery report is where Windows keeps capacity history and energy drains. This \
             PC has no battery, or Windows could not make the report.",
            NotRecorded::new(
                "the battery's wear and recent drains",
                "a PC with a battery; pcsleuth doctor says why the report could not be read",
            ),
        )),
    }
    if input.srum.data.is_empty() && !input.srum.access.is_ok() {
        out.push(app_energy_gap(&input.srum));
    }
    finish(Question::Battery, window, out.0, limits)
}

fn wh(mwh: u64) -> String {
    format!("{:.1} Wh", mwh as f64 / 1000.0)
}

fn wear(battery: &Battery, report: &BatteryReport, window: &Window, out: &mut Findings) {
    let (Some(wear), Some(design), Some(full)) = (
        battery.wear_percent(),
        battery.design_capacity_mwh,
        battery.full_charge_capacity_mwh,
    ) else {
        return;
    };
    let cycles = battery
        .cycle_count
        .map(|n| format!(" It has been through {n} charge cycles."))
        .unwrap_or_default();
    let history = {
        let first = report.capacity_history.first();
        let last = report.capacity_history.last();
        match (first, last) {
            (Some(first), Some(last)) => match (
                first.full_charge_capacity_mwh,
                last.full_charge_capacity_mwh,
                between(Some(first.start), Some(last.end)),
            ) {
                (Some(then), Some(now), Some(span)) if report.capacity_history.len() > 1 => {
                    format!(
                        " Over the {} of history in the report, the full-charge capacity fell \
                         from {} to {}.",
                        duration(span),
                        wh(then),
                        wh(now)
                    )
                }
                _ => String::new(),
            },
            _ => String::new(),
        }
    };
    let mut evidence = Evidence::new(SourceId::BatteryReport)
        .at(report.scanned_at.unwrap_or(window.now))
        .with_field("design_capacity_mwh", design.to_string())
        .with_field("full_charge_capacity_mwh", full.to_string())
        .with_field("wear_percent", format!("{wear:.1}"));
    if let Some(n) = battery.cycle_count {
        evidence = evidence.with_field("cycle_count", n.to_string());
    }
    out.push(Finding::recorded(
        "battery.wear",
        Question::Battery,
        format!(
            "The battery holds {:.0}% of its original capacity",
            100.0 - wear
        ),
        format!(
            "Windows' battery report says a full charge now holds {} against {} when new, which \
             is {wear:.0}% worn. Some wear is normal over time.{cycles}{history}",
            wh(full),
            wh(design)
        ),
        [evidence],
    ));
}

fn drains(report: &BatteryReport, srum: &Sourced<AppUsage>, window: &Window, out: &mut Findings) {
    let full_capacity = report
        .batteries
        .first()
        .and_then(|b| b.full_charge_capacity_mwh);
    let mut biggest: Vec<(&EnergyDrain, u64)> = report
        .energy_drains
        .iter()
        .filter(|d| window.contains(Some(d.end)))
        .filter_map(|d| Some((d, u64::try_from(d.drained_mwh()?).ok()?)))
        .filter(|(_, mwh)| *mwh > 0)
        .collect();
    biggest.sort_by_key(|(_, mwh)| std::cmp::Reverse(*mwh));
    biggest.truncate(DRAINS_SHOWN);

    for (drain, mwh) in biggest {
        let full = drain.start_full_charge_mwh.or(full_capacity);
        let size = match full.filter(|f| *f > 0) {
            Some(full) => format!("{:.0}%", mwh as f64 / full as f64 * 100.0),
            None => wh(mwh),
        };
        let span = between(Some(drain.start), Some(drain.end))
            .map(|span| format!(" in {}", duration(span)))
            .unwrap_or_default();
        let evidence = drain_evidence(drain, mwh);
        out.push(
            Finding::recorded(
                "battery.drain",
                Question::Battery,
                format!("The battery dropped {size}{span}"),
                format!(
                    "Windows' battery report (energy drains) shows the charge fell by {} while \
                     the PC ran on battery.",
                    wh(mwh)
                ),
                [evidence.clone()],
            )
            .map(|f| f.at(drain.start)),
        );
        if let Some(apps) = apps_in(drain, srum, window) {
            out.push(drain_apps(drain, evidence, apps));
        }
    }
}

fn drain_evidence(drain: &EnergyDrain, mwh: u64) -> Evidence {
    Evidence::new(SourceId::BatteryReport)
        .at(drain.start)
        .with_field("start", drain.start.to_string())
        .with_field("end", drain.end.to_string())
        .with_field("drained_mwh", mwh.to_string())
}

struct Apps {
    /// (app, energy on battery, hour of the last bucket counted), biggest first.
    ranked: Vec<(String, u64, Timestamp)>,
    total: u64,
}

/// SRUM energy for the whole hours inside `drain` that are also inside the window.
fn apps_in(drain: &EnergyDrain, srum: &Sourced<AppUsage>, window: &Window) -> Option<Apps> {
    let hour = SignedDuration::from_hours(1);
    let mut by_app: BTreeMap<&str, (u64, Timestamp)> = BTreeMap::new();
    for bucket in &srum.data {
        let whole_hour_inside = bucket.hour >= drain.start
            && bucket
                .hour
                .checked_add(hour)
                .is_ok_and(|end| end <= drain.end);
        if whole_hour_inside
            && window.contains(Some(bucket.hour))
            && bucket.usage.energy_on_battery > 0
        {
            let entry = by_app
                .entry(bucket.app.as_str())
                .or_insert((0, bucket.hour));
            entry.0 = entry.0.saturating_add(bucket.usage.energy_on_battery);
            entry.1 = entry.1.max(bucket.hour);
        }
    }
    let total: u64 = by_app
        .values()
        .map(|(energy, _)| *energy)
        .fold(0, u64::saturating_add);
    let mut ranked: Vec<_> = by_app
        .into_iter()
        .map(|(app, (energy, hour))| (app.to_owned(), energy, hour))
        .collect();
    ranked.sort_by_key(|(_, energy, _)| std::cmp::Reverse(*energy));
    (total > 0 && !ranked.is_empty()).then_some(Apps { ranked, total })
}

fn drain_apps(
    drain: &EnergyDrain,
    drain_evidence: Evidence,
    apps: Apps,
) -> Result<Finding, FindingError> {
    let (top, top_energy, top_hour) = &apps.ranked[0];
    let name = exe_name(top).unwrap_or_else(|| top.clone());
    let mut srum = Evidence::new(SourceId::Srum)
        .at(*top_hour)
        .with_field("app", top.as_str())
        .with_field("energy_on_battery", top_energy.to_string());
    if let Some(exe) = exe_name(top) {
        srum = srum.with_field("process", exe);
    }
    let share = |energy: u64| energy as f64 / apps.total as f64 * 100.0;
    let list: Vec<String> = apps
        .ranked
        .iter()
        .take(3)
        .map(|(app, energy, _)| {
            format!(
                "{} {:.0}%",
                exe_name(app).unwrap_or_else(|| app.clone()),
                share(*energy)
            )
        })
        .collect();
    Finding::correlated(
        "battery.drain_apps",
        Question::Battery,
        format!("During that drain, {name} likely used the most energy"),
        format!(
            "Windows' per-app energy records (SRUM) for the whole hours inside that drain rank \
             the apps: {}. SRUM keeps hourly totals and its energy numbers are estimates, so this \
             is a likely cause and not proof.",
            list.join(", ")
        ),
        [drain_evidence, srum],
    )
    .map(|f| f.at(drain.start))
}

fn app_energy_gap(srum: &Sourced<AppUsage>) -> Result<Finding, FindingError> {
    let would_capture = if srum.access.elevation_helps() {
        "run pcsleuth battery --elevate: Windows keeps per-app usage records (SRUM) with energy estimates, but only \
         an administrator can read them"
    } else {
        "pcsleuth doctor shows why the per-app energy records could not be read"
    };
    Finding::not_recorded(
        "battery.app_energy",
        Question::Battery,
        "Which apps used the battery's energy was not read",
        "Without per-app energy records pcsleuth can say how much the battery dropped and when, \
         but not which app was responsible.",
        NotRecorded::new("which app used the energy in each drain", would_capture),
    )
}
