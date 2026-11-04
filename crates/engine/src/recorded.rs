//! Findings from the opt-in recorder. Each is `Sampled`: the recorder looked at an interval, so
//! anything shorter can be missed, and every explanation says so with the interval.

use std::collections::BTreeMap;

use jiff::Timestamp;
use pcsleuth_core::{Finding, Question, RecorderRow, SourceId, Sourced};

use crate::common::{Findings, Window, between, bytes, duration, exe_name};

/// The recorder's rows inside the window, oldest first.
pub fn rows_in_window<'a>(
    recorder: &'a Sourced<RecorderRow>,
    window: &Window,
) -> Vec<&'a RecorderRow> {
    let mut rows: Vec<&RecorderRow> = recorder
        .data
        .iter()
        .filter(|row| window.contains(Some(row.at)))
        .collect();
    rows.sort_by_key(|row| row.at);
    rows
}

fn watched(rows: &[&RecorderRow]) -> String {
    let interval = rows.iter().map(|r| r.interval_secs).max().unwrap_or(0);
    let span = between(rows.first().map(|r| r.at), rows.last().map(|r| r.at))
        .map(|span| format!(" over {}", duration(span)))
        .unwrap_or_default();
    format!(
        "The recorder samples every {interval} s ({} samples here{span}), so anything that lasted \
         less than that can be missed.",
        rows.len()
    )
}

/// How many rows could see power requests. A row recorded without admin has an empty list that
/// means "not visible", so it counts for nothing here, either way.
pub fn seeing_requests(rows: &[&RecorderRow]) -> usize {
    rows.iter().filter(|row| row.requests_visible).count()
}

/// A sentence for the rows that could not see power requests, or nothing when there are none.
fn blind_note(rows: &[&RecorderRow]) -> String {
    let blind = rows.len() - seeing_requests(rows);
    if blind == 0 {
        return String::new();
    }
    format!(
        " {blind} of the {} samples could not see power requests because the recorder was not \
         running as admin, so a blocker held during those would not show here.",
        rows.len()
    )
}

fn kind_label(kind: &str) -> String {
    match kind {
        "away_mode" => "away mode".into(),
        other => other.replace('_', " "),
    }
}

struct Seen {
    count: usize,
    first: Timestamp,
    last: Timestamp,
    reason: Option<String>,
}

/// Power requests the recorder saw, grouped by owner and kind. Returns whether it made any.
pub fn request_findings(rows: &[&RecorderRow], out: &mut Findings) -> bool {
    let mut groups: BTreeMap<(&str, &str), Seen> = BTreeMap::new();
    // Only samples that could see requests can say one was held, or count as one that looked.
    for row in rows.iter().filter(|row| row.requests_visible) {
        for request in &row.power_requests {
            let seen = groups
                .entry((request.owner.as_str(), request.kind.as_str()))
                .or_insert(Seen {
                    count: 0,
                    first: row.at,
                    last: row.at,
                    reason: None,
                });
            seen.count += 1;
            seen.last = seen.last.max(row.at);
            seen.first = seen.first.min(row.at);
            if request.reason.is_some() {
                seen.reason.clone_from(&request.reason);
            }
        }
    }
    let total = seeing_requests(rows);
    let made = !groups.is_empty();
    for ((owner, kind), seen) in groups {
        let mut evidence = pcsleuth_core::Evidence::new(SourceId::Recorder)
            .at(seen.last)
            .with_field("samples", format!("{}/{total}", seen.count))
            .with_field(
                "interval_secs",
                rows.iter()
                    .map(|r| r.interval_secs)
                    .max()
                    .unwrap_or(0)
                    .to_string(),
            )
            .with_field("kind", kind)
            .with_field("first_seen", seen.first.to_string())
            .with_field("last_seen", seen.last.to_string());
        evidence = match exe_name(owner) {
            Some(exe) => evidence.with_field("process", exe),
            None => evidence.with_field("owner", owner),
        };
        let reason = seen
            .reason
            .as_deref()
            .map(|r| format!(" The reason it gave: \"{r}\"."))
            .unwrap_or_default();
        out.push(
            Finding::sampled(
                "nosleep.recorder_request",
                Question::NoSleep,
                format!(
                    "{owner} held a {} power request in {} of {total} recorder samples",
                    kind_label(kind),
                    seen.count
                ),
                format!("{}{reason}{}", watched(rows), blind_note(rows)),
                [evidence],
            )
            .map(|f| f.at(seen.last)),
        );
    }
    made
}

/// Processes the recorder often saw busy, by CPU and by IO. Returns whether it made any.
pub fn busy_findings(rows: &[&RecorderRow], out: &mut Findings) -> bool {
    // ponytail: fixed thresholds, a tenth of the machine and 20 MiB/s. Make them options if a
    // real recording shows them too high or too low.
    const BUSY_CPU_PERMILLE: u32 = 100;
    const BUSY_IO_PER_SEC: u64 = 20 * 1024 * 1024;

    let total = rows.len();
    let mut made = false;
    for (id, cpu) in [("slow.recorder_cpu", true), ("slow.recorder_io", false)] {
        let mut groups: BTreeMap<&str, (usize, u64, u64, Timestamp)> = BTreeMap::new();
        for row in rows {
            let list = if cpu { &row.top_cpu } else { &row.top_io };
            for process in list {
                let amount = if cpu {
                    u64::from(process.cpu_permille)
                } else {
                    process.io_bytes_per_sec
                };
                let busy = if cpu {
                    amount >= u64::from(BUSY_CPU_PERMILLE)
                } else {
                    amount >= BUSY_IO_PER_SEC
                };
                if busy {
                    let entry = groups
                        .entry(process.name.as_str())
                        .or_insert((0, 0, 0, row.at));
                    entry.0 += 1;
                    entry.1 += amount;
                    entry.2 = entry.2.max(amount);
                    entry.3 = entry.3.max(row.at);
                }
            }
        }
        let mut ranked: Vec<_> = groups.into_iter().collect();
        ranked.sort_by_key(|(_, (count, sum, _, _))| {
            std::cmp::Reverse((*count as u64) * 1_000_000 + sum / (*count as u64).max(1))
        });
        for (name, (count, sum, max, last)) in ranked.into_iter().take(3) {
            let mean = sum / count as u64;
            let (what, how) = if cpu {
                (
                    "busy on the CPU",
                    format!(
                        "When busy it used {:.0}% of the whole machine on average and {:.0}% at most.",
                        mean as f64 / 10.0,
                        max as f64 / 10.0
                    ),
                )
            } else {
                (
                    "doing a lot of IO",
                    format!(
                        "When busy it moved {}/s on average and {}/s at most. IO counts disk, \
                         network and other transfers together.",
                        bytes(mean),
                        bytes(max)
                    ),
                )
            };
            let evidence = pcsleuth_core::Evidence::new(SourceId::Recorder)
                .at(last)
                .with_field("process", name)
                .with_field("samples", format!("{count}/{total}"))
                .with_field(
                    "interval_secs",
                    rows.iter()
                        .map(|r| r.interval_secs)
                        .max()
                        .unwrap_or(0)
                        .to_string(),
                );
            out.push(
                Finding::sampled(
                    id,
                    Question::Slow,
                    format!("{name} was {what} in {count} of {total} recorder samples"),
                    format!("{how} {}", watched(rows)),
                    [evidence],
                )
                .map(|f| f.at(last)),
            );
            made = true;
        }
    }
    made
}
