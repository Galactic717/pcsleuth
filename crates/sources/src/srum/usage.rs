//! What the reader produces: per app and hour counters, and sums over a time range. Pure: the
//! database reader feeds it rows, the tests feed it numbers.

use std::collections::{BTreeMap, HashMap};

use jiff::Timestamp;

use super::decode::IdName;
use crate::eventlog::collapse_profile_path;

/// Counters for one app over one span. Summing two spans adds field by field, saturating.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// CPU cycles used while the app was in the foreground.
    pub cpu_cycles_foreground: u64,
    /// CPU cycles used in the background.
    pub cpu_cycles_background: u64,
    /// Bytes read from disk, foreground and background together.
    pub bytes_read: u64,
    /// Bytes written to disk, foreground and background together.
    pub bytes_written: u64,
    /// Bytes sent over any network interface.
    pub net_sent: u64,
    /// Bytes received over any network interface.
    pub net_received: u64,
    /// Estimated energy, in the units SRUM's estimator stores and `powercfg /srumutil` prints
    /// (`TotalEnergyConsumption`). Summed over every machine-wide reading, a busy hour on the test
    /// laptop came to about 1e8, which fits millijoules; that is inferred, not proven.
    pub energy: u64,
    /// The part of `energy` recorded while the machine ran on battery.
    pub energy_on_battery: u64,
}

impl Usage {
    /// Add `other` into `self`.
    pub fn add(&mut self, other: &Usage) {
        self.cpu_cycles_foreground = self
            .cpu_cycles_foreground
            .saturating_add(other.cpu_cycles_foreground);
        self.cpu_cycles_background = self
            .cpu_cycles_background
            .saturating_add(other.cpu_cycles_background);
        self.bytes_read = self.bytes_read.saturating_add(other.bytes_read);
        self.bytes_written = self.bytes_written.saturating_add(other.bytes_written);
        self.net_sent = self.net_sent.saturating_add(other.net_sent);
        self.net_received = self.net_received.saturating_add(other.net_received);
        self.energy = self.energy.saturating_add(other.energy);
        self.energy_on_battery = self
            .energy_on_battery
            .saturating_add(other.energy_on_battery);
    }

    /// All CPU cycles, foreground and background.
    pub fn cpu_cycles(&self) -> u64 {
        self.cpu_cycles_foreground
            .saturating_add(self.cpu_cycles_background)
    }

    /// The share of `energy` spent on battery, from 0.0 to 1.0, or `None` when no energy was
    /// recorded (so the share is undefined, not zero). Only the energy table carries the
    /// on-battery flag.
    pub fn on_battery_share(&self) -> Option<f64> {
        (self.energy > 0).then(|| self.energy_on_battery as f64 / self.energy as f64)
    }
}

/// Who an app ran as, without saying who. SRUM names accounts by SID; the SID identifies a person,
/// so it is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AccountKind {
    /// A person's account: a local, domain or Microsoft account (`S-1-5-21-...`, `S-1-12-1-...`).
    User,
    /// Anything that is not a person's account: Local System, Local Service, Network Service,
    /// service and virtual accounts.
    System,
}

impl AccountKind {
    /// The kind of account a SID string names.
    pub fn from_sid(sid: &str) -> AccountKind {
        if sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-") {
            AccountKind::User
        } else {
            AccountKind::System
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            AccountKind::User => "user",
            AccountKind::System => "system",
        }
    }
}

impl std::fmt::Display for AccountKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One app's counters for one UTC hour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppUsage {
    /// The name SRUM stores: an executable path, a service name or a package family name, with a
    /// user profile folder written as `%USERPROFILE%`. An id the id map does not know, or that
    /// names a SID, reads `#<id>`.
    pub app: String,
    /// The kind of account, when the id map has a SID for it. Accounts of the same kind share a
    /// bucket.
    pub user: Option<AccountKind>,
    /// Start of the UTC hour the readings fall in.
    pub hour: Timestamp,
    pub usage: Usage,
}

/// One app's counters summed over a range of hours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTotal {
    pub app: String,
    pub user: Option<AccountKind>,
    /// How many hour buckets went into the sum.
    pub hours: u32,
    pub usage: Usage,
}

/// Sum the `buckets` that overlap `[since, until)` per app and kind of account, biggest energy
/// first, then by name so the order is stable.
///
/// A bucket is a whole hour, so `since` in the middle of an hour keeps that hour's bucket: it is
/// compared with the start of its hour. `until` is exclusive, so a bucket that starts at `until`
/// is out and one that starts before it is in.
pub fn aggregate(buckets: &[AppUsage], since: Timestamp, until: Timestamp) -> Vec<AppTotal> {
    let first_hour = hour_start(since);
    let mut totals: BTreeMap<(&str, Option<AccountKind>), AppTotal> = BTreeMap::new();
    for bucket in buckets
        .iter()
        .filter(|b| first_hour <= b.hour && b.hour < until)
    {
        let key = (bucket.app.as_str(), bucket.user);
        let total = totals.entry(key).or_insert_with(|| AppTotal {
            app: bucket.app.clone(),
            user: bucket.user,
            hours: 0,
            usage: Usage::default(),
        });
        total.hours += 1;
        total.usage.add(&bucket.usage);
    }
    let mut totals: Vec<AppTotal> = totals.into_values().collect();
    totals.sort_by(|a, b| {
        b.usage
            .energy
            .cmp(&a.usage.energy)
            .then_with(|| a.app.cmp(&b.app))
            .then_with(|| a.user.cmp(&b.user))
    });
    totals
}

/// The start of the UTC hour containing `ts`.
pub fn hour_start(ts: Timestamp) -> Timestamp {
    let seconds = ts.as_second();
    Timestamp::from_second(seconds - seconds.rem_euclid(3600)).unwrap_or(ts)
}

/// Id to name, from `SruDbIdMapTable`.
#[derive(Debug, Default)]
pub(crate) struct IdMap {
    names: HashMap<i64, IdName>,
}

impl IdMap {
    pub(crate) fn insert(&mut self, id: i64, name: IdName) {
        self.names.insert(id, name);
    }

    /// The app's name, with the user profile folder collapsed. An id that is unknown, empty or a
    /// SID reads `#<id>`.
    fn app(&self, id: i64) -> String {
        match self.names.get(&id) {
            Some(IdName::Text(name) | IdName::Opaque(name)) if !name.is_empty() => {
                collapse_profile_path(name).into_owned()
            }
            _ => format!("#{id}"),
        }
    }

    /// The kind of account, when the id map holds a SID for `id`.
    fn user(&self, id: i64) -> Option<AccountKind> {
        match self.names.get(&id) {
            Some(IdName::Sid(sid)) => Some(AccountKind::from_sid(sid)),
            _ => None,
        }
    }
}

/// Groups readings into (hour, app id, user id) buckets inside a time window.
#[derive(Debug)]
pub(crate) struct Accumulator {
    since: Timestamp,
    until: Timestamp,
    buckets: BTreeMap<(i64, i64, i64), Usage>,
}

impl Accumulator {
    pub(crate) fn new(since: Timestamp, until: Timestamp) -> Self {
        Accumulator {
            since,
            until,
            buckets: BTreeMap::new(),
        }
    }

    /// True when a reading taken at `at` falls in `[since, until)`.
    pub(crate) fn contains(&self, at: Timestamp) -> bool {
        self.since <= at && at < self.until
    }

    /// Add one reading taken at `at`. Readings outside `[since, until)` are dropped.
    pub(crate) fn add(&mut self, at: Timestamp, app: i64, user: i64, delta: &Usage) {
        if !self.contains(at) {
            return;
        }
        self.buckets
            .entry((hour_start(at).as_second(), app, user))
            .or_default()
            .add(delta);
    }

    /// Name the ids and order the buckets by hour, then app, then kind of account. Ids that end up
    /// with the same hour, name and kind (two people's accounts, two ids for one app) are one
    /// bucket, so a bucket is unique and `aggregate` counts each hour once.
    pub(crate) fn finish(self, names: &IdMap) -> Vec<AppUsage> {
        let mut merged: BTreeMap<(i64, String, Option<AccountKind>), Usage> = BTreeMap::new();
        for ((hour, app, user), usage) in self.buckets {
            merged
                .entry((hour, names.app(app), names.user(user)))
                .or_default()
                .add(&usage);
        }
        merged
            .into_iter()
            .filter_map(|((hour, app, user), usage)| {
                Some(AppUsage {
                    app,
                    user,
                    hour: Timestamp::from_second(hour).ok()?,
                    usage,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn usage(energy: u64, on_battery: u64) -> Usage {
        Usage {
            energy,
            energy_on_battery: on_battery,
            ..Usage::default()
        }
    }

    fn bucket(app: &str, hour: &str, usage: Usage) -> AppUsage {
        AppUsage {
            app: app.into(),
            user: Some(AccountKind::User),
            hour: ts(hour),
            usage,
        }
    }

    #[test]
    fn hour_start_floors_to_the_utc_hour_including_before_1970() {
        assert_eq!(
            hour_start(ts("2026-11-03T12:59:59Z")),
            ts("2026-11-03T12:00:00Z")
        );
        assert_eq!(
            hour_start(ts("2026-11-03T12:00:00Z")),
            ts("2026-11-03T12:00:00Z")
        );
        assert_eq!(
            hour_start(ts("1969-12-31T23:30:00Z")),
            ts("1969-12-31T23:00:00Z")
        );
    }

    #[test]
    fn usage_add_sums_every_field_and_saturates() {
        let mut total = Usage {
            cpu_cycles_foreground: 1,
            cpu_cycles_background: 2,
            bytes_read: 3,
            bytes_written: 4,
            net_sent: 5,
            net_received: 6,
            energy: 7,
            energy_on_battery: 8,
        };
        total.add(&total.clone());
        assert_eq!(total.cpu_cycles(), 6);
        assert_eq!((total.bytes_read, total.bytes_written), (6, 8));
        assert_eq!((total.net_sent, total.net_received), (10, 12));
        assert_eq!((total.energy, total.energy_on_battery), (14, 16));
        total.add(&Usage {
            energy: u64::MAX,
            ..Usage::default()
        });
        assert_eq!(total.energy, u64::MAX);
    }

    #[test]
    fn on_battery_share_is_none_without_energy() {
        assert_eq!(Usage::default().on_battery_share(), None);
        assert_eq!(usage(200, 50).on_battery_share(), Some(0.25));
        assert_eq!(usage(200, 200).on_battery_share(), Some(1.0));
    }

    #[test]
    fn aggregate_sums_per_app_inside_the_range_only() {
        let buckets = vec![
            bucket("a.exe", "2026-11-03T09:00:00Z", usage(10, 10)),
            bucket("a.exe", "2026-11-03T10:00:00Z", usage(20, 0)),
            bucket("b.exe", "2026-11-03T10:00:00Z", usage(100, 100)),
            bucket("a.exe", "2026-11-03T11:00:00Z", usage(5, 5)),
        ];
        // [10:00, 11:00): the 09:00 and 11:00 buckets are outside, the end is exclusive.
        let totals = aggregate(
            &buckets,
            ts("2026-11-03T10:00:00Z"),
            ts("2026-11-03T11:00:00Z"),
        );
        assert_eq!(totals.len(), 2);
        assert_eq!(totals[0].app, "b.exe");
        assert_eq!(totals[0].usage.energy, 100);
        assert_eq!(totals[1].app, "a.exe");
        assert_eq!((totals[1].hours, totals[1].usage.energy), (1, 20));

        let all = aggregate(
            &buckets,
            ts("2026-11-03T00:00:00Z"),
            ts("2026-11-04T00:00:00Z"),
        );
        let a = all.iter().find(|t| t.app == "a.exe").unwrap();
        assert_eq!(
            (a.hours, a.usage.energy, a.usage.energy_on_battery),
            (3, 35, 15)
        );
    }

    #[test]
    fn aggregate_keeps_users_apart_and_orders_ties_by_name() {
        let mut other_user = bucket("a.exe", "2026-11-03T10:00:00Z", usage(7, 0));
        other_user.user = Some(AccountKind::System);
        let buckets = vec![
            bucket("z.exe", "2026-11-03T10:00:00Z", usage(7, 0)),
            other_user,
            bucket("a.exe", "2026-11-03T10:00:00Z", usage(7, 0)),
        ];
        let totals = aggregate(
            &buckets,
            ts("2026-11-03T00:00:00Z"),
            ts("2026-11-04T00:00:00Z"),
        );
        let order: Vec<_> = totals.iter().map(|t| (t.app.as_str(), t.user)).collect();
        assert_eq!(
            order,
            [
                ("a.exe", Some(AccountKind::User)),
                ("a.exe", Some(AccountKind::System)),
                ("z.exe", Some(AccountKind::User))
            ]
        );
        assert!(aggregate(&[], ts("2026-11-03T00:00:00Z"), ts("2026-11-04T00:00:00Z")).is_empty());
    }

    #[test]
    fn accumulator_buckets_by_hour_app_and_user_and_respects_the_window() {
        let mut acc = Accumulator::new(ts("2026-11-03T10:00:00Z"), ts("2026-11-03T12:00:00Z"));
        acc.add(ts("2026-11-03T09:59:59Z"), 1, 9, &usage(1, 0)); // before
        acc.add(ts("2026-11-03T10:05:00Z"), 1, 9, &usage(2, 0));
        acc.add(ts("2026-11-03T10:55:00Z"), 1, 9, &usage(3, 3)); // same bucket
        acc.add(ts("2026-11-03T11:00:00Z"), 1, 9, &usage(4, 0));
        acc.add(ts("2026-11-03T11:00:00Z"), 2, 9, &usage(5, 0));
        acc.add(ts("2026-11-03T12:00:00Z"), 1, 9, &usage(6, 0)); // end is exclusive

        let mut names = IdMap::default();
        names.insert(1, IdName::Text("one.exe".into()));
        names.insert(9, IdName::Sid("S-1-5-18".into()));
        let usage = acc.finish(&names);
        let flat: Vec<_> = usage
            .iter()
            .map(|u| (u.hour.to_string(), u.app.as_str(), u.usage.energy))
            .collect();
        assert_eq!(
            flat,
            [
                ("2026-11-03T10:00:00Z".to_string(), "one.exe", 5),
                ("2026-11-03T11:00:00Z".to_string(), "#2", 5),
                ("2026-11-03T11:00:00Z".to_string(), "one.exe", 4),
            ]
        );
        assert_eq!(usage[0].user, Some(AccountKind::System));
        assert_eq!(usage[0].usage.energy_on_battery, 3);
    }

    #[test]
    fn aggregate_keeps_the_first_bucket_when_since_is_mid_hour() {
        let buckets = vec![
            bucket("a.exe", "2026-11-03T10:00:00Z", usage(10, 0)),
            bucket("a.exe", "2026-11-03T11:00:00Z", usage(20, 0)),
            bucket("a.exe", "2026-11-03T12:00:00Z", usage(40, 0)),
        ];
        let energy = |since: &str, until: &str| {
            aggregate(&buckets, ts(since), ts(until))
                .first()
                .map_or(0, |t| t.usage.energy)
        };
        // 10:30 is inside the 10:00 bucket, which holds the readings from 10:30 to 11:00.
        assert_eq!(energy("2026-11-03T10:30:00Z", "2026-11-03T12:00:00Z"), 30);
        assert_eq!(energy("2026-11-03T10:00:00Z", "2026-11-03T12:00:00Z"), 30);
        assert_eq!(energy("2026-11-03T10:59:59Z", "2026-11-03T11:00:00Z"), 10);
        // A bucket that starts at `until` is out; one that starts before it is in.
        assert_eq!(energy("2026-11-03T10:00:00Z", "2026-11-03T11:30:00Z"), 30);
        assert_eq!(energy("2026-11-03T11:00:00Z", "2026-11-03T11:00:00Z"), 0);
    }

    #[test]
    fn accounts_are_kinds_not_sids() {
        for (sid, kind) in [
            ("S-1-5-21-1111-2222-3333-1001", AccountKind::User),
            ("S-1-12-1-1-2-3-4", AccountKind::User),
            ("S-1-5-18", AccountKind::System),
            ("S-1-5-19", AccountKind::System),
            ("S-1-5-20", AccountKind::System),
            ("S-1-5-80-1-2-3-4-5", AccountKind::System),
            ("S-1-5-90-0-1", AccountKind::System),
            ("S-1-5-96-0-2", AccountKind::System),
        ] {
            assert_eq!(AccountKind::from_sid(sid), kind, "{sid}");
        }
        assert_eq!(AccountKind::User.to_string(), "user");
        assert_eq!(AccountKind::System.to_string(), "system");
    }

    #[test]
    fn two_people_share_one_bucket_and_no_sid_survives() {
        let mut names = IdMap::default();
        names.insert(1, IdName::Text("app.exe".into()));
        names.insert(8, IdName::Sid("S-1-5-21-1-2-3-1001".into()));
        names.insert(9, IdName::Sid("S-1-5-21-1-2-3-1002".into()));
        names.insert(10, IdName::Sid("S-1-5-18".into()));
        // An app id that holds a SID is not shown either.
        names.insert(2, IdName::Sid("S-1-5-21-1-2-3-1001".into()));
        let mut acc = Accumulator::new(ts("2026-01-01T00:00:00Z"), ts("2027-01-01T00:00:00Z"));
        let at = ts("2026-06-01T10:10:00Z");
        acc.add(at, 1, 8, &usage(5, 0));
        acc.add(at, 1, 9, &usage(7, 0));
        acc.add(at, 1, 10, &usage(100, 0));
        acc.add(at, 2, 8, &usage(1, 0));
        let usage = acc.finish(&names);
        let flat: Vec<_> = usage
            .iter()
            .map(|u| (u.app.as_str(), u.user, u.usage.energy))
            .collect();
        assert_eq!(
            flat,
            [
                ("#2", Some(AccountKind::User), 1),
                ("app.exe", Some(AccountKind::User), 12),
                ("app.exe", Some(AccountKind::System), 100),
            ]
        );
    }

    #[test]
    fn profile_folders_in_app_names_are_collapsed() {
        let mut names = IdMap::default();
        names.insert(
            1,
            IdName::Text(r"\Device\HarddiskVolume3\Users\alice\AppData\Local\app.exe".into()),
        );
        names.insert(
            2,
            IdName::Text(r"\Device\HarddiskVolume3\Program Files\app\app.exe".into()),
        );
        let mut acc = Accumulator::new(ts("2026-01-01T00:00:00Z"), ts("2027-01-01T00:00:00Z"));
        acc.add(ts("2026-06-01T10:10:00Z"), 1, 0, &usage(1, 0));
        acc.add(ts("2026-06-01T10:10:00Z"), 2, 0, &usage(1, 0));
        let apps: Vec<_> = acc.finish(&names).into_iter().map(|u| u.app).collect();
        assert_eq!(
            apps,
            [
                r"%USERPROFILE%\AppData\Local\app.exe",
                r"\Device\HarddiskVolume3\Program Files\app\app.exe"
            ]
        );
    }

    #[test]
    fn unmapped_and_empty_ids_degrade_to_a_placeholder_not_a_panic() {
        let mut names = IdMap::default();
        names.insert(1, IdName::Opaque(String::new()));
        let mut acc = Accumulator::new(ts("2026-01-01T00:00:00Z"), ts("2027-01-01T00:00:00Z"));
        acc.add(ts("2026-06-01T00:10:00Z"), 1, 77, &usage(1, 0));
        let usage = acc.finish(&names);
        assert_eq!(usage[0].app, "#1");
        assert_eq!(usage[0].user, None);
    }
}
