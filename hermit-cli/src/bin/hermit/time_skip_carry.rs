/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Carry recorded jumps of global time into the trial schedules that analyze
//! and bisect splice from recorded ones.
//!
//! A record lists the jumps its run made (`PreemptionRecord::time_skips`),
//! each at a position in its event stream, and a replay of the record makes
//! exactly those jumps. A trial schedule that analyze or bisect builds from a
//! recorded schedule's events carries none of them by itself, so its replay
//! would make no jump where the recording did and diverge there. This module
//! remembers every recorded schedule, and gives a trial
//! schedule the jumps of the one recording whose events it repeats furthest:
//! one recording's history, never a mix of several, which could disagree.
//!
//! Only a trial whose events are a prefix of that recording's, one that lists
//! its jumps, gets a list, and that recording's format with it. A trial that
//! goes on past where its events and the recording's part (a bisection's
//! splice, an edited or continued schedule) gets none, and is written in a
//! format that lists no jumps, so its replay makes them as a replay of an
//! older record does (`TimeSkipMode::Legacy`). No recording lists the jumps of
//! its events past that point, and a replay that makes only listed jumps makes
//! none there, not even where a run would compute one: a FIFO open that finds
//! nothing else can run, with a timer pending, moves global time to that timer
//! in a legacy replay and stays where it is in a driven one. The trial keeps
//! its recordings' charge of replayed switch-ins, a field of its own
//! (`TimeSkipSources::trial_charges`), whatever format it is written in.

use std::hash::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::Mutex;

use detcore::preemptions::PreemptionRecord;
use detcore::preemptions::ReservedInputMetadata;
use detcore::preemptions::TimeSkip;
use detcore::types::SchedEvent;
use detcore_model::pid::GuestIds;

/// Every recorded schedule seen so far: the hash of each prefix of its events,
/// and its jumps in stream order, none for a schedule that made none.
#[derive(Debug, Default)]
pub struct TimeSkipSources {
    sources: Vec<Source>,
    /// Whether every recording remembered charged replayed switch-ins
    /// (`PreemptionRecord::charges_replayed_switch_ins`), once one is
    /// (`trial_charges`).
    all_charged: Option<bool>,
}

#[derive(Debug, PartialEq)]
struct Source {
    /// Entry `i` hashes the recording's first `i` events (`prefix_hashes`).
    prefix_hashes: Vec<u64>,
    skips: Vec<TimeSkip>,
    /// The recording's format (`None` for format 1): whether it lists every
    /// jump of its run, and the format a trial that repeats its prefix takes.
    format: Option<u32>,
    guest_ids: GuestIds,
    reserved_input: ReservedInputMetadata,
}

/// One [`TimeSkipSources`] that every copy of the analyze options shares.
pub type SharedTimeSkipSources = Arc<Mutex<TimeSkipSources>>;

/// The hash of each prefix of `events`, from the empty one on: entry `i`
/// covers `events[..i]`. An event's timestamp is left out, because analyze and
/// bisect drop timestamps from the schedules they search.
fn prefix_hashes(events: &[SchedEvent]) -> Vec<u64> {
    let mut hash = 0u64;
    std::iter::once(hash)
        .chain(events.iter().map(move |event| {
            let mut hasher = DefaultHasher::new();
            hash.hash(&mut hasher);
            (
                event.dettid,
                event.op,
                event.count,
                event.start_rip,
                event.end_rip,
            )
                .hash(&mut hasher);
            hash = hasher.finish();
            hash
        }))
        .collect()
}

/// How many leading events two schedules share, from their prefix hashes:
/// the hash of a prefix covers every event before it, so prefixes match up to
/// some length and differ from there on.
fn shared_events(left: &[u64], right: &[u64]) -> usize {
    let shared = left.len().min(right.len());
    // The empty prefixes always match; find the last matching entry.
    let (mut matching, mut differing) = (0, shared);
    while matching + 1 < differing {
        let middle = (matching + differing) / 2;
        if left[middle] == right[middle] {
            matching = middle;
        } else {
            differing = middle;
        }
    }
    if shared > 0 && left[shared - 1] == right[shared - 1] {
        shared - 1
    } else {
        matching
    }
}

impl TimeSkipSources {
    /// Remember `record`. One that made no jump counts as much as one that
    /// did: a trial that repeats it furthest makes no jump either.
    pub fn remember(&mut self, record: &PreemptionRecord) {
        self.all_charged =
            Some(self.all_charged.unwrap_or(true) && record.charges_replayed_switch_ins());
        let source = Source {
            prefix_hashes: prefix_hashes(record.schedevents()),
            skips: record.time_skips().unwrap_or_default().to_vec(),
            format: record.format_version(),
            guest_ids: record.guest_ids().unwrap_or_default(),
            reserved_input: record.reserved_input().clone(),
        };
        if !self.sources.contains(&source) {
            self.sources.push(source);
        }
    }

    /// Whether a trial schedule built from the remembered recordings charges
    /// replayed switch-ins (`PreemptionRecord::with_switch_ins_charged`): when
    /// every one of them did, since its events follow those recordings' rules,
    /// or, when none was read, as a run that follows no record does. Analyze
    /// and bisect refuse, before any trial, recordings that charged
    /// differently
    /// (`AnalyzeOpts::refuse_recordings_under_another_switch_in_charge`), so
    /// this is every remembered recording's charge, the one a trial's jumps
    /// come from included, whatever format the trial is written in.
    pub fn trial_charges(&self) -> bool {
        self.all_charged.unwrap_or(true)
    }

    /// Admit all Chosen source metadata before a trial or endpoint shortcut.
    /// Non-Chosen metadata is opaque and adds no new source-admission rule.
    pub fn validate_reserved_inputs(&self) -> anyhow::Result<()> {
        if !self
            .sources
            .iter()
            .any(|source| matches!(source.guest_ids, GuestIds::Chosen { .. }))
        {
            return Ok(());
        }
        if let Some(first) = self.sources.first() {
            for source in &self.sources {
                if let Some(refusal) = detcore::preemptions::guest_ids_mismatch(
                    "transformation source",
                    first.guest_ids,
                    source.guest_ids,
                ) {
                    anyhow::bail!("{refusal}");
                }
                first
                    .reserved_input
                    .require_same_for_chosen(&source.reserved_input)?;
            }
        }
        Ok(())
    }

    /// Carry the same source's numbering/provenance as its selected prefix.
    /// This copies a producer declaration; it never creates one from defaults.
    pub fn trial_identity_metadata(
        &self,
        events: &[SchedEvent],
    ) -> anyhow::Result<Option<(GuestIds, ReservedInputMetadata)>> {
        self.validate_reserved_inputs()?;
        Ok(self
            .selected(events)
            .map(|(_, source)| (source.guest_ids, source.reserved_input.clone())))
    }

    fn selected(&self, events: &[SchedEvent]) -> Option<(usize, &Source)> {
        let hashes = prefix_hashes(events);
        let mut best: Option<(usize, &Source)> = None;
        for source in &self.sources {
            let shared = shared_events(&source.prefix_hashes, &hashes);
            if best.is_none_or(|(furthest, _)| shared > furthest) {
                best = Some((shared, source));
            }
        }
        best
    }

    /// The jumps a replay of `events` must make, when a recording lists them
    /// all, with that recording's format: those of the remembered recording
    /// whose events `events` repeats furthest, in stream order, when `events`
    /// is a prefix of that recording's events and the recording lists its
    /// jumps (format 2 or later). The run that recorded a jump was in the
    /// state those events lead to when it jumped, so a replay of the same
    /// events is too. One recording's jumps, validated when it was read, are
    /// never mixed with another's, which could disagree. Ties go to the
    /// recording remembered first.
    ///
    /// `None` when `events` goes on past that recording's events, when the
    /// recording lists no jumps (format 1), or when none was remembered: no
    /// recording lists the jumps of the rest, so the trial must not claim to
    /// list them (see the module's doc).
    pub fn carried(&self, events: &[SchedEvent]) -> Option<(Vec<TimeSkip>, Option<u32>)> {
        let (shared, source) = self.selected(events)?;
        let lists = source
            .format
            .is_some_and(|format| format >= detcore::preemptions::TIME_SKIPS_FORMAT);
        if shared < events.len() || !lists {
            return None;
        }
        let skips = source
            .skips
            .iter()
            .take_while(|skip| usize::try_from(skip.event).is_ok_and(|event| event <= shared))
            .copied()
            .collect();
        Some((skips, source.format))
    }
}

#[cfg(test)]
mod tests {
    use detcore::preemptions::TimeSkipReason;
    use detcore::types::DetTid;
    use detcore::types::LogicalTime;
    use detcore::types::SyscallPhase;
    use reverie::syscalls::Sysno;

    use super::*;

    fn events(tids: &[i32]) -> Vec<SchedEvent> {
        tids.iter()
            .map(|&tid| {
                SchedEvent::syscall(DetTid::from_raw(tid), Sysno::poll, SyscallPhase::Posthook)
            })
            .collect()
    }

    fn skip(event: u64, target: u64) -> TimeSkip {
        TimeSkip {
            event,
            target: LogicalTime::from_nanos(target),
            reason: TimeSkipReason::IdleGuestPollers,
        }
    }

    /// The jumps `carried` gives, without the format.
    fn jumps(carried: Option<(Vec<TimeSkip>, Option<u32>)>) -> Option<Vec<TimeSkip>> {
        carried.map(|(skips, _)| skips)
    }

    /// A trial whose events are a prefix of a recorded schedule's carries the
    /// jumps that prefix contains, at their positions, in the recording's
    /// format. Test adapted: a trial spliced after event 3 used to carry the
    /// prefix's jump and claim a complete list; it goes on past the
    /// recording's events, which list none of its jumps there, and a driven
    /// replay would make no jump where a run computes one (detcore's
    /// `past_its_list_a_driven_replay_makes_no_fifo_open_jump_a_legacy_one_makes`),
    /// so it now carries no list.
    #[test]
    fn a_spliced_prefix_carries_the_jumps_inside_it() {
        let recorded = events(&[3, 3, 5, 3, 5, 5]);
        let record = PreemptionRecord::from_sched_events(recorded.clone())
            .with_time_skips(vec![skip(2, 1_000), skip(5, 2_000)]);
        let mut sources = TimeSkipSources::default();
        sources.remember(&record);

        // The whole schedule carries both.
        assert_eq!(
            sources.carried(&recorded),
            Some((
                vec![skip(2, 1_000), skip(5, 2_000)],
                Some(detcore::preemptions::TIME_SKIPS_FORMAT)
            ))
        );
        // A prefix of three events carries the jump inside it.
        assert_eq!(
            jumps(sources.carried(&recorded[..3])),
            Some(vec![skip(2, 1_000)])
        );
        // Spliced after event 3: no list.
        let mut spliced = recorded[..3].to_vec();
        spliced.extend(events(&[5, 3, 3]));
        assert_eq!(sources.carried(&spliced), None);
        // A jump exactly at the prefix's end is inside it.
        assert_eq!(
            jumps(sources.carried(&recorded[..2])),
            Some(vec![skip(2, 1_000)])
        );
        // A trial that differs from the first event on carries no list.
        assert_eq!(sources.carried(&events(&[5, 3, 5])), None);
    }

    /// A schedule that goes on past every recording's events carries no list:
    /// one continued past a recording's end, and any schedule when no
    /// recording was remembered.
    #[test]
    fn a_schedule_past_every_recording_carries_no_list() {
        let recorded = events(&[3, 5]);
        let mut sources = TimeSkipSources::default();
        assert_eq!(sources.carried(&recorded), None);
        sources.remember(
            &PreemptionRecord::from_sched_events(recorded.clone())
                .with_time_skips(vec![skip(1, 1_000)]),
        );
        assert_eq!(
            jumps(sources.carried(&recorded)),
            Some(vec![skip(1, 1_000)])
        );
        let mut continued = recorded;
        continued.extend(events(&[3]));
        assert_eq!(sources.carried(&continued), None);
    }

    /// A prefix trial takes the format of the recording it repeats, whose list
    /// it carries; one of a format-1 recording, which lists no jumps, carries
    /// no list (main used one recording's missing list as a complete, empty
    /// one).
    #[test]
    fn a_prefix_trial_takes_its_recordings_format() {
        let current = events(&[3, 5]);
        let second = events(&[4, 5]);
        let legacy = events(&[6, 5]);
        let mut sources = TimeSkipSources::default();
        sources.remember(
            &PreemptionRecord::from_sched_events(current.clone())
                .with_current_format()
                .with_time_skips(vec![skip(1, 1_000)]),
        );
        sources.remember(&PreemptionRecord::from_sched_events(second.clone()).with_format(Some(2)));
        sources.remember(&PreemptionRecord::from_sched_events(legacy.clone()));
        assert_eq!(
            sources.carried(&current),
            Some((
                vec![skip(1, 1_000)],
                Some(detcore::preemptions::PREEMPTION_RECORD_FORMAT)
            ))
        );
        assert_eq!(sources.carried(&second[..1]), Some((Vec::new(), Some(2))));
        assert_eq!(sources.carried(&legacy), None);
    }

    /// Timestamps, which analyze and bisect strip, do not stop a prefix from
    /// matching.
    #[test]
    fn a_prefix_matches_without_its_timestamps() {
        let mut recorded = events(&[3, 5, 3]);
        for (index, event) in recorded.iter_mut().enumerate() {
            event.end_time = Some(LogicalTime::from_nanos(index as u64 + 1));
        }
        let record = PreemptionRecord::from_sched_events(recorded.clone())
            .with_time_skips(vec![skip(1, 1_000)]);
        let mut sources = TimeSkipSources::default();
        sources.remember(&record);
        let mut stripped = recorded;
        for event in &mut stripped {
            event.end_time = None;
        }
        assert_eq!(
            jumps(sources.carried(&stripped)),
            Some(vec![skip(1, 1_000)])
        );
    }

    /// A record without jumps, and a jump past the end of its events, add
    /// nothing.
    #[test]
    fn unplaceable_jumps_are_left_out() {
        let recorded = events(&[3, 5]);
        let mut sources = TimeSkipSources::default();
        sources.remember(
            &PreemptionRecord::from_sched_events(recorded.clone())
                .with_time_skips(vec![skip(9, 1_000)]),
        );
        assert_eq!(jumps(sources.carried(&recorded)), Some(Vec::new()));
    }

    /// Two recordings that share their first events but jumped differently
    /// inside them are never mixed: a trial carries the jumps of the one whose
    /// events it repeats furthest, and the result validates (Codex review,
    /// finding 5).
    #[test]
    fn recordings_that_disagree_are_not_mixed() {
        let first = events(&[3, 5, 7]);
        let second = events(&[3, 5, 9]);
        let mut sources = TimeSkipSources::default();
        sources.remember(
            &PreemptionRecord::from_sched_events(first.clone())
                .with_time_skips(vec![skip(1, 2_000)]),
        );
        sources.remember(
            &PreemptionRecord::from_sched_events(second.clone())
                .with_time_skips(vec![skip(2, 1_000)]),
        );
        let carried = jumps(sources.carried(&first)).unwrap();
        assert_eq!(carried, vec![skip(1, 2_000)]);
        assert!(
            PreemptionRecord::from_sched_events(first)
                .with_time_skips(carried)
                .validate()
                .is_ok()
        );
        assert_eq!(jumps(sources.carried(&second)), Some(vec![skip(2, 1_000)]));
    }

    /// A recording that made no jump is a source like any other: a trial that
    /// repeats it further than a recording that jumped makes no jump (Codex
    /// review, round 2).
    #[test]
    fn a_closer_recording_without_jumps_wins() {
        let jumped = events(&[3, 5, 7]);
        let plain = events(&[3, 5, 9]);
        let mut sources = TimeSkipSources::default();
        sources.remember(
            &PreemptionRecord::from_sched_events(jumped.clone())
                .with_time_skips(vec![skip(1, 2_000)]),
        );
        sources.remember(&PreemptionRecord::from_sched_events(plain.clone()).with_format(Some(2)));
        assert_eq!(jumps(sources.carried(&plain)), Some(Vec::new()));
        assert_eq!(jumps(sources.carried(&jumped)), Some(vec![skip(1, 2_000)]));
    }

    /// A trial charges replayed switch-ins when every recording read did, and
    /// when none was read, as a run that follows no record does; the format
    /// says nothing about it.
    #[test]
    fn a_trial_charges_only_when_every_recording_read_did() {
        let mut sources = TimeSkipSources::default();
        assert!(sources.trial_charges());
        sources.remember(
            &PreemptionRecord::from_sched_events(events(&[3]))
                .with_current_format()
                .with_switch_ins_charged(true),
        );
        assert!(sources.trial_charges());
        sources.remember(
            &PreemptionRecord::from_sched_events(events(&[4])).with_switch_ins_charged(true),
        );
        assert!(sources.trial_charges());
        sources.remember(&PreemptionRecord::from_sched_events(events(&[5])).with_current_format());
        assert!(!sources.trial_charges());
    }

    fn with_metadata(record: PreemptionRecord, metadata: serde_json::Value) -> PreemptionRecord {
        let mut value = serde_json::to_value(record).unwrap();
        value["reserved_input"] = metadata;
        serde_json::from_value(value).unwrap()
    }

    /// The chosen prefix selects one source's opaque metadata and jumps
    /// together. A non-Chosen future value is not a new admission failure.
    #[test]
    fn metadata_follows_the_same_source_as_its_time_skips() {
        let first = with_metadata(
            PreemptionRecord::from_sched_events(events(&[3, 5, 7]))
                .with_current_format()
                .with_time_skips(vec![skip(1, 1000)]),
            serde_json::json!({"future": [null, 17]}),
        );
        let second = with_metadata(
            PreemptionRecord::from_sched_events(events(&[3, 5, 9]))
                .with_current_format()
                .with_time_skips(vec![skip(2, 2000)]),
            serde_json::Value::Null,
        );
        let mut sources = TimeSkipSources::default();
        sources.remember(&first);
        sources.remember(&second);
        for source in [&first, &second] {
            let (ids, metadata) = sources
                .trial_identity_metadata(source.schedevents())
                .unwrap()
                .unwrap();
            assert_eq!(ids, GuestIds::Namespace);
            assert_eq!(&metadata, source.reserved_input());
            assert_eq!(
                sources.carried(source.schedevents()),
                Some((source.time_skips().unwrap().to_vec(), Some(3)))
            );
        }
    }

    /// Even when the output exactly matches a qualified endpoint, every
    /// Chosen source must have the same recognized producer declaration.
    #[test]
    fn chosen_sources_are_admitted_before_an_identity_trial() {
        let metadata = serde_json::json!({
            "contract": "sealed-private-input-v1", "base": "0x71010000",
            "abi": "x86_64", "page_bytes": 4096
        });
        let ids = GuestIds::Chosen {
            base: 5000,
            refuse_host_ids: true,
        };
        let record = PreemptionRecord::from_sched_events(events(&[3, 5, 7]))
            .with_current_format()
            .with_time_skips(vec![skip(1, 1000)])
            .with_guest_ids(ids);
        let qualified = with_metadata(record.clone(), metadata.clone());
        for other in [
            record.clone(),
            with_metadata(record.clone(), serde_json::Value::Null),
            with_metadata(
                record.clone(),
                serde_json::json!({"contract": "future-input"}),
            ),
            with_metadata(
                record,
                serde_json::json!({
                    "contract": "sealed-private-input-v1", "base": "0x71010000",
                    "abi": "aarch64", "page_bytes": 4096
                }),
            ),
        ] {
            for sources_in_order in [[&qualified, &other], [&other, &qualified]] {
                let mut sources = TimeSkipSources::default();
                for source in sources_in_order {
                    sources.remember(source);
                }
                let error = sources
                    .trial_identity_metadata(qualified.schedevents())
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("HERMIT_CHOSEN_JSON_INPUT_PROVENANCE:"),
                    "{error}"
                );
            }
        }
        let mut sources = TimeSkipSources::default();
        sources.remember(&qualified);
        assert_eq!(
            sources
                .trial_identity_metadata(qualified.schedevents())
                .unwrap(),
            Some((ids, qualified.reserved_input().clone()))
        );
        assert_eq!(
            sources.carried(qualified.schedevents()),
            Some((qualified.time_skips().unwrap().to_vec(), Some(3)))
        );
    }
}
