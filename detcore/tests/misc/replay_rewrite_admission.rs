/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A launch that drives Detcore through Reverie directly, without Hermit's
//! entry points, refuses a replayed record whose exclusive-loop rewrite is
//! not the run's before the guest runs: `Detcore::facility_admission`
//! compares them, as Hermit's `validate_config_replay_inputs` does for its
//! own launches.

use detcore::Config;
use detcore::Detcore;
use detcore::preemptions::PreemptionRecord;
use detcore::preemptions::RecordAdmissionRefusal;
use detcore::preemptions::RewriteExclusives;
use detcore::preemptions::RewriteExclusivesMode;

/// A record of an in-memory rewrite, replayed by a run that rewrites
/// nothing (the case every host can launch), through either replay input.
/// The refusal is the typed admission refusal, returned before global
/// initialization, and the guest never runs.
#[test]
fn a_direct_launch_refuses_a_record_of_another_exclusive_rewrite() {
    let directory = tempfile::tempdir().unwrap();
    let record = directory.path().join("in-memory.json");
    PreemptionRecord::from_sched_events(Vec::new())
        .with_rewrite_exclusives(Some(RewriteExclusives::current(
            RewriteExclusivesMode::Memory,
        )))
        .write_to_disk(&record)
        .unwrap();
    let marker = directory.path().join("guest-ran");
    for from_schedule in [true, false] {
        let config = Config {
            replay_schedule_from: from_schedule.then(|| record.clone()),
            replay_preemptions_from: (!from_schedule).then(|| record.clone()),
            ..Default::default()
        };
        let guest_marker = marker.clone();
        let error = detcore_testutils::test_fn_with_config::<Detcore, _>(
            move || std::fs::write(&guest_marker, b"ran").unwrap(),
            config,
            true,
        )
        .err()
        .unwrap_or_else(|| panic!("the replay was admitted (schedule: {from_schedule})"));
        let reverie::Error::Tool(error) = error else {
            panic!("not the tool's refusal: {error:?}");
        };
        assert!(
            error
                .chain()
                .any(|cause| cause.is::<RecordAdmissionRefusal>()),
            "{error:#}"
        );
        assert!(
            format!("{error:#}").contains("cannot reproduce the run"),
            "{error:#}"
        );
        assert!(
            !marker.exists(),
            "the guest ran (schedule: {from_schedule})"
        );
    }
}
