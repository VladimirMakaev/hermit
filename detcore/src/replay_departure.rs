/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A preemption replay's departures from its record: where its thread is found
//! past a recorded slice end without its own timer having overshot
//! (`crate::tool_local::classify_replay_overshoot`), or where a change point
//! would not come after the last one. Counted here, apart
//! from the timer's skid count (`reverie::record_skid_overshoot`), so the run
//! ends in its own policy refusal (`cause=replay-departure`).

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// The marker that starts every report of a departure on stderr.
pub const REPLAY_DEPARTED_MARKER: &str = "HERMIT_REPLAY_DEPARTED";

static COUNT: AtomicU64 = AtomicU64::new(0);

/// Count one departure. Detcore counts its own; public so the CLI's tests can
/// stand in for one.
pub fn record() {
    COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Read and reset the departure count, as `reverie::take_skid_overshoot_count`
/// does the skid count.
pub fn take_count() -> u64 {
    COUNT.swap(0, Ordering::Relaxed)
}
