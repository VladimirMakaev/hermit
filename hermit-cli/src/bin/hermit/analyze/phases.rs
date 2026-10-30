/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A mode for analyzing a hermit run.

use std::cell::Cell;
use std::cmp;
use std::collections::BTreeMap;
use std::fs::File;
use std::num::NonZeroU64;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::bail;
use colored::Colorize;
use detcore::preemptions::PreemptionReader;
use detcore::preemptions::PreemptionRecord;
use detcore::preemptions::boundary_recording::Recording;
use detcore::types::DetTid;
use detcore::types::SchedEvent;
use detcore::util::truncated;
use detcore_model::config::MaybeTimeslice;
use hermit::Error;
use rand::RngExt as _;
use rand::SeedableRng;
use rand_pcg::Pcg64Mcg;
use regex::Regex;
use reverie::PrettyBacktrace;
use reverie::process::ExitStatus;
use reverie::process::Output;

use crate::analyze::budget;
use crate::analyze::budget::Budget;
use crate::analyze::budget::BudgetExpired;
use crate::analyze::budget::BudgetKind;
use crate::analyze::checkpoint::BisectInterval;
use crate::analyze::checkpoint::CHECKPOINT_VERSION;
use crate::analyze::checkpoint::Checkpoint;
use crate::analyze::checkpoint::DecidedEvents;
use crate::analyze::checkpoint::FileIdentity;
use crate::analyze::checkpoint::Identity;
use crate::analyze::checkpoint::IntervalResume;
use crate::analyze::checkpoint::Journal;
use crate::analyze::checkpoint::Phase;
use crate::analyze::checkpoint::PrefixBracket;
use crate::analyze::checkpoint::Progress;
use crate::analyze::consts::*;
use crate::analyze::race_report::TracedReplay;
use crate::analyze::races::RacingAccesses;
use crate::analyze::races::render_racing_accesses;
use crate::analyze::rundata::RunData;
use crate::analyze::rundata::Stop;
use crate::analyze::rundata::TrialEnd;
use crate::analyze::rundata::VirtualBoundStop;
use crate::analyze::rundata::guest_reached_a_refusal;
use crate::analyze::stop;
use crate::analyze::stop::StopSignals;
use crate::analyze::stop::Stopped;
use crate::analyze::types::AnalyzeOpts;
use crate::analyze::types::CONFIRM_BOUND_FACTOR;
use crate::analyze::types::ContinuationTimeslice;
use crate::analyze::types::ExitStatusConstraint;
use crate::analyze::types::PartialReport;
use crate::analyze::types::Report;
use crate::analyze::types::ReportCriticalEvent;
use crate::analyze::types::TrialTimeout;
use crate::analyze::verdict::AlternativeTiming;
use crate::analyze::verdict::AnalyzeFailure;
use crate::analyze::verdict::AnalyzePrecondition;
use crate::analyze::verdict::AnalyzeVerdict;
use crate::analyze::verdict::PreconditionClass;
use crate::analyze::verdict::TimingSetting;
use crate::analyze::verdict::Verdict;
use crate::analyze::workspace::Retention;
use crate::analyze::workspace::Workspace;
use crate::analyze::workspace::note;
use crate::container::RunTimeoutMarker;
use crate::global_opts::GlobalOpts;
use crate::logdiff::LogDiffCLIOpts;
use crate::run::RunOpts;
use crate::schedule_search::Config;
use crate::schedule_search::CriticalSchedule;
use crate::schedule_search::INEXACT_COUNTER_BRANCH_JITTER;
use crate::schedule_search::NoReorderableDistance;
use crate::schedule_search::NoSingleSwap;
use crate::schedule_search::SearchStart;
use crate::schedule_search::TrialOutcome;
use crate::schedule_search::search_for_critical_schedule_observed;

/// Compare only preemptions, not recorded schedules.
fn preempt_files_equal(path1: &Path, path2: &Path) -> bool {
    let mut pr1 = PreemptionReader::new(path1).load_all();
    let mut pr2 = PreemptionReader::new(path2).load_all();
    pr1.preemptions_only();
    pr2.preemptions_only();
    pr1 == pr2
}

fn yellow_msg(msg: &str) {
    eprintln!(":: {}", msg.yellow().bold());
}

/// What stack1 and stack2 of a `--prefix-search` report are, given the
/// thread the target schedule runs at the deciding event (`chosen`) and the
/// one the scheduler runs there without that event (`instead`, `None` when
/// the run without it ended first). Two threads are a pair whose order
/// decides the outcome. One thread is not a pair at all: the scheduler runs
/// it there either way, so stack2 is the thread that runs after its slice
/// without the event (`next`: that event and thread), when one does; else
/// the report says that both are one thread instead of calling the thread a
/// race with itself. `partner`, when stack2 is another thread than those
/// ([`partner_turn`], [`moved_past`]), says which and why.
fn stack_pair_sentences(
    chosen: detcore::types::DetTid,
    instead: Option<detcore::types::DetTid>,
    next: Option<(usize, detcore::types::DetTid)>,
    partner: Option<&Partner>,
) -> String {
    if let Some(Partner {
        side,
        thread,
        event,
        why,
    }) = partner
    {
        let side = side.name();
        return if instead == Some(chosen) {
            format!(
                "The scheduler runs thread {chosen} at that point with or without the event, so \
                 the event does not choose between two threads there. stack1 is thread {chosen} \
                 there; stack2 is thread {thread}, at event #{event} of the continuation {side} \
                 the event: {why}.\nWhat the event can change is how the threads run from \
                 there: look at what thread {chosen} does until then, and at thread {thread}.\n"
            )
        } else {
            let instead = instead.map_or(String::new(), |instead| {
                format!("; without the event the scheduler runs thread {instead} there instead")
            });
            format!(
                "stack1 is thread {chosen}, which the target schedule runs at that \
                 point{instead}. stack2 is thread {thread}, at event #{event} of the \
                 continuation {side} the event: {why}.\nThe outcome depends on which of threads \
                 {chosen} and {thread} runs first: add synchronization that makes the order \
                 irrelevant, or that enforces the passing order.\n"
            )
        };
    }
    if instead == Some(chosen)
        && let Some((index, next)) = next
    {
        format!(
            "The scheduler runs thread {chosen} at that point with or without the event, so \
             the event does not choose between two threads there. stack1 is thread {chosen} \
             there; stack2 is thread {next}, which runs after thread {chosen}'s slice without the \
             event, at event #{index} of that continuation.\nWhat the event can change is how \
             thread {chosen} runs from there: look at what it does before thread {next} runs, \
             and at thread {next}.\n"
        )
    } else if instead == Some(chosen) {
        format!(
            "stack1 and stack2 both belong to thread {chosen}: the scheduler runs it at that \
             point with or without the event, so they are not two threads racing.\nWhat the \
             event can change is how thread {chosen} runs from there, not which thread runs: look \
             at what it does before another thread runs, and at that thread.\n"
        )
    } else {
        "stack1 is the thread the target schedule runs at that point; stack2 is the thread that \
         runs there instead when the scheduler continues without chaos.\nThe outcome depends on \
         which of the two runs first: add synchronization that makes the order irrelevant, or \
         that enforces the passing order.\n"
            .to_owned()
    }
}

/// The baseline run (from `.0`) did not finish: a wall-clock bound ended it,
/// or Hermit refused it, so it recorded no schedule to bisect against.
#[derive(Debug)]
pub struct BaselineUnfinished(&'static str);

impl std::fmt::Display for BaselineUnfinished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the baseline run ({}) did not finish, so it recorded no schedule to bisect against",
            self.0
        )
    }
}

impl std::error::Error for BaselineUnfinished {}

/// `--minimize`'s knock-outs removed every intervention and the replay still
/// meets the target, so there is no baseline schedule to bisect against.
#[derive(Debug)]
pub struct NothingToKnockOut;

impl std::fmt::Display for NothingToKnockOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "--minimize knocked out every intervention and the run still meets the target, so \
             there is no baseline schedule to bisect against"
        )
    }
}

impl std::error::Error for NothingToKnockOut {}

/// `--minimize`'s baseline: knock interventions out of `record`, the latest
/// first, until `replay(try, knocked_out)` misses the target and returns the
/// run that did; [`NothingToKnockOut`] when none is left. Each knock-out
/// starts from the record the previous one replayed, not from what that run
/// recorded: a run's recording also holds the priority changes chaos makes
/// after the replayed record ends, which every run makes again, so knocking
/// those out never ends.
fn knock_out_until_missed<T>(
    mut record: PreemptionRecord,
    mut replay: impl FnMut(usize, &PreemptionRecord) -> anyhow::Result<Option<T>>,
) -> anyhow::Result<T> {
    for attempt in 1.. {
        let Some(knocked_out) = knock_out_latest(&record) else {
            break;
        };
        if let Some(missed) = replay(attempt, &knocked_out)? {
            return Ok(missed);
        }
        record = knocked_out;
    }
    Err(NothingToKnockOut.into())
}

/// `record` with its latest intervention knocked out, for `--minimize`'s
/// baseline; `None` when it has none left. Threads at the default priority
/// with no change are dropped first: replay gives a thread the record does
/// not name that same priority, and a knock-out that removes a whole thread
/// (once no priority change is left) must not pick one of them, which would
/// change nothing.
fn knock_out_latest(record: &PreemptionRecord) -> Option<PreemptionRecord> {
    let pruned = record.without_default_threads();
    let knocked_out = pruned.with_latest_preempt_removed();
    (knocked_out != pruned).then_some(knocked_out)
}

/// What a partial report says about `--prefix-search`'s `bracket`. Short
/// prefixes miss the target and long ones meet it, so the deciding event
/// lies between the longest prefix known to miss and the shortest known to
/// meet.
fn describe_bracket(bracket: &PrefixBracket) -> String {
    let mut said = match (bracket.misses, bracket.meets) {
        (Some(misses), Some(meets)) => format!(
            "The prefix search's bracket, continuing without chaos {}: replaying the first \
             {misses} of the target schedule's {} events misses the target ({}), and replaying \
             the first {meets} meets it ({}). The deciding event is one of events #{misses} to \
             #{} ({} events), assuming, as the search does, that the outcome changes once along \
             the schedule.\n",
            bracket.continuation,
            bracket.events,
            bracket.misses_run.as_deref().unwrap_or("a trial"),
            bracket.meets_run.as_deref().unwrap_or("a trial"),
            meets - 1,
            meets - misses,
        ),
        (None, Some(meets)) => format!(
            "The prefix search had found that replaying the first {meets} of the target \
             schedule's {} events meets the target ({}), continuing without chaos {}, but no \
             shorter prefix whose trial finished and missed it yet: the deciding event is one \
             of events #0 to #{}.\n",
            bracket.events,
            bracket.meets_run.as_deref().unwrap_or("a trial"),
            bracket.continuation,
            meets - 1,
        ),
        (misses, None) => format!(
            "The prefix search had not yet found a prefix of the target schedule's {} events \
             whose replay meets the target, continuing without chaos {}{}.\n",
            bracket.events,
            bracket.continuation,
            misses.map_or_else(String::new, |misses| format!(
                "; replaying the first {misses} misses it ({})",
                bracket.misses_run.as_deref().unwrap_or("a trial")
            )),
        ),
    };
    if !bracket.unfinished.is_empty() {
        said.push_str(&format!(
            "The trials of the prefixes of {} events in between did not finish (a bound or a \
             refusal stopped them); they are not outcomes.\n",
            bracket
                .unfinished
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    said
}

/// The command line that continues this analysis in `workspace`: this
/// invocation's own, with `--resume=WORKSPACE` in place of any earlier one.
fn resume_command(workspace: &Path) -> String {
    let mut args: Vec<String> = std::env::args_os()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--resume" {
            args.drain(index..(index + 2).min(args.len()));
        } else if args[index].starts_with("--resume=") {
            args.remove(index);
        } else {
            index += 1;
        }
    }
    let resume = format!("--resume={}", workspace.display());
    match args.iter().position(|arg| arg == "analyze") {
        Some(at) => args.insert(at + 1, resume),
        None => args.push(resume),
    }
    shell_words::join(&args)
}

/// The guest program `program` on the host: as it is when it names a path,
/// else found on `PATH`. `None` when it is not there.
fn find_program(program: &Path) -> Option<PathBuf> {
    if program.components().count() > 1 {
        return program.is_file().then(|| program.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

/// The default search's interval, kept in the workspace as it narrows: the
/// side that changed is written again, and the progress (`checkpoint`)
/// names both.
struct IntervalFiles {
    paths: [PathBuf; 2],
    /// The digest of the schedule each file holds (`events_digest`).
    written: [Option<String>; 2],
}

/// The sha256 that `IntervalResume` keeps of the schedules `lists`: of each
/// one's length and events as `std::hash::Hash` writes them, streamed
/// rather than collected, since a schedule can hold millions of events.
fn events_digest(lists: &[&[SchedEvent]]) -> String {
    /// Collects what `Hash` writes.
    struct Sink<'a>(&'a mut Vec<u8>);
    impl std::hash::Hasher for Sink<'_> {
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
        fn finish(&self) -> u64 {
            0
        }
    }
    struct Stream<'a> {
        lists: std::slice::Iter<'a, &'a [SchedEvent]>,
        events: std::slice::Iter<'a, SchedEvent>,
        buf: Vec<u8>,
        at: usize,
    }
    impl std::io::Read for Stream<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            use std::hash::Hash as _;
            if self.at == self.buf.len() {
                self.buf.clear();
                self.at = 0;
                while self.buf.len() < 1 << 16 {
                    match self.events.next() {
                        Some(event) => event.hash(&mut Sink(&mut self.buf)),
                        None => match self.lists.next() {
                            Some(list) => {
                                list.len().hash(&mut Sink(&mut self.buf));
                                self.events = list.iter();
                            }
                            None => break,
                        },
                    }
                }
            }
            let n = out.len().min(self.buf.len() - self.at);
            out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
    }
    let stream = Stream {
        lists: lists.iter(),
        events: [].iter(),
        buf: Vec::new(),
        at: 0,
    };
    detcore::Digest::digest_reader(stream)
        .expect("reading from memory does not fail")
        .to_string()
}

/// Where the default search stands, besides its interval: what
/// `IntervalResume` keeps.
#[derive(Clone)]
struct SearchState {
    endpoints: String,
    event_level: bool,
    trials: usize,
    unfinished: usize,
    refused: usize,
}

impl IntervalFiles {
    fn new(workspace: &Path) -> Self {
        Self {
            paths: [
                workspace.join("interval_passing").with_extension(SCHED_EXT),
                workspace.join("interval_failing").with_extension(SCHED_EXT),
            ],
            written: [None, None],
        }
    }

    /// Record the interval `passing`, `failing`, at the start of `pass`
    /// with its edit and swap `distances` and the search's `state`, or
    /// before the first pass. Each file is replaced whole (written aside,
    /// then renamed), and the progress names the interval only after both.
    fn record(
        &mut self,
        opts: &AnalyzeOpts,
        pass: Option<usize>,
        [passing, failing]: [&[SchedEvent]; 2],
        distances: Option<(usize, usize)>,
        state: Option<SearchState>,
    ) {
        let mut hashes = [String::new(), String::new()];
        let mut whole = true;
        for (slot, events) in [passing, failing].into_iter().enumerate() {
            let hash = events_digest(&[events]);
            hashes[slot] = hash.clone();
            if self.written[slot].as_ref() == Some(&hash) {
                continue;
            }
            let path = &self.paths[slot];
            let aside = path.with_extension("partial");
            let written = opts
                .write_trial_schedule_from(events.to_vec(), &[], &aside)
                .and_then(|()| Ok(std::fs::rename(&aside, path)?));
            match written {
                Ok(()) => self.written[slot] = Some(hash),
                Err(error) => {
                    whole = false;
                    self.written[slot] = None;
                    note(&format!(
                        ":: cannot write the search's interval to {}: {error:#}",
                        path.display()
                    ))
                }
            }
        }
        let common_prefix = passing
            .iter()
            .zip(failing)
            .take_while(|(first, second)| first == second)
            .count();
        opts.progress.interval(BisectInterval {
            pass,
            edit_distance: distances.map(|(edit, _)| edit),
            swap_distance: distances.map(|(_, swap)| swap),
            passing: self.paths[0].clone(),
            passing_events: passing.len(),
            failing: self.paths[1].clone(),
            failing_events: failing.len(),
            common_prefix,
            passing_event: passing.get(common_prefix).map(ToString::to_string),
            failing_event: failing.get(common_prefix).map(ToString::to_string),
            resume: state.filter(|_| whole).map(|state| IntervalResume {
                endpoints: state.endpoints,
                passing_hash: hashes[0].clone(),
                failing_hash: hashes[1].clone(),
                event_level: state.event_level,
                trials: state.trials,
                unfinished: state.unfinished,
                refused: state.refused,
            }),
        });
    }
}

/// How the last trial of each prefix ended, per continuation, and the
/// wall-clock bound it ran under, in seconds.
type Ends = BTreeMap<(usize, MaybeTimeslice), (TrialEnd, Option<u64>)>;

/// `--prefix-search`'s bracket at `continuation` over a schedule of
/// `events` events, from each prefix's last trial (`ends`) and the run that
/// was (`runs`): only trials that finished bound it.
fn prefix_bracket(
    ends: &Ends,
    runs: &BTreeMap<(usize, MaybeTimeslice), String>,
    continuation: MaybeTimeslice,
    events: usize,
) -> PrefixBracket {
    let at = |end: TrialEnd| {
        ends.iter()
            .filter(move |((_, timeslice), (ended, _))| *timeslice == continuation && *ended == end)
            .map(|((prefix, _), _)| *prefix)
    };
    let meets = at(TrialEnd::Met).min();
    let below = meets.unwrap_or(usize::MAX);
    let misses = at(TrialEnd::Missed).filter(|&prefix| prefix < below).max();
    let unfinished = ends
        .iter()
        .filter(|((prefix, timeslice), (end, _))| {
            *timeslice == continuation
                && !end.finished()
                && *prefix < below
                && misses.is_none_or(|misses| *prefix > misses)
        })
        .map(|((prefix, _), _)| *prefix)
        .collect();
    let run = |prefix: Option<usize>| {
        prefix.and_then(|prefix| runs.get(&(prefix, continuation)).cloned())
    };
    PrefixBracket {
        events,
        continuation: describe_continuation(continuation),
        misses,
        misses_run: run(misses),
        meets,
        meets_run: run(meets),
        unfinished,
    }
}

/// The result of `--prefix-search`: replaying the first `decision` events of
/// `schedule` and then scheduling without chaos, with timeslices of
/// `continuation`, misses the target, while replaying event `decision` too
/// meets it.
pub struct PrefixDecision {
    pub schedule: PreemptionRecord,
    pub decision: usize,
    pub continuation: MaybeTimeslice,
    /// [`refused_trials_warning`], if any trial was refused.
    pub refused: Option<String>,
    /// [`unfinished_boundary_warning`], when the last trial of the first
    /// `decision` events did not finish.
    pub unfinished: Option<String>,
}

/// The bound a confirmation of a prefix's trial gets, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmationBound {
    /// The first confirmation: it raises every later run's bound to this.
    Raise(u64),
    /// The bound was raised already, but this prefix's last trial ran under
    /// a shorter one (the empty prefix's, say): it runs again under this.
    Rerun(u64),
    /// No longer bound can be given.
    Unavailable,
}

/// Which [`ConfirmationBound`] a prefix whose last trial ran under `earlier`
/// seconds gets: `raised` is [`AnalyzeOpts::confirmation_bound`], `factor`
/// [`AnalyzeOpts::trial_bound_factor`] and `now` the bound a trial created
/// now runs under ([`AnalyzeOpts::effective_trial_bound`]).
fn confirmation_bound(
    raised: Option<u64>,
    factor: u32,
    now: Option<u64>,
    earlier: Option<u64>,
) -> ConfirmationBound {
    match (raised, now) {
        (Some(longer), _) => ConfirmationBound::Raise(longer),
        (None, Some(now)) if factor != 1 && earlier < Some(now) => ConfirmationBound::Rerun(now),
        _ => ConfirmationBound::Unavailable,
    }
}

/// The bound factor after a confirmation that `raised` it ended `end`: a
/// confirmation the wall-clock bound stopped again goes back to the usual
/// bound, since the boundary rests on a bound either way and the shorter one
/// costs less; one that finished keeps the longer bound, so the recheck and
/// the stack-trace runs of that prefix can finish too. So does one the
/// virtual-time bound stopped: those runs need as long to reach that same
/// stop.
fn factor_after_confirmation(factor: u32, raised: bool, end: TrialEnd) -> u32 {
    if raised && end == TrialEnd::Unfinished(Stop::Bound) {
        1
    } else {
        factor
    }
}

/// The longest prefix shorter than `passing` whose last trial at
/// `continuation` finished, and how it ended, from each prefix's last trial
/// (`ends`).
fn longest_finished_below(
    ends: &BTreeMap<(usize, MaybeTimeslice), (TrialEnd, Option<u64>)>,
    continuation: MaybeTimeslice,
    passing: usize,
) -> Option<(usize, TrialEnd)> {
    ends.iter()
        .rev()
        .filter(|((prefix, timeslice), _)| *timeslice == continuation && *prefix < passing)
        .map(|(&(prefix, _), &(end, _))| (prefix, end))
        .find(|&(_, end)| end.finished())
}

/// Which flag raises the bound that stopped a trial, as advice: the run
/// arguments' own `--timeout` (`own`, in seconds) where that is the bound
/// trials ran under, `last` (none when `--trial-timeout` is `off`), else
/// `--trial-timeout`.
fn bound_remedy(own: Option<u64>, trial_timeout_off: bool, last: Option<u64>) -> &'static str {
    if own.is_some() && (trial_timeout_off || own <= last) {
        "raise the run arguments' --timeout"
    } else {
        "raise --trial-timeout"
    }
}

/// [`bound_remedy`] for a trial a virtual-time bound of `bound` virtual
/// nanoseconds stopped: the run arguments' own `--virtual-timeout` (`own`)
/// where that is the bound, `--trial-virtual-timeout` where analyze's
/// (`analyze`) is, and both where they are equal.
fn virtual_bound_remedy(own: Option<u64>, analyze: Option<u64>, bound: u64) -> &'static str {
    match (own == Some(bound), analyze == Some(bound)) {
        (true, true) => {
            "raise both the run arguments' --virtual-timeout and --trial-virtual-timeout"
        }
        (true, false) => "raise the run arguments' --virtual-timeout",
        (false, _) => "raise --trial-virtual-timeout",
    }
}

/// What a search should say about its result when the last trial of the first
/// `passing` events, the boundary's baseline side, did not finish and ended
/// `last` ([`Stop::Bound`] or [`Stop::VirtualBound`]). A trial the wall-clock
/// bound stopped did not finish within `bound` seconds and then, when it ran
/// again to confirm it, within `confirmed` seconds (`None`: no longer bound
/// could be given). One the virtual-time bound stopped is not confirmed with a
/// longer bound, since a rerun at the same bound stops at the same scheduler
/// turn, unless it was itself the confirmation, under `confirmed` seconds, of a
/// trial the wall-clock bound stopped. `below` is the longest shorter prefix
/// the search replayed whose trial finished, and how it ended. It names only
/// prefixes the search replayed: the search assumes the outcome changes once
/// along the schedule, so it claims nothing about the prefixes in between.
/// `remedy` is [`bound_remedy`]'s or [`virtual_bound_remedy`]'s advice.
fn unfinished_boundary_warning(
    passing: usize,
    last: TrialEnd,
    bound: Option<u64>,
    confirmed: Option<u64>,
    below: Option<(usize, TrialEnd)>,
    remedy: &str,
) -> String {
    let wall = describe_trial_end(TrialEnd::Unfinished(Stop::Bound), bound);
    let (stopped, rests_on) = match (last, confirmed) {
        (TrialEnd::Unfinished(Stop::VirtualBound(_)), None) => (
            describe_trial_end(last, None),
            "a virtual-time bound, not on an outcome. That bound is the same on every host, and a \
             rerun at the same bound stops at the same scheduler turn, so the trial was not \
             confirmed with a longer bound",
        ),
        (TrialEnd::Unfinished(Stop::VirtualBound(nanos)), Some(longer)) => (
            format!(
                "{wall}, nor within {nanos} ns of virtual time when it ran again with a bound of \
                 {longer} s to confirm it"
            ),
            "a virtual-time bound, not on an outcome. That bound is the same on every host, and a \
             rerun at the same bound stops at the same scheduler turn",
        ),
        (_, Some(longer)) => (
            format!("{wall}, nor within {longer} s when it ran again to confirm it"),
            "a wall-clock bound, not on an outcome",
        ),
        (_, None) => (
            format!("{wall}, and no longer bound could be given to confirm it"),
            "a wall-clock bound, not on an outcome",
        ),
    };
    let below = match below {
        Some((prefix, end)) => format!(
            "The longest shorter prefix the search replayed that finished is the prefix of \
             {prefix} events, which {}.",
            describe_trial_end(end, None)
        ),
        None => "No shorter prefix the search replayed finished.".to_owned(),
    };
    format!(
        "replaying the first {passing} events and then scheduling without chaos {stopped}: the \
         guest hangs (for example in a deadlock while other threads keep polling), or needs \
         longer still. A hang is a third outcome, not a run that misses the target, yet the \
         search counted it as not meeting the target: this boundary rests on {rests_on}. Given \
         longer, that trial may meet the target, and an earlier event decide the outcome \
         ({remedy}). {below}"
    )
}

/// How a trial ended, for a message; `bound` is the wall-clock bound it ran
/// under, in seconds. A virtual-time bound is in the end itself.
fn describe_trial_end(end: TrialEnd, bound: Option<u64>) -> String {
    match end {
        TrialEnd::Met => "met the target".to_owned(),
        TrialEnd::Missed => "missed the target".to_owned(),
        TrialEnd::Unfinished(Stop::Bound) => match bound {
            Some(bound) => format!("did not finish within {bound} s"),
            None => "did not finish".to_owned(),
        },
        TrialEnd::Unfinished(Stop::VirtualBound(nanos)) => {
            format!("did not finish within {nanos} ns of virtual time")
        }
        TrialEnd::Unfinished(Stop::Refusal) => "was refused by Hermit".to_owned(),
    }
}

/// What a search with `refused` trials Hermit refused at run time, all
/// counted as not meeting the target, should say about its result.
fn refused_trials_warning(refused: usize) -> Option<String> {
    (refused > 0).then(|| {
        format!(
            "{refused} trial(s) were refused by Hermit (exit 122) and counted as not meeting \
             the target, so the deciding event may separate the target from a path Hermit does \
             not support rather than from a run that misses the target."
        )
    })
}

/// The coarsest timeslice `--continuation-timeslice=auto` tries, in virtual
/// nanoseconds: `hermit run`'s default `--max-timeslice` (200 ms).
pub const COARSEST_CONTINUATION_TIMESLICE: NonZeroU64 = NonZeroU64::new(200_000_000).unwrap();

/// The continuation timeslices `--continuation-timeslice=auto` tries, in
/// order, for a run whose own maximum is `run`: that, then
/// [`COARSEST_CONTINUATION_TIMESLICE`] if it is coarser. Never a shorter one:
/// a trial's `--max-timeslice` also ends the replayed prefix's slices that
/// its schedule does not end, so a shorter one would change the prefix. A run
/// without PMU timeslices (`None`) continues as it is.
fn continuation_candidates(run: MaybeTimeslice) -> Vec<MaybeTimeslice> {
    let Some(run) = run else {
        return vec![None];
    };
    let mut candidates = vec![Some(run), Some(run.max(COARSEST_CONTINUATION_TIMESLICE))];
    candidates.dedup();
    candidates
}

/// What the endpoint trials of a prefix search showed for one continuation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Continuation {
    /// Replaying none of the schedule misses the target, and replaying all
    /// of it meets it: a search can find the event in between that decides.
    Usable,
    /// The scheduler alone, replaying none of the schedule, meets the target.
    MeetsTargetAlone,
    /// Replaying the whole schedule finished and missed the target.
    ReplayMisses,
    /// Replaying the whole schedule did not finish (a bound or a refusal
    /// stopped it).
    ReplayUnfinished,
}

/// Check the two endpoint trials of a prefix search over `len` events.
fn check_continuation(
    len: usize,
    mut trial: impl FnMut(usize) -> anyhow::Result<TrialEnd>,
) -> anyhow::Result<Continuation> {
    if trial(0)?.reached_target() {
        return Ok(Continuation::MeetsTargetAlone);
    }
    Ok(match trial(len)? {
        TrialEnd::Met => Continuation::Usable,
        TrialEnd::Missed => Continuation::ReplayMisses,
        TrialEnd::Unfinished(_) => Continuation::ReplayUnfinished,
    })
}

/// Pick the first of `candidates` (continuation timeslices) whose endpoint
/// trials allow a prefix search over `len` events, each candidate's trials
/// run by `trial(prefix, timeslice)`. When none does, the error says what
/// each one showed and what to do instead.
fn choose_continuation(
    candidates: &[MaybeTimeslice],
    len: usize,
    mut trial: impl FnMut(usize, MaybeTimeslice) -> anyhow::Result<TrialEnd>,
) -> anyhow::Result<MaybeTimeslice> {
    let mut outcomes = Vec::new();
    for &timeslice in candidates {
        match check_continuation(len, |prefix| trial(prefix, timeslice))? {
            Continuation::Usable => return Ok(timeslice),
            outcome => {
                eprintln!(
                    ":: Continuing without chaos {}, {}",
                    describe_continuation(timeslice),
                    describe_outcome(outcome)
                );
                outcomes.push((timeslice, outcome));
            }
        }
    }
    let alone: Vec<String> = outcomes
        .iter()
        .filter(|(_, outcome)| *outcome == Continuation::MeetsTargetAlone)
        .map(|(timeslice, _)| describe_continuation(*timeslice))
        .collect();
    if let (true, Some(&(first, _))) = (alone.len() == outcomes.len(), outcomes.first()) {
        // A completed analysis, not a failure (`AnalyzeVerdict`).
        return Err(AnalyzeVerdict::no_deciding_event(
            format!(
                "no event of the target schedule decides the outcome: without chaos, the scheduler \
             alone already meets the target criteria {}. The outcome does not depend on a chaos \
             decision, so debug that run directly: the reproducer of the first trial \
             (prefix_round_001.repro in the workspace) runs it. To bisect against a run that \
             misses the target instead, pass --continuation-timeslice with a timeslice at which \
             the scheduler alone misses it, or use the default search with a passing \
             --run2-seed.",
                alone.join(" and ")
            ),
            first,
        )
        .into());
    }
    let remedy = if outcomes
        .iter()
        .any(|(_, outcome)| *outcome == Continuation::ReplayUnfinished)
    {
        "A replay that did not finish was ended by a bound (raise --trial-timeout, or \
         --trial-virtual-timeout for a virtual-time bound) or refused by Hermit (its reason is \
         in its log file, or in analyze's output above when it writes none)."
    } else {
        "Schedule replay does not reproduce this run where replaying the whole target schedule \
         misses the target; check that the target run replays (--selfcheck)."
    };
    Err(AnalyzePrecondition::no_prefix_continuation(format!(
        "no continuation allows a prefix search: {}. {remedy} The default search with a \
         passing --run2-seed needs no continuation.",
        outcomes
            .iter()
            .map(|(timeslice, outcome)| format!(
                "{} {}",
                describe_continuation(*timeslice),
                describe_outcome(*outcome)
            ))
            .collect::<Vec<_>>()
            .join("; ")
    ))
    .into())
}

/// Whether the bisection's `error` says that no single reordering separates
/// the endpoints ([`NoSingleSwap`], [`NoReorderableDistance`]): the decision
/// is then within the failing schedule, and a prefix search needs no baseline
/// to find it.
fn no_swap_separates(error: &Error) -> bool {
    error.downcast_ref::<NoSingleSwap>().is_some()
        || error.downcast_ref::<NoReorderableDistance>().is_some()
}

/// `error` from bisecting analyze's own endpoints, pointing an endpoint that
/// did not reproduce its outcome at replay: analyze recorded both endpoints
/// itself, so Hermit's replay, or the host's branch counter, did not
/// reproduce the run.
fn point_endpoint_misses_at_replay(error: Error) -> Error {
    match error.downcast::<AnalyzePrecondition>() {
        Ok(precondition)
            if matches!(
                precondition.class,
                PreconditionClass::TargetNotReproduced | PreconditionClass::BaselineNotReproduced
            ) =>
        {
            precondition
                .with_hint(
                    "Analyze recorded this endpoint itself, so its replay did not reproduce \
                     the run: --selfcheck checks that the target run replays, and `hermit \
                     host-capabilities` whether this host's branch counter is exact.",
                )
                .into()
        }
        Ok(precondition) => precondition.into(),
        Err(error) => error,
    }
}

/// How analyze goes on after bisecting its own endpoints
/// ([`own_bisection_end`]).
enum OwnBisectionEnd {
    /// The critical pair, to report.
    Critical(CriticalSchedule),
    /// No single reordering separates the endpoints (the error says why): the
    /// decision is still within the failing schedule, and a prefix search
    /// needs no baseline to find it.
    SearchPrefixes(Error),
}

/// What the bisection of analyze's own endpoints, `bisected`, leads to. An
/// endpoint that did not reproduce is pointed at replay
/// ([`point_endpoint_misses_at_replay`]); any other error ends the analysis.
fn own_bisection_end(
    bisected: anyhow::Result<CriticalSchedule>,
) -> anyhow::Result<OwnBisectionEnd> {
    match bisected {
        Ok(critical) => Ok(OwnBisectionEnd::Critical(critical)),
        Err(error) if no_swap_separates(&error) => Ok(OwnBisectionEnd::SearchPrefixes(error)),
        Err(error) => Err(point_endpoint_misses_at_replay(error)),
    }
}

/// --selfcheck's conclusion from its rerun of the target: whether it met the
/// target, whether its log matched, and (checked last) whether it recorded
/// the preemptions it replayed. Any difference is replay not reproducing,
/// Hermit's or the host's, and a failure (`AnalyzeFailure`), not an input
/// analyze cannot use.
fn selfcheck_conclusion(
    rerun_matched: bool,
    logs_agree: bool,
    fixed_point: impl FnOnce() -> Result<(), String>,
) -> anyhow::Result<()> {
    const HOST: &str = "`hermit host-capabilities` reports whether this host's branch counter \
                        is exact.";
    let difference = if !rerun_matched {
        "First run matched criteria but second run did not.".to_string()
    } else if !logs_agree {
        "Log differences found, aborting because --selfcheck requires perfect reproducibility \
         of the target run!"
            .to_string()
    } else if let Err(difference) = fixed_point() {
        difference
    } else {
        return Ok(());
    };
    Err(AnalyzeFailure::ReplayNotReproducible(format!("{difference} {HOST}")).into())
}

/// The verdict of a prefix search whose empty prefix meets the target when
/// continued without chaos at `continuation` (`error`, an
/// [`EmptyPrefixMeetsTarget`]), naming any coarser one of `candidates` it did
/// not try.
fn empty_prefix_verdict(
    error: &Error,
    candidates: &[Option<NonZeroU64>],
    continuation: Option<NonZeroU64>,
) -> AnalyzeVerdict {
    // The empty prefix's first trial was stopped, so the continuation looked
    // usable and any coarser candidate went untried; name it rather than let
    // the host's speed decide.
    let untried: Vec<String> = candidates
        .iter()
        .skip_while(|&&candidate| candidate != continuation)
        .skip(1)
        .map(|&candidate| describe_continuation(candidate))
        .collect();
    let untried = if untried.is_empty() {
        String::new()
    } else {
        format!(
            " The search did not try continuing {}, because the empty prefix's first trial did \
             not finish; --continuation-timeslice selects one.",
            untried.join(" or ")
        )
    };
    AnalyzeVerdict::no_deciding_event(
        format!(
            "no event of the target schedule decides the outcome: {error}, so without chaos {}, the \
         scheduler alone, replaying none of the target schedule, meets the target. The outcome \
         does not depend on a chaos decision, so debug that run directly: the reproducer of the \
         last trial in the workspace runs it. To bisect against a run that misses the target \
         instead, pass --continuation-timeslice with a timeslice at which the scheduler alone \
         misses it, or use the default search with a passing --run2-seed.{untried}",
            describe_continuation(continuation)
        ),
        continuation,
    )
}

/// `args` without the option `name`, as `name=VALUE` or as `name` and its
/// value, before any `--` that starts the guest command, whose arguments are
/// kept as they are.
fn without_option(args: &[String], name: &str) -> Vec<String> {
    let mut kept = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            kept.push(arg.clone());
            kept.extend(iter.cloned());
            break;
        }
        if arg == name {
            iter.next();
        } else if !arg
            .strip_prefix(name)
            .is_some_and(|rest| rest.starts_with('='))
        {
            kept.push(arg.clone());
        }
    }
    kept
}

/// "at a 200000000 ns timeslice", or "without PMU timeslices".
pub(super) fn describe_continuation(timeslice: MaybeTimeslice) -> String {
    match timeslice {
        Some(nanos) => format!("at a {nanos} ns timeslice"),
        None => "without PMU timeslices".to_owned(),
    }
}

fn describe_outcome(outcome: Continuation) -> &'static str {
    match outcome {
        Continuation::Usable => "a prefix search can run",
        Continuation::MeetsTargetAlone => {
            "the scheduler alone, replaying none of the target schedule, meets the target"
        }
        Continuation::ReplayMisses => "replaying the whole target schedule misses the target",
        Continuation::ReplayUnfinished => {
            "replaying the whole target schedule did not finish (a bound or a refusal stopped it)"
        }
    }
}

/// The trial of the empty prefix, which a bound had stopped, met the target
/// when [`search_prefix_boundary`] confirmed it: the scheduler alone meets it.
#[derive(Debug)]
struct EmptyPrefixMeetsTarget;

impl std::fmt::Display for EmptyPrefixMeetsTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "given longer than the bound that stopped it, the trial of the empty prefix meets \
             the target criteria"
        )
    }
}

impl std::error::Error for EmptyPrefixMeetsTarget {}

/// Why [`search_prefix_boundary`] runs a trial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrialPurpose {
    /// To narrow the search.
    Search,
    /// To confirm the boundary: the prefix's last trial did not finish, and
    /// it runs again with a longer bound.
    Confirm,
}

/// The boundary a prefix search settled on: the prefix of `passing` events
/// does not meet the target, the prefix of `passing + 1` events meets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Boundary {
    passing: usize,
    /// How the last trial of the prefix of `passing` events ended: it missed
    /// the target, or it did not finish.
    passing_end: TrialEnd,
}

/// The binary search of `--prefix-search` over a schedule of `len` events
/// whose endpoints [`check_continuation`] found usable, the trial of the
/// empty prefix having ended `empty`. Uses about log2(len) trials when they
/// all finish.
///
/// Only a trial that finished has an outcome: a wall-clock bound stops a
/// trial at a time the host decides, so one run of a prefix can finish and
/// meet the target and the next be stopped. While the search narrows, a
/// stopped trial counts as not meeting the target, since a guest can spin
/// for ever on the baseline side. It does not decide the boundary, though:
/// when the search settles on one, `trial(k, Confirm)` runs it again with a
/// longer bound. If it then meets the target, the boundary is below it, and
/// the search goes on above the longest prefix that did not meet the target
/// and was not stopped by the wall-clock bound (or the empty prefix), every
/// such stopped trial in between open again. `Confirm` returns `None` when
/// no longer bound can be given, and the boundary stays on the stopped
/// trial. A search trial always returns `Some`.
///
/// A trial the virtual-time bound stopped is not confirmed with a longer
/// bound, and bounds the search from below like a trial that missed: every
/// run of it at the same bound stops at the same scheduler turn, on every
/// host, so the boundary then rests on that bound.
///
/// Confirming the boundary's trial is enough when a prefix that meets the
/// target stays met when it grows: a stopped trial that steered the search
/// past the deciding event left a passing side at or after that event, which
/// meets the target when given long enough, so its confirmation shows it.
fn search_prefix_boundary(
    len: usize,
    empty: TrialEnd,
    mut trial: impl FnMut(usize, TrialPurpose) -> anyhow::Result<Option<TrialEnd>>,
) -> anyhow::Result<Boundary> {
    // How each prefix shorter than `failing` that did not meet the target
    // ended, the empty prefix included.
    let mut missed = BTreeMap::from([(0, empty)]);
    let mut failing = len;
    loop {
        let mut passing = *missed.keys().next_back().expect("the empty prefix is kept");
        while failing - passing > 1 {
            let mid = passing + (failing - passing) / 2;
            let end = trial(mid, TrialPurpose::Search)?
                .context("a search trial always ends one way or another")?;
            if end.reached_target() {
                failing = mid;
            } else {
                missed.insert(mid, end);
                passing = mid;
            }
        }
        let passing_end = missed[&passing];
        if passing_end != TrialEnd::Unfinished(Stop::Bound) {
            return Ok(Boundary {
                passing,
                passing_end,
            });
        }
        match trial(passing, TrialPurpose::Confirm)? {
            Some(TrialEnd::Met) if passing == 0 => return Err(EmptyPrefixMeetsTarget.into()),
            Some(TrialEnd::Met) => {
                failing = passing;
                // A stopped trial is no more an outcome than the one just
                // refuted, so only the others bound the search from below.
                missed.retain(|&prefix, end| {
                    prefix == 0 || *end != TrialEnd::Unfinished(Stop::Bound)
                });
            }
            confirmed => {
                return Ok(Boundary {
                    passing,
                    passing_end: confirmed.unwrap_or(passing_end),
                });
            }
        }
    }
}

/// What the final recheck of a `--prefix-search` boundary trial shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recheck {
    /// Nothing to warn about: it ended as before, or missed the target in
    /// another way (a refusal for a miss).
    Repeated,
    /// The wall-clock bound stopped it: the trial runs close to that bound.
    CloseToTheBound,
    /// Another outcome: whether it met the target changed, or a stop at the
    /// virtual-time bound, which repeats like an outcome, did not repeat.
    Other,
}

/// [`Recheck`] for a boundary trial that ended `first` and, run again,
/// `again`.
fn recheck(first: TrialEnd, again: TrialEnd) -> Recheck {
    let virtual_stop = |end| matches!(end, TrialEnd::Unfinished(Stop::VirtualBound(_)));
    if again == first {
        Recheck::Repeated
    } else if again == TrialEnd::Unfinished(Stop::Bound) {
        Recheck::CloseToTheBound
    } else if again.reached_target() != first.reached_target()
        || virtual_stop(first)
        || virtual_stop(again)
    {
        Recheck::Other
    } else {
        Recheck::Repeated
    }
}

/// Why the critical pair a search settled on may not be a race, if there is a reason.
///
/// Swapping two events of one thread is no interleaving any execution can take, so
/// the outcome change at such a pair comes from the replay falling off the schedule.
/// Trials that timed out were counted as not reaching the target, which can steer
/// the search onto exactly such a pair.
fn critical_pair_caveat(crit: &CriticalSchedule) -> Option<String> {
    let index = crit.critical_event_index;
    let schedule = &crit.failing_schedule;
    let same_thread =
        index > 0 && index < schedule.len() && schedule[index - 1].dettid == schedule[index].dettid;
    if !same_thread {
        return None;
    }
    Some(format!(
        "the critical events #{} and #{index} both belong to thread {}, so swapping them is \
         not an interleaving and this pair is not a race.",
        index - 1,
        schedule[index].dettid,
    ))
}

/// The warnings a default search's result carries: how many trials the run
/// arguments' `--timeout` stopped, whenever any did, and why a critical pair
/// of one thread is not a race ([`critical_pair_caveat`]).
fn search_warnings(crit: &CriticalSchedule, timed_out: usize) -> Vec<String> {
    let mut warnings = Vec::new();
    if timed_out > 0 {
        warnings.push(format!(
            "{timed_out} trial(s) did not finish within the run arguments' --timeout. Each was \
             counted as the baseline condition, with the schedule it was asked to replay taken \
             as the one it realized, so the critical pair may rest on them."
        ));
    }
    warnings.extend(critical_pair_caveat(crit));
    warnings
}

/// How long one thread runs from an event on, in one schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slice {
    /// Its events, from the first one on.
    events: usize,
    /// The retired conditional branches among them.
    branches: u64,
    /// The event at which another thread runs next, and that thread; `None`
    /// if none does before the schedule ends.
    next: Option<(usize, DetTid)>,
}

/// The schedule a prefix trial realized, and where it was recorded.
type Continued<'a> = (&'a [SchedEvent], &'a Path);
/// A continuation with the access trace its replay recorded, if it recorded
/// one (`prefix_racing_accesses`).
type TracedContinuation<'a, 'b> = (Continued<'a>, &'b mut Option<TracedReplay>);

/// A record that replays `continued`, the schedule a prefix trial of the
/// first `len` events of `schedule` realized, under the callback checkpoints
/// of that prefix (a replay records none of its own), unless they no longer
/// fit its events.
fn continued_record(
    schedule: &PreemptionRecord,
    len: usize,
    continued: &[SchedEvent],
) -> PreemptionRecord {
    schedule
        .schedule_prefix(len)
        .with_schedule(continued.to_vec())
        .unwrap_or_else(|| PreemptionRecord::from_sched_events(continued.to_vec()))
}

/// How many events of the search's schedule keep their callback
/// checkpoints in a race candidate's check of the `role` run: that run's own
/// prefix (the baseline replayed one event fewer than the target's `len`),
/// up to `unchanged`, where the edit starts.
fn check_prefix_len(len: usize, role: &str, unchanged: usize) -> usize {
    let own = if role == "baseline" {
        len.saturating_sub(1)
    } else {
        len
    };
    own.min(unchanged)
}

/// The run of `thread`'s events in `schedule` from event `from` on.
fn slice_from(schedule: &[SchedEvent], from: usize, thread: DetTid) -> Slice {
    let mut slice = Slice {
        events: 0,
        branches: 0,
        next: None,
    };
    for (index, event) in schedule.iter().enumerate().skip(from) {
        if event.dettid != thread {
            slice.next = Some((index, event.dettid));
            break;
        }
        slice.events += 1;
        if event.op == detcore_model::schedule::Op::Branch {
            slice.branches += u64::from(event.count);
        }
    }
    slice
}

/// One thread's run of consecutive events in a realized schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Turn {
    thread: DetTid,
    /// Its first and last events.
    start: usize,
    end: usize,
    /// The retired conditional branches it ran.
    branches: u64,
    /// The thread's first turn in the schedule. Its first event is where the
    /// thread starts, which says nothing about what it does.
    first: bool,
    /// It only finishes creating a thread or process: it is not the
    /// thread's first turn (a forked child's begins with the fork's return
    /// too), it begins by returning from a clone, clone3, fork or vfork, and
    /// after that makes no call but the ones pthread_create ends with
    /// (restoring the signal mask, waking the new thread's start-up lock)
    /// and runs at most [`CREATION_EPILOGUE_BRANCHES`] branches.
    creates: bool,
    /// The call the turn ends at, entering it, if it does: where the thread
    /// blocks or waits. A turn that ends elsewhere was preempted.
    ends_at: Option<reverie::syscalls::Sysno>,
}

/// The most branches a creator's turn runs after its clone or fork returns
/// for the turn to count as only finishing the creation ([`Turn::creates`]).
/// pthread_create's own epilogue, from the clone's return to its own, ran
/// 159 in bionic (Android's libc; a thread-pool harness: rt_sigprocmask and
/// two futex calls) and 13 in glibc 2.34 (x86-64, clone3: one
/// rt_sigprocmask), measured as the retired conditional branches Hermit
/// recorded between the clone's return and the caller's next call.
const CREATION_EPILOGUE_BRANCHES: u64 = 256;

impl Turn {
    fn events(&self) -> usize {
        self.end + 1 - self.start
    }

    /// Where the thread's stack shows what it does in this turn: its first
    /// event, where it resumes, unless that is where it starts; then its
    /// last.
    fn telling_event(&self) -> usize {
        if self.first { self.end } else { self.start }
    }

    /// For a thread that starts in this turn, where its stack is taken and
    /// what that is, as the end of a report sentence.
    fn start_sentence(&self) -> String {
        let end = match self.ends_at {
            Some(sysno) => format!("at its {} call, where it blocks or waits", sysno.name()),
            None => "where it was preempted, at an arbitrary instruction".to_owned(),
        };
        format!(
            ". Thread {} starts in that turn, so its stack is where the turn ends, {end}",
            self.thread
        )
    }
}

/// Whether `creator`'s turn (which returns from a clone or fork) returns
/// from creating `child`: `child` has no event before the creator's call.
/// Such a creator is never passed over for `child`: what it does next is
/// what its new thread races with.
fn created(schedule: &[SchedEvent], creator: &Turn, child: DetTid) -> bool {
    use detcore_model::schedule::Op;
    use detcore_model::schedule::SyscallPhase;
    let call = schedule[..creator.start].iter().rposition(|event| {
        event.dettid == creator.thread
            && matches!(event.op, Op::Syscall(sysno, SyscallPhase::Prehook) if creates_a_task(sysno))
    });
    call.is_some_and(|call| schedule[..call].iter().all(|event| event.dettid != child))
}

/// Whether stack2 passes over `turn`: it only finishes creating a thread
/// ([`Turn::creates`]), and not the thread `related` (the deciding thread,
/// or the other side's).
fn passed_over(schedule: &[SchedEvent], turn: &Turn, related: DetTid) -> bool {
    turn.creates && !created(schedule, turn, related)
}

/// Whether `sysno` creates a thread or process.
fn creates_a_task(sysno: reverie::syscalls::Sysno) -> bool {
    use reverie::syscalls::Sysno;
    #[cfg(target_arch = "x86_64")]
    if matches!(sysno, Sysno::fork | Sysno::vfork) {
        return true;
    }
    matches!(sysno, Sysno::clone | Sysno::clone3)
}

/// The turns of `schedule` from event `from` on.
fn turns(schedule: &[SchedEvent], from: usize) -> impl Iterator<Item = Turn> + '_ {
    use detcore_model::schedule::Op;
    use detcore_model::schedule::SyscallPhase;
    let mut seen: std::collections::BTreeSet<DetTid> = schedule
        .iter()
        .take(from)
        .map(|event| event.dettid)
        .collect();
    use reverie::syscalls::Sysno;
    let mut at = from;
    std::iter::from_fn(move || {
        let thread = schedule.get(at)?.dettid;
        let start = at;
        let mut branches = 0;
        // Returned from creating a task, and since then only the epilogue's
        // calls and this many branches.
        let mut epilogue: Option<u64> = None;
        let mut creates = true;
        let mut first_call = true;
        let mut ends_at = None;
        while let Some(event) = schedule.get(at).filter(|event| event.dettid == thread) {
            ends_at = None;
            match event.op {
                Op::Branch => {
                    branches += u64::from(event.count);
                    if let Some(after) = epilogue.as_mut() {
                        *after += u64::from(event.count);
                    }
                }
                Op::Syscall(sysno, phase) => {
                    if first_call {
                        if phase == SyscallPhase::Posthook && creates_a_task(sysno) {
                            epilogue = Some(0);
                        } else {
                            creates = false;
                        }
                    } else if !matches!(sysno, Sysno::rt_sigprocmask | Sysno::futex) {
                        creates = false;
                    }
                    first_call = false;
                    if phase == SyscallPhase::Prehook {
                        ends_at = Some(sysno);
                    }
                }
                _ => {}
            }
            at += 1;
        }
        let first = seen.insert(thread);
        Some(Turn {
            thread,
            start,
            end: at - 1,
            branches,
            first,
            creates: creates
                && !first
                && epilogue.is_some_and(|after| after <= CREATION_EPILOGUE_BRANCHES),
            ends_at,
        })
    })
}

/// The continuation of a `--prefix-search` trial a stack comes from: the one
/// that replays the deciding event, or the one without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    With,
    Without,
}

impl Side {
    fn name(self) -> &'static str {
        match self {
            Side::With => "with",
            Side::Without => "without",
        }
    }
}

/// stack2's thread for a `--prefix-search` report, the event its stack is
/// taken at in the continuation `side`, and why that thread.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Partner {
    side: Side,
    thread: DetTid,
    event: usize,
    why: String,
}

/// Which of `moved`, the turns `schedule` runs before the deciding thread's
/// turn (which the other continuation runs first), stack2 shows: the first
/// that does more than finish creating a thread ([`passed_over`]), unless
/// none does. Such a turn only finishes the creation, so its thread's order
/// does not matter unless nothing else moved, or unless it created the
/// deciding thread.
fn first_moved(
    schedule: &[SchedEvent],
    side: Side,
    moved: &[Turn],
    deciding: DetTid,
) -> Option<Partner> {
    let passed = moved
        .iter()
        .take_while(|turn| passed_over(schedule, turn, deciding))
        .count();
    let (turn, passed) = match moved.get(passed) {
        Some(turn) => (turn, &moved[..passed]),
        None => (moved.first()?, &moved[..0]),
    };
    let other = match side {
        Side::Without => "with",
        Side::With => "without",
    };
    let mut why = format!(
        "thread {} runs before thread {deciding}'s turn {} the event and after it {other} it",
        turn.thread,
        side.name(),
    );
    for creator in passed {
        why.push_str(&format!(
            "; thread {}, which runs before it, only returns from creating a thread",
            creator.thread
        ));
    }
    if passed_over(schedule, turn, deciding) {
        why.push_str(", and only returns from creating a thread, as every thread that moved does");
    } else if turn.creates {
        why.push_str(&format!(
            "; it returns from creating thread {deciding}, which its next steps race with"
        ));
    }
    if turn.first {
        why.push_str(&turn.start_sentence());
    }
    Some(Partner {
        side,
        thread: turn.thread,
        event: turn.telling_event(),
        why,
    })
}

/// stack2's thread when the deciding event runs `deciding`'s turn first in
/// one continuation and `other`, which runs other threads first, does not:
/// the threads `other` runs from event `from` until `deciding`'s turn are
/// those that turn moves past ([`first_moved`]).
fn moved_past(other: &[SchedEvent], side: Side, from: usize, deciding: DetTid) -> Option<Partner> {
    let moved: Vec<Turn> = turns(other, from)
        .take_while(|turn| turn.thread != deciding)
        .collect();
    first_moved(other, side, &moved, deciding)
}

/// stack2's thread for a `--prefix-search` report, from the continuations
/// with the deciding event (`with`) and without it (`without`), from that
/// event `from` on; `deciding` is its thread. The two run the same turns
/// until one differs:
/// - the same thread for a different number of events: that thread, at the
///   last event both continuations give it, where they part;
/// - `deciding` in one and another thread in the other: the threads the
///   other runs before `deciding`'s turn ([`moved_past`]);
/// - two other threads: the one without the event, unless only it returns
///   from creating a thread.
///
/// `None` when one continuation ends before they differ.
fn partner_turn(
    with: &[SchedEvent],
    without: &[SchedEvent],
    from: usize,
    deciding: DetTid,
) -> Option<Partner> {
    let (with_turn, without_turn) = turns(with, from)
        .zip(turns(without, from))
        .find(|(a, b)| (a.thread, a.events(), a.branches) != (b.thread, b.events(), b.branches))?;
    if with_turn.thread == without_turn.thread {
        let shared = with_turn.events().min(without_turn.events());
        return Some(Partner {
            side: Side::Without,
            thread: without_turn.thread,
            event: without_turn.start + shared - 1,
            why: format!(
                "the continuations run the same turns until thread {}'s from event #{}, which \
                 runs {} events with the event and {} without it; its stack is where the two \
                 part",
                without_turn.thread,
                without_turn.start,
                with_turn.events(),
                without_turn.events(),
            ),
        });
    }
    if with_turn.thread == deciding {
        return moved_past(without, Side::Without, without_turn.start, deciding);
    }
    if without_turn.thread == deciding {
        return moved_past(with, Side::With, with_turn.start, deciding);
    }
    let (side, turn) = if passed_over(without, &without_turn, deciding)
        && !passed_over(with, &with_turn, deciding)
    {
        (Side::With, with_turn)
    } else {
        (Side::Without, without_turn)
    };
    let mut why = format!(
        "the continuations first run different threads at event #{}: thread {} with the event, \
         thread {} without it",
        without_turn.start, with_turn.thread, without_turn.thread,
    );
    if turn.first {
        why.push_str(&turn.start_sentence());
    }
    Some(Partner {
        side,
        thread: turn.thread,
        event: turn.telling_event(),
        why,
    })
}

/// Where phase 6 takes a `--prefix-search` report's stack2 ([`stack2_plan`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Stack2Plan {
    /// Another thread runs at the decision without the event: the replay of
    /// that continuation takes the stack at `at`, the decision itself unless
    /// `partner`, a thread the deciding turn moved past, says otherwise.
    Instead { at: usize, partner: Option<Partner> },
    /// The deciding thread runs there either way: the first thread whose
    /// turn differs between the continuations ([`partner_turn`]).
    Changed(Partner),
    /// The deciding thread runs there either way and the continuations do
    /// not differ before one ends: the thread after its slice without the
    /// event, at `index`.
    NextSlice { index: usize, thread: DetTid },
    /// The continuation without the event ends at the decision or before.
    Nothing,
}

/// Where phase 6 takes stack2 for the decision at `decision` of thread
/// `deciding`, from the continuation without the event (`without`) and, when
/// the deciding thread runs there either way, the one with it (`with`).
fn stack2_plan(
    deciding: DetTid,
    decision: usize,
    without: &[SchedEvent],
    with: Option<&[SchedEvent]>,
) -> Stack2Plan {
    let Some(instead) = without.get(decision) else {
        return Stack2Plan::Nothing;
    };
    if instead.dettid != deciding {
        return match moved_past(without, Side::Without, decision, deciding) {
            Some(moved) if moved.event != decision => Stack2Plan::Instead {
                at: moved.event,
                partner: Some(moved),
            },
            _ => Stack2Plan::Instead {
                at: decision,
                partner: None,
            },
        };
    }
    if let Some(changed) = with.and_then(|with| partner_turn(with, without, decision, deciding)) {
        return Stack2Plan::Changed(changed);
    }
    match slice_from(without, decision, deciding).next {
        Some((index, thread)) => Stack2Plan::NextSlice { index, thread },
        None => Stack2Plan::Nothing,
    }
}

/// Where a stack shows the thread that runs at an event where two realized
/// schedules first run different threads ([`telling_event_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Telling {
    event: usize,
    thread: DetTid,
    /// The thread passed over, whose turn there only returns from creating
    /// a thread.
    creator: Option<DetTid>,
    /// The thread starts in the turn, so `event` is where the turn ends.
    starts: bool,
    /// The call the turn ends at, if it does ([`Turn::ends_at`]).
    ends_at: Option<reverie::syscalls::Sysno>,
}

/// Where `schedule`'s stack shows the thread that runs at event `at`, where
/// two realized schedules first run different threads (`other` is the one
/// the other schedule runs there): `at` itself, unless a turn starts there
/// that only finishes creating a thread other than `other` ([`passed_over`];
/// then the next turn's) or is its thread's first, whose start says nothing
/// (then where it ends). A turn that runs on from before `at` stays at `at`,
/// where the two schedules part.
fn telling_event_at(schedule: &[SchedEvent], at: usize, other: DetTid) -> Option<Telling> {
    let thread = schedule.get(at)?.dettid;
    if at > 0 && schedule[at - 1].dettid == thread {
        return Some(Telling {
            event: at,
            thread,
            creator: None,
            starts: false,
            ends_at: None,
        });
    }
    let mut from_at = turns(schedule, at);
    let mut turn = from_at.next()?;
    let mut creator = None;
    if passed_over(schedule, &turn, other)
        && let Some(next) = from_at.next()
    {
        creator = Some(turn.thread);
        turn = next;
    }
    Some(Telling {
        event: turn.telling_event(),
        thread: turn.thread,
        creator,
        starts: turn.first,
        ends_at: turn.ends_at,
    })
}

/// Whether two stacks have the same frames, whichever threads they belong
/// to.
fn same_frames(first: &PrettyBacktrace, second: &PrettyBacktrace) -> bool {
    first.iter().eq(second.iter())
}

/// The events at which the deciding thread's slice ends in the continuation
/// with the deciding event and in the one without it, when the stacks of the
/// threads that run next (`next_stacks`) tell nothing apart: both captured,
/// with the same frames (often threads just started, at their first
/// instruction). `None` otherwise.
fn slice_end_events(
    with: &Slice,
    without: &Slice,
    next_stacks: [Option<&PrettyBacktrace>; 2],
) -> Option<[usize; 2]> {
    match (next_stacks, with.next, without.next) {
        ([Some(first), Some(second)], Some((with_next, _)), Some((without_next, _)))
            if same_frames(first, second) =>
        {
            Some([with_next - 1, without_next - 1])
        }
        _ => None,
    }
}

/// The header of a `--prefix-search` report whose deciding event `event`,
/// #`decision`, is a timing decision: `with` and `without` are how long its
/// thread then runs with and without that event replayed. `slice_ends`, the
/// last events of those slices, is set when stack1 shows where the deciding
/// thread stops with the event instead of the thread that runs next, whose
/// stack (the same in both continuations) is stack2, from the continuation
/// without it.
fn timing_decision_header(
    decision: usize,
    event: &SchedEvent,
    (with, without): (&Slice, &Slice),
    criteria: &str,
    continuation: MaybeTimeslice,
    slice_ends: Option<[usize; 2]>,
) -> String {
    let thread = event.dettid;
    let then = |slice: &Slice, stack: Option<&str>| match (slice.next, stack) {
        (Some((index, next)), Some(stack)) => {
            format!("then thread {next} runs at event #{index} ({stack})")
        }
        (Some((index, next)), None) => format!("then thread {next} runs at event #{index}"),
        (None, _) => "and no other thread runs after it".to_owned(),
    };
    let mut header = format!(
        "The scheduling decision at event #{decision} of the target schedule decides the \
         outcome, and it is a timing decision: with or without it, the scheduler runs thread \
         {thread} there, so what decides is how long thread {thread} runs, not which thread \
         runs.\nWith event #{decision} replayed ({event}), thread {thread} runs {} events ({} \
         retired conditional branches) from event #{decision} on, {}, and the run meets the \
         target criteria ({criteria}).\nWithout it, scheduling without chaos {}, thread {thread} \
         runs {} events ({} retired conditional branches), {}, and the run does not.\n",
        with.events,
        with.branches,
        then(with, slice_ends.is_none().then_some("stack1")),
        describe_continuation(continuation),
        without.events,
        without.branches,
        then(without, Some("stack2")),
    );
    if let Some([with_end, without_end]) = slice_ends {
        header.push_str(&format!(
            "The thread that runs next has the same stack in both continuations (often a \
             thread just started), so stack1 shows where thread {thread} is when its slice ends \
             with the event, at event #{with_end}, and stack2 is that next thread, without the \
             event (where thread {thread}'s slice ends at event #{without_end}).\n"
        ));
    }
    header.push_str(&format!(
        "Thread {thread}'s own stack at event #{decision} is printed first (deciding_event in \
         the report file).\nThe outcome depends on what thread {thread} does before the other \
         thread runs: add synchronization that makes its timing irrelevant, or that enforces \
         the passing order.\n"
    ));
    header
}

/// What a stack-trace replay of a critical pair gave.
struct StackReplay {
    /// It finished (no bound or refusal stopped it).
    finished: bool,
    /// It finished and met the target criteria.
    met_target: bool,
    /// The stacks at its schedule's events `index - 1` and `index`.
    stacks: [Option<PrettyBacktrace>; 2],
    /// Where it left its schedule before passing event `index`, if it did.
    left_schedule: Option<Departure>,
    /// The first event of its schedule it recorded at another position,
    /// after a branch event the schedule leaves out ([`follow`]), if any.
    shifted_at: Option<usize>,
    /// The threads it ran at positions `index - 1` and `index` of its
    /// realized schedule, where the scheduler took its stacks, if it
    /// recorded them.
    ran: [Option<DetTid>; 2],
    /// The schedule it realized (empty if it recorded none), recorded at
    /// `realized_path`.
    realized: Vec<SchedEvent>,
    realized_path: PathBuf,
    /// Its access trace, when it recorded one.
    traced: Option<TracedReplay>,
}

impl StackReplay {
    /// Whether the replay followed its schedule through event `event`, each
    /// event at its own position, so that a stack it took there is that
    /// event's: the scheduler counts the events it ran, so one it recorded
    /// that the schedule leaves out moves the positions after it.
    fn followed_through(&self, event: usize) -> bool {
        self.reached(event) && self.shifted_at.is_none_or(|shifted| shifted > event)
    }

    /// Whether the replay ran its schedule's events through event `event`,
    /// at whatever positions.
    fn reached(&self, event: usize) -> bool {
        match &self.left_schedule {
            None => true,
            Some(Departure::OtherEvent { index, .. }) => *index > event,
            Some(Departure::Ended { events }) => *events > event,
            Some(Departure::Unknown) => false,
        }
    }
}

/// Where a replay left the schedule it replayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Departure {
    /// At this event it ran another event than the schedule's: another
    /// thread, operation or instruction pointer, compared as the scheduler
    /// does when it takes a stack (the count and time aside).
    OtherEvent {
        index: usize,
        expected: SchedEvent,
        ran: SchedEvent,
    },
    /// It ended after this many events.
    Ended { events: usize },
    /// It recorded no schedule (a bound or a refusal stopped it).
    Unknown,
}

impl std::fmt::Display for Departure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Departure::OtherEvent {
                index,
                expected,
                ran,
            } => write!(
                f,
                "ran {ran} at event #{index}, where the schedule has {expected}"
            ),
            Departure::Ended { events } => write!(f, "ended after {events} events"),
            Departure::Unknown => write!(
                f,
                "did not finish (a bound or a refusal stopped it), so it recorded no schedule"
            ),
        }
    }
}

/// Whether `ran` is the event `expected`, as the replayer matches them: the
/// count and the time aside, an instruction pointer compared only where
/// `expected` has one, and the end's only where neither run took that
/// timeslice end without a stop (`SchedEvent::same_kind`). A replay records
/// the end of a slice a timer cut, which the recording it replays may leave
/// out; that is the same event.
fn same_event(expected: &SchedEvent, ran: &SchedEvent) -> bool {
    let rips_known = !(expected.stopless || ran.stopless);
    expected.dettid == ran.dettid
        && expected.op == ran.op
        && (expected.start_rip.is_none() || expected.start_rip == ran.start_rip)
        && (!rips_known || expected.end_rip.is_none() || expected.end_rip == ran.end_rip)
}

/// The first of the first `until` events of `requested` at which `realized`
/// ran another event, or ended: [`follow`]'s departure (the race report's
/// reading of a traced replay).
pub(super) fn departure(
    requested: &[SchedEvent],
    realized: &[SchedEvent],
    until: usize,
) -> Option<Departure> {
    follow(requested, realized, until).1
}

/// How `realized` follows the first `until` events of `requested`: the
/// position in `realized` of each requested event it ran, in order, and
/// where it left them, if it did. A replay can record a branch event its
/// schedule leaves out: the search's interleavings of two runs keep only the
/// events both runs share, and branch events whose counts differ are not
/// shared, yet the thread still runs those branches before its next event.
/// Such a branch event, on the thread the schedule runs next, is passed
/// over, not a departure.
fn follow(
    requested: &[SchedEvent],
    realized: &[SchedEvent],
    until: usize,
) -> (Vec<usize>, Option<Departure>) {
    let until = until.min(requested.len());
    let mut positions = Vec::with_capacity(until);
    let mut next = 0;
    for (index, expected) in requested[..until].iter().enumerate() {
        loop {
            match realized.get(next) {
                None => return (positions, Some(Departure::Ended { events: index })),
                Some(ran) if same_event(expected, ran) => break,
                Some(ran)
                    if ran.op == detcore_model::schedule::Op::Branch
                        && ran.dettid == expected.dettid =>
                {
                    next += 1;
                }
                Some(ran) => {
                    let departure = Departure::OtherEvent {
                        index,
                        expected: expected.clone(),
                        ran: ran.clone(),
                    };
                    return (positions, Some(departure));
                }
            }
        }
        positions.push(next);
        next += 1;
    }
    (positions, None)
}

/// How a stack-trace replay that realized `realized` followed `requested`
/// through the critical pair at `index - 1` and `index`: where it left it,
/// the first event it recorded at another position, and the threads it ran
/// at positions `index - 1` and `index`, where the scheduler, which counts
/// the events it ran, took its stacks.
fn replay_positions(
    requested: &[SchedEvent],
    realized: &[SchedEvent],
    index: usize,
) -> (Option<Departure>, Option<usize>, [Option<DetTid>; 2]) {
    let (positions, left_schedule) = follow(requested, realized, index + 1);
    let ran_at = |position: usize| realized.get(position).map(|event| event.dettid);
    let shifted_at = positions
        .iter()
        .enumerate()
        .position(|(event, position)| event != *position);
    (
        left_schedule,
        shifted_at,
        [ran_at(index - 1), ran_at(index)],
    )
}

/// The first event at which two realized schedules run different threads,
/// if both reach one: where two replays that share a schedule prefix part.
fn first_thread_difference(first: &[SchedEvent], second: &[SchedEvent]) -> Option<usize> {
    first
        .iter()
        .zip(second)
        .position(|(a, b)| a.dettid != b.dettid)
}

/// The thread a stack was taken on, as the guest numbers it (which is the
/// scheduler's numbering under Hermit's thread-id virtualization).
pub(super) fn stack_thread(stack: &PrettyBacktrace) -> Option<DetTid> {
    let thread = serde_json::to_value(stack)
        .ok()?
        .get("thread_id")?
        .as_i64()?;
    Some(DetTid::from_raw(i32::try_from(thread).ok()?))
}

/// The stacks of the two racing operations, in the passing schedule's order,
/// each with the replay it came from; `threads` are the threads of the
/// passing schedule's events `index - 1` and `index`. Those events are the
/// failing schedule's `index` and `index - 1`, so each stack can come from
/// either replay: preferably one that followed its schedule through that
/// event, else one taken on that operation's thread (the replay ran that
/// thread there, or the stack says so), said to be possibly another
/// occurrence of the operation. A stack taken on another thread is left
/// out: a replay that left its schedule can take one there.
fn merge_stacks(
    baseline: &StackReplay,
    target: &StackReplay,
    index: usize,
    threads: [DetTid; 2],
) -> [Option<(PrettyBacktrace, String)>; 2] {
    [0, 1].map(|slot| {
        let other = 1 - slot;
        let candidates = [
            ("the baseline replay", baseline, slot, index - 1 + slot),
            ("the target replay", target, other, index - 1 + other),
        ];
        candidates
            .iter()
            .find(|(_, replay, stack, event)| {
                replay.stacks[*stack].is_some() && replay.followed_through(*event)
            })
            .map(|(name, replay, stack, _)| {
                (replay.stacks[*stack].clone().unwrap(), (*name).to_owned())
            })
            .or_else(|| {
                candidates.iter().find_map(|(name, replay, stack, event)| {
                    let taken = replay.stacks[*stack].as_ref()?;
                    // The stack's own thread decides; without one, the
                    // thread the replay ran where it took the stack.
                    let taken_on = stack_thread(taken).or(replay.ran[*stack]);
                    (taken_on == Some(threads[slot])).then_some(())?;
                    let why = match &replay.left_schedule {
                        Some(_) if !replay.reached(*event) => "left its schedule",
                        _ => "recorded branch events its schedule leaves out",
                    };
                    Some((
                        taken.clone(),
                        format!(
                            "{name}, which {why} before this operation, so the stack may be \
                             another occurrence of it"
                        ),
                    ))
                })
            })
    })
}

/// Whether [`merge_stacks`] takes slot `slot`'s stack from a replay that
/// followed its schedule through that operation, each event at its own
/// position, so that the stack is that operation's.
fn exact_stack(baseline: &StackReplay, target: &StackReplay, index: usize, slot: usize) -> bool {
    let other = 1 - slot;
    (baseline.stacks[slot].is_some() && baseline.followed_through(index - 1 + slot))
        || (target.stacks[other].is_some() && target.followed_through(index - 1 + other))
}

/// The opening of an order-of-events report, true to what its stacks show,
/// and whether they show two threads racing. `threads` are the threads of
/// the two operations. Two operations of one thread are no interleaving;
/// two stacks taken on one thread, a stack taken on another thread than its
/// operation's, or a pair with a stack missing, do not show the race, and
/// the report says so instead of claiming one.
fn racing_pair_opening(
    threads: [DetTid; 2],
    stacks: [Option<&PrettyBacktrace>; 2],
) -> (String, bool) {
    let [first, second] = threads;
    if first == second {
        return (
            format!(
                "Both operations belong to thread {first}: swapping two events of one thread is \
                 not an interleaving, so they are not two threads racing.\n"
            ),
            false,
        );
    }
    let one_thread = matches!(
        stacks,
        [Some(one), Some(other)]
            if stack_thread(one).is_some() && stack_thread(one) == stack_thread(other)
    );
    let elsewhere = [0, 1].into_iter().find_map(|slot| {
        let taken_on = stack_thread(stacks[slot]?)?;
        (taken_on != threads[slot]).then_some((slot, taken_on))
    });
    if !one_thread && let Some((slot, taken_on)) = elsewhere {
        return (
            format!(
                "These two operations are on threads {first} and {second}, but stack{} was \
                 taken on thread {taken_on}, not thread {}, so the stacks do not show the two \
                 threads.\n",
                slot + 1,
                threads[slot]
            ),
            false,
        );
    }
    match stacks {
        [Some(one), Some(other)]
            if stack_thread(one).is_some() && stack_thread(one) == stack_thread(other) =>
        {
            (
                format!(
                    "These two operations are on threads {first} and {second}, but both stacks \
                     were taken on thread {}, so they do not show the two threads.\n",
                    stack_thread(one).unwrap_or(first)
                ),
                false,
            )
        }
        [Some(_), Some(_)] => (
            format!(
                "These two operations, on threads {first} and {second}, are RACING with each other.\n"
            ),
            true,
        ),
        [None, None] => (
            format!(
                "These two operations are on threads {first} and {second}; neither has a stack \
                 (see below), so this report cannot show them racing.\n"
            ),
            false,
        ),
        _ => (
            format!(
                "These two operations are on threads {first} and {second}; only one has a stack \
                 (see below), so this report cannot show both sides of the race.\n"
            ),
            false,
        ),
    }
}

/// The stacks of two operations the replays of the passing and failing
/// schedules realized, when those replays could not follow their schedules
/// through the critical pair: around `event`, the first event at which the
/// two realized schedules run different threads, `at[0]` in the passing one
/// and `at[1]` in the failing one ([`telling_event_at`]).
struct RealizedPair {
    event: usize,
    at: [Telling; 2],
    stacks: [PrettyBacktrace; 2],
}

/// What a [`RealizedPair`]'s stack of the replay `which` ("passing" or
/// "failing") shows, when not the thread that runs at `event` there.
fn telling_sentence(which: &str, slot: &str, event: usize, at: &Telling) -> Option<String> {
    let Telling {
        event: shown,
        thread,
        creator,
        starts,
        ends_at,
    } = *at;
    let mut sentence = match creator {
        Some(creator) => format!(
            "In the replay of the {which} schedule, thread {creator} at event #{event} only \
             returns from creating a thread, so {slot} is thread {thread}, which runs next"
        ),
        None if starts => {
            format!("In the replay of the {which} schedule, {slot} is thread {thread}")
        }
        None => return None,
    };
    if starts {
        let end = match ends_at {
            Some(sysno) => format!("at its {} call, where it blocks or waits", sysno.name()),
            None => "where it was preempted, at an arbitrary instruction".to_owned(),
        };
        sentence.push_str(&format!(
            ", which starts in that turn: it is shown where the turn ends, at event #{shown}, \
             {end}"
        ));
    } else {
        sentence.push_str(&format!(", at event #{shown}"));
    }
    sentence.push_str(".\n");
    Some(sentence)
}

/// Why the replays of the passing and failing schedules (`baseline`,
/// `target`) did not give the stacks of the critical pair at `index - 1` and
/// `index`, for a report whose stacks come from a [`RealizedPair`].
fn realized_pair_reason(baseline: &StackReplay, target: &StackReplay, index: usize) -> String {
    let departed = [("passing", baseline), ("failing", target)]
        .into_iter()
        .find_map(|(which, replay)| match &replay.left_schedule {
            Some(departure @ Departure::OtherEvent { index: at, .. }) if *at <= index => {
                Some((which, departure))
            }
            _ => None,
        });
    match departed {
        Some((which, departure)) => format!(
            "the replay of the {which} schedule {departure}. The passing and failing schedules \
             are the search's interleavings of the two runs, and this one cannot be realized \
             there"
        ),
        None if baseline.shifted_at.is_some() || target.shifted_at.is_some() => {
            "the replays recorded branch events the schedules leave out (the search's \
             interleavings keep only the events both runs share), so the stacks they took by \
             position are not those operations'"
                .to_owned()
        }
        None => "the stacks they took are not those operations'".to_owned(),
    }
}

/// The last component of `path`, as the report names a workspace file.
fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Why neither replay captured `which` (the stack at the passing schedule's
/// event `event`).
fn missing_stack_reason(
    which: &str,
    (event, target_event): (usize, usize),
    baseline: &StackReplay,
    target: &StackReplay,
) -> String {
    let describe =
        |replay: &StackReplay, event: usize| match (&replay.left_schedule, replay.shifted_at) {
            (Some(departure), _) if !replay.followed_through(event) => {
                format!("left its schedule: it {departure}")
            }
            (_, Some(shifted)) if shifted <= event => format!(
                "followed its schedule through event #{event}, but from event #{shifted} on it \
             recorded branch events the schedule leaves out, so its stacks were taken at other \
             events"
            ),
            _ => format!(
                "followed its schedule through event #{event}, but left no readable stack there"
            ),
        };
    let unfinished = [baseline, target]
        .iter()
        .any(|replay| replay.left_schedule == Some(Departure::Unknown));
    format!(
        "{which} is not available: no stack-trace replay captured that operation (event #{event} \
         of the passing schedule). The baseline replay {}; the target replay {}. {}",
        describe(baseline, event),
        describe(target, target_event),
        if unfinished {
            "A replay that did not finish was stopped by a bound (raise --trial-timeout) or \
             refused by Hermit (its reason is in its log file, or in analyze's output above \
             when it writes none)."
        } else {
            "Schedule replay did not reproduce these runs; check that they replay (--selfcheck) \
             on a host with an exact branch counter (hermit host-capabilities)."
        },
    )
}

/// The line of `text` that holds `pattern`'s first match.
fn matched_line<'a>(pattern: &Regex, text: &'a str) -> Option<&'a str> {
    let found = pattern.find(text)?;
    let start = text[..found.start()].rfind('\n').map_or(0, |at| at + 1);
    let end = text[found.start()..]
        .find('\n')
        .map_or(text.len(), |at| found.start() + at);
    Some(&text[start..end])
}

/// Whether the replay at workspace root `replay` met the criteria with
/// another failure than the target run at root `target`: whether the line
/// each output pattern (`patterns`, by stream) matches differs between them.
/// Output the patterns do not match may differ with the interleaving and is
/// not compared.
fn changed_output(
    target: &Path,
    replay: &Path,
    patterns: [(&str, Option<&Regex>); 2],
) -> Option<String> {
    patterns.into_iter().find_map(|(stream, pattern)| {
        let pattern = pattern?;
        let read = |root: &Path| {
            std::fs::read(root.with_extension(stream))
                .ok()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        };
        let (want, got) = (read(target)?, read(replay)?);
        let (want, got) = (matched_line(pattern, &want)?, matched_line(pattern, &got)?);
        (want != got).then(|| {
            format!(
                "the final target schedule meets the target criteria with another failure than \
                 the target run: the {stream} line that --target-{stream} matches is {got:?}, \
                 where the target run's is {want:?}. The critical pair may belong to that other \
                 failure; narrow --target-{stream} to tell them apart."
            )
        })
    })
}

impl AnalyzeOpts {
    /// The branch-count difference two replays of one control schedule may
    /// show and still count as one realized trace
    /// (`schedule_search::Config::max_branch_count_jitter`): on a host whose
    /// branch counter is not exact only, which analyze says. Elsewhere the two
    /// must be identical, event times included.
    fn replay_branch_jitter(&self) -> Option<u32> {
        let reason = (self.inexact_branch_counter)()?;
        eprintln!(
            ":: {} this host's branch counter is not exact ({reason}), so two replays of one \
             schedule count as the same trace when their branch counts differ by at most {}",
            "NOTE:".yellow().bold(),
            INEXACT_COUNTER_BRANCH_JITTER
        );
        Some(INEXACT_COUNTER_BRANCH_JITTER)
    }

    /// The default search's configuration: `--verbose`, `--run-needleman`,
    /// `--jitter-dist`, and the branch-count difference two replays of one
    /// control schedule may show, on a host whose branch counter is not exact
    /// only ([`Self::replay_branch_jitter`]).
    fn bisect_config(&self) -> Config {
        let mut cfg = Config {
            verbose: self.verbose,
            needleman_search: self.run_needleman,
            max_branch_count_jitter: self.replay_branch_jitter(),
            ..Default::default()
        };
        if let Some(dist) = self.jitter_dist {
            cfg.max_jitter_editdist = dist;
            cfg.max_jitter_swapdist = dist * dist;
        }
        cfg
    }

    pub fn get_tmp(&self) -> anyhow::Result<&Path> {
        if let Some(pb) = &self.tmp_dir {
            Ok(pb.as_path())
        } else {
            bail!("Expected tmp_dir to be set at this point!")
        }
    }

    /// The chaos run of `--search` round `round`, with schedule seed
    /// `sched_seed`. The one that matches becomes the target, whose log
    /// `--selfcheck` compares.
    pub(super) fn search_run(&self, round: u64, sched_seed: u64) -> anyhow::Result<RunData> {
        let runname = format!("search_round_{:0wide$}", round, wide = 3);
        let mut rundat = RunData::new_baseline(self, runname)?
            .with_preemption_recording()
            .compared_by_selfcheck();
        rundat.runopts.det_opts.det_config.sched_seed = Some(sched_seed);
        if self.imprecise_search {
            rundat.runopts.det_opts.det_config.imprecise_timers = true; // TODO: enable this by default when bugs are fixed.
        }
        Ok(rundat)
    }

    /// Launch a chaos run searching for a target (e.g. failing) schudule.
    /// Returns Some if a target schedule is found.
    fn launch_search(&self, round: u64, sched_seed: u64) -> Result<Option<RunData>, Error> {
        yellow_msg(&format!(
            "Searching (round {}) for a target execution, chaos --sched-seed={} ",
            round, sched_seed
        ));
        let mut rundat = self.search_run(round, sched_seed)?;
        if rundat.launch_trial()?.reached_target() {
            eprintln!(
                ":: {}:\n    {}",
                "Target run established by --search. Reproducer"
                    .green()
                    .bold(),
                rundat.to_repro(),
            );
            Ok(Some(rundat))
        } else {
            Ok(None)
        }
    }

    /// The run that replays the preemptions in `preempts_path`, as a
    /// `--minimize` round does.
    pub(super) fn preempts_replay_run(
        &self,
        runname: &str,
        preempts_path: &Path,
    ) -> anyhow::Result<RunData> {
        Ok(RunData::new_baseline(self, runname.to_string())?
            .with_edited_preempts_path_in(preempts_path.to_path_buf())
            .compared_by_selfcheck())
    }

    /// `run` replaying the target's preemption record at `path`: one
    /// minimization edited when `--minimize` ran, which replays as edited
    /// ([`RunData::with_edited_preempts_path_in`]); otherwise the target
    /// run's recording, which replays strictly.
    fn replaying_the_target_record(&self, run: RunData, path: PathBuf) -> RunData {
        if self.minimize {
            run.with_edited_preempts_path_in(path)
        } else {
            run.with_preempts_path_in(path)
        }
    }

    // TODO: REMOVE. Only used by minimize atm.
    //
    /// Launch a run with preempts provided (to replay). Return true if it matches the
    /// criteria. If provided, additionally record full schedule events from the run to
    /// `record_sched_path`. The last of these runs to match is the minimized target, whose log
    /// --selfcheck compares.
    pub(super) fn launch_from_preempts_to_sched(
        &self,
        runname: &str,
        preempts_path: &Path,
        record_sched_path: Option<&Path>,
    ) -> anyhow::Result<(bool, RunOpts)> {
        let mut run = self.preempts_replay_run(runname, preempts_path)?;
        if let Some(path) = record_sched_path {
            run = run.with_schedule_recording_to(path.to_path_buf());
        }
        let is_match = run.launch_trial()?.reached_target();
        Ok((is_match, run.into_runopts()))
    }

    /// The stacks of where the replays of the passing and failing schedules
    /// (`baseline`, `target`) part: the first event at which their realized
    /// schedules run different threads, each from a replay of that realized
    /// schedule, which follows it exactly. Otherwise why not: they do not
    /// part before one of them ends, a replay does not take a stack there on
    /// that event's thread, or it fails to run. A fallback never fails the
    /// analysis.
    fn realized_pair(
        &self,
        baseline: &StackReplay,
        target: &StackReplay,
    ) -> Result<RealizedPair, String> {
        let Some(event) = first_thread_difference(&baseline.realized, &target.realized) else {
            return Err(
                "the schedules the two replays realized do not run different threads at any \
                 event both reach"
                    .to_owned(),
            );
        };
        let mut stacks = Vec::with_capacity(2);
        let mut tellings = Vec::with_capacity(2);
        for (runname, replay, other) in [
            ("final_baseline_realized_for_stacktraces", baseline, target),
            ("final_target_realized_for_stacktraces", target, baseline),
        ] {
            let telling = telling_event_at(&replay.realized, event, other.realized[event].dettid)
                .expect("both reach the event");
            let at = telling.event;
            // The replay also asks for the stack at the next event, which
            // must exist.
            if at + 1 >= replay.realized.len() {
                return Err(format!(
                    "the schedule {} realized ends at event #{at}",
                    file_name(&replay.realized_path)
                ));
            }
            let again = self
                .replay_for_stacks(
                    runname,
                    &replay.realized_path,
                    &replay.realized,
                    at + 1,
                    None,
                )
                .map_err(|error| format!("the replay {runname} failed to run ({error:#})"))?;
            let thread = telling.thread;
            match &again.stacks[0] {
                Some(stack)
                    if again.followed_through(at) && stack_thread(stack) == Some(thread) =>
                {
                    stacks.push(stack.clone());
                    tellings.push(telling);
                }
                _ => {
                    return Err(format!(
                        "the replay {runname} of a realized schedule did not take thread \
                         {thread}'s stack at its event #{at}"
                    ));
                }
            }
        }
        let [first, second]: [PrettyBacktrace; 2] = stacks.try_into().expect("two replays");
        let at: [Telling; 2] = tellings.try_into().expect("two replays");
        Ok(RealizedPair {
            event,
            at,
            stacks: [first, second],
        })
    }

    /// Replay `schedule` (written at `schedule_path`) for the stacks of the
    /// critical pair, its events `index - 1` and `index`, recording the
    /// schedule the replay realized. A replay that a bound stops or Hermit
    /// refuses still returns what it captured.
    fn replay_for_stacks(
        &self,
        runname: &str,
        schedule_path: &Path,
        schedule: &[SchedEvent],
        index: usize,
        trace: Option<(&'static str, u64)>,
    ) -> anyhow::Result<StackReplay> {
        let run = RunData::new_baseline(self, runname.to_string())?
            .with_schedule_replay_from(schedule_path.to_path_buf())
            .with_schedule_recording();
        let (role, from) = trace.unzip();
        let (mut run, request) = self.request_trace(run, role.unwrap_or_default(), from);
        let root_path = run.root_path();
        let realized = run.sched_path_out().to_path_buf();
        let paths = [
            root_path.with_extension("stack1"),
            root_path.with_extension("stack2"),
        ];
        run.runopts.det_opts.det_config.stacktrace_event = vec![
            (index as u64 - 1, Some(paths[0].clone())),
            (index as u64, Some(paths[1].clone())),
        ];
        let finished = match run.launch() {
            Ok(()) => true,
            Err(error)
                if error.downcast_ref::<RunTimeoutMarker>().is_some()
                    || error.downcast_ref::<VirtualBoundStop>().is_some()
                    || guest_reached_a_refusal(&error) =>
            {
                eprintln!(
                    ":: {} the stack-trace replay {runname} did not finish ({error:#}); \
                     using the stacks it recorded",
                    "WARNING:".yellow().bold(),
                );
                false
            }
            Err(error) => return Err(error),
        };
        eprintln!(
            "\n:: {}\n{}",
            if finished {
                "Stack-trace replay finished.  Repro command:"
            } else {
                "Stack-trace replay stopped.  Repro command:"
            }
            .green()
            .bold(),
            run.to_repro()
        );
        let mut stacks = [None, None];
        for (stack, path) in stacks.iter_mut().zip(&paths) {
            let Ok(file) = File::open(path) else {
                continue;
            };
            match serde_json::from_reader(file) {
                Ok(parsed) => *stack = Some(parsed),
                Err(error) => eprintln!(
                    ":: {} cannot read the stack trace in {} ({error}); it is left out",
                    "WARNING:".yellow().bold(),
                    path.display()
                ),
            }
        }
        let realized_path = realized;
        let realized = if realized_path.exists() {
            PreemptionReader::new(&realized_path)
                .load_all()
                .into_global()
        } else {
            Vec::new()
        };
        let (left_schedule, shifted_at, ran) = if realized_path.exists() {
            replay_positions(schedule, &realized, index)
        } else {
            (Some(Departure::Unknown), None, [None, None])
        };
        let traced = request.map(|request| {
            request.ran_with(left_schedule.clone(), realized.clone(), &realized_path)
        });
        Ok(StackReplay {
            finished,
            met_target: finished && run.is_a_match(),
            stacks,
            left_schedule,
            shifted_at,
            ran,
            realized,
            realized_path,
            traced,
        })
    }

    /// One `--prefix-search` trial: replay the first `len` events of `target`,
    /// then let the scheduler go on without chaos, with timeslices of
    /// `continuation`. The trial's record keeps the callback checkpoints
    /// within the prefix ([`PreemptionRecord::schedule_prefix`]), so its
    /// slices end where the recording's did, all but the one running at the
    /// prefix's end: where that slice ends decides what runs next, which is
    /// event `len`'s decision. A trial that replayed it would already make
    /// that decision, and the search would name the event before it, with
    /// the thread that ran up to it on both sides of the pair.
    fn prefix_trial(
        &self,
        runname: &str,
        target: &PreemptionRecord,
        len: usize,
        continuation: MaybeTimeslice,
    ) -> anyhow::Result<RunData> {
        let mut run = RunData::new_baseline(self, runname.to_string())?;
        run.runopts.det_opts.det_config.chaos = false;
        run.runopts.det_opts.det_config.max_timeslice = continuation;
        let path = run.sched_path_in().to_path_buf();
        self.write_trial_record(target.schedule_prefix(len), &path)?;
        Ok(run.with_schedule_replay_from(path))
    }

    /// Launch a prefix trial and say how it ended. A trial that a wall-clock
    /// bound ends, or that Hermit refuses, did not reach the target.
    fn launch_prefix_trial(&self, run: &mut RunData) -> anyhow::Result<TrialEnd> {
        if self.verbose {
            eprintln!(
                ":: {}\n    {}",
                "Prefix trial, repro command:".yellow().bold(),
                run.to_repro()
            );
        }
        run.launch_trial()
    }

    /// `--prefix-search`: find the shortest prefix of the target schedule that,
    /// replayed and then continued without chaos, still meets the target
    /// criteria. Returns the index of that prefix's last event.
    pub fn phase5_prefix_search(
        &mut self,
        target_record: &PreemptionRecord,
    ) -> anyhow::Result<PrefixDecision> {
        let target = target_record.schedevents();
        let candidates = match self.continuation_timeslice {
            ContinuationTimeslice::Auto => continuation_candidates(self.trial_max_timeslice()),
            ContinuationTimeslice::Nanos(nanos) => vec![Some(nanos)],
        };
        self.progress.phase(Phase::PrefixSearch);
        let mut trial = 0;
        let mut refused = 0;
        let ends = std::cell::RefCell::new(Ends::new());
        // The run of each prefix's last trial, per continuation.
        let mut runs = BTreeMap::new();
        // For each prefix confirmed, the bound its trial ran under before and
        // the one the confirmation ran under, in seconds.
        let confirmations = std::cell::RefCell::new(BTreeMap::new());
        let bound_of = |len: usize, continuation: MaybeTimeslice| {
            ends.borrow()
                .get(&(len, continuation))
                .and_then(|&(_, bound)| bound)
        };
        let mut run_trial = |len: usize,
                             continuation: MaybeTimeslice,
                             purpose: TrialPurpose|
         -> anyhow::Result<Option<TrialEnd>> {
            let mut raised = false;
            if purpose == TrialPurpose::Confirm {
                let earlier = bound_of(len, continuation);
                let longer = match confirmation_bound(
                    self.confirmation_bound(),
                    self.trial_bound_factor,
                    self.effective_trial_bound(),
                    earlier,
                ) {
                    ConfirmationBound::Raise(longer) => {
                        self.trial_bound_factor = CONFIRM_BOUND_FACTOR;
                        raised = true;
                        longer
                    }
                    ConfirmationBound::Rerun(now) => now,
                    ConfirmationBound::Unavailable => {
                        eprintln!(
                            ":: The search settled next to the prefix of {len} events, whose \
                             trial {}; no longer bound can be given to confirm it",
                            describe_trial_end(TrialEnd::Unfinished(Stop::Bound), earlier),
                        );
                        return Ok(None);
                    }
                };
                eprintln!(
                    ":: The search settled next to the prefix of {len} events, whose trial {}; \
                     running it again with a bound of {longer} s, so that a finished trial \
                     decides the boundary",
                    describe_trial_end(TrialEnd::Unfinished(Stop::Bound), earlier),
                );
                confirmations.borrow_mut().insert(len, (earlier, longer));
            }
            trial += 1;
            let runname = format!("prefix_round_{trial:03}");
            let mut run = self.prefix_trial(&runname, target_record, len, continuation)?;
            let bound = run.runopts.run_timeout().map(|bound| bound.as_secs());
            let end = self.launch_prefix_trial(&mut run)?;
            if purpose == TrialPurpose::Confirm {
                if end == TrialEnd::Met && len > 0 {
                    eprintln!(
                        ":: Given longer, it met the target: the boundary is below it, and runs \
                         from here on get the longer bound"
                    );
                }
                self.trial_bound_factor =
                    factor_after_confirmation(self.trial_bound_factor, raised, end);
            }
            refused += usize::from(end == TrialEnd::Unfinished(Stop::Refusal));
            eprintln!(
                ":: Prefix of {len} of {} events => {}",
                target.len(),
                match end {
                    TrialEnd::Met => format!("target condition ({})", self.display_criteria()),
                    TrialEnd::Missed => "baseline condition".to_string(),
                    TrialEnd::Unfinished(_) => format!(
                        "no outcome: it {}, counted as not meeting the target",
                        describe_trial_end(end, bound)
                    ),
                }
            );
            ends.borrow_mut().insert((len, continuation), (end, bound));
            runs.insert((len, continuation), runname);
            self.progress.bracket(prefix_bracket(
                &ends.borrow(),
                &runs,
                continuation,
                target.len(),
            ));
            Ok(Some(end))
        };
        let ended = "a search trial always ends one way or another";

        let continuation = choose_continuation(&candidates, target.len(), |len, continuation| {
            run_trial(len, continuation, TrialPurpose::Search)?.context(ended)
        })?;
        eprintln!(
            ":: Searching the prefixes continued without chaos {}",
            describe_continuation(continuation)
        );
        let empty = ends.borrow()[&(0, continuation)].0;
        let searched = search_prefix_boundary(target.len(), empty, |len, purpose| {
            run_trial(len, continuation, purpose)
        });
        let Boundary {
            passing,
            passing_end,
        } = match searched {
            Err(error) if error.downcast_ref::<EmptyPrefixMeetsTarget>().is_some() => {
                return Err(empty_prefix_verdict(&error, &candidates, continuation).into());
            }
            searched => searched?,
        };
        let failing = passing + 1;
        // On a host whose branch counter is not exact, two replays of one
        // prefix can differ, so the boundary is checked once more. A trial
        // the wall-clock bound stopped has no outcome to repeat, so such a
        // baseline side is not run again, and a check that bound stops shows
        // a trial close to the bound, not another outcome. A stop at the
        // virtual-time bound repeats like an outcome, and is checked as one:
        // a run of it that ends otherwise did not repeat.
        let mut rechecks = vec![(failing, TrialEnd::Met)];
        if passing_end != TrialEnd::Unfinished(Stop::Bound) {
            rechecks.insert(0, (passing, passing_end));
        }
        let (mut changed, mut unfinished_again) = (Vec::new(), Vec::new());
        for (len, first) in rechecks {
            let first_bound = bound_of(len, continuation);
            let again = run_trial(len, continuation, TrialPurpose::Search)?.context(ended)?;
            let what = || {
                format!(
                    "the prefix of {len} events {} and then {}",
                    describe_trial_end(first, first_bound),
                    describe_trial_end(again, bound_of(len, continuation))
                )
            };
            match recheck(first, again) {
                Recheck::Repeated => {}
                Recheck::CloseToTheBound => unfinished_again.push(what()),
                Recheck::Other => {
                    changed.push(what());
                    // As before: one other outcome is enough to warn.
                    break;
                }
            }
        }
        if !changed.is_empty() {
            eprintln!(
                ":: {} replaying the prefixes of {passing} and {failing} events again gave other \
                 outcomes ({}); the decision below may not repeat",
                "WARNING:".yellow().bold(),
                changed.join("; ")
            );
        }
        if !unfinished_again.is_empty() {
            eprintln!(
                ":: {} {}: these trials run close to their wall-clock bound, so the search may \
                 have counted trials that meet the target given longer as not meeting it, and an \
                 earlier event decide the outcome ({})",
                "WARNING:".yellow().bold(),
                unfinished_again.join("; "),
                bound_remedy(
                    self.run_args_timeout(),
                    self.trial_timeout == TrialTimeout::Off,
                    self.effective_trial_bound(),
                )
            );
        }
        let refused = refused_trials_warning(refused);
        if let Some(warning) = &refused {
            eprintln!(":: {} {warning}", "WARNING:".yellow().bold());
        }
        let unfinished = matches!(
            passing_end,
            TrialEnd::Unfinished(Stop::Bound | Stop::VirtualBound(_))
        )
        .then(|| {
            let below = longest_finished_below(&ends.borrow(), continuation, passing);
            let confirmed = confirmations.borrow().get(&passing).copied();
            let (bound, longer) = match confirmed {
                Some((earlier, longer)) => (earlier, Some(longer)),
                None => (bound_of(passing, continuation), None),
            };
            let remedy = match passing_end {
                TrialEnd::Unfinished(Stop::VirtualBound(nanos)) => virtual_bound_remedy(
                    self.run_args_virtual_timeout(),
                    self.current_trial_virtual_bound(),
                    nanos,
                ),
                _ => bound_remedy(
                    self.run_args_timeout(),
                    self.trial_timeout == TrialTimeout::Off,
                    longer.or(bound),
                ),
            };
            unfinished_boundary_warning(passing, passing_end, bound, longer, below, remedy)
        });
        if let Some(warning) = &unfinished {
            eprintln!(":: {} {warning}", "WARNING:".yellow().bold());
        }
        eprintln!(
            ":: The scheduling decision at event #{passing} of {} decides the outcome: {}",
            target.len(),
            target[passing]
        );
        Ok(PrefixDecision {
            schedule: target_record.clone(),
            decision: passing,
            refused,
            unfinished,
            continuation,
        })
    }

    /// Replay the first `len` events of `schedule` as a prefix trial and
    /// return whether it met the target with the stack at schedule position
    /// `position`: a replayed event, or, at `len`, the first event the
    /// scheduler ran after the prefix.
    fn prefix_stack(
        &self,
        runname: &str,
        schedule: &PreemptionRecord,
        len: usize,
        position: usize,
        continuation: MaybeTimeslice,
    ) -> anyhow::Result<(bool, Option<PrettyBacktrace>)> {
        let (is_match, stack, _) =
            self.traced_prefix_stack(runname, schedule, len, position, continuation, None)?;
        Ok((is_match, stack))
    }

    /// [`Self::prefix_stack`] for the target side of the report: with
    /// `trace_from` set, the trial also records its schedule and an access
    /// trace from that event.
    fn traced_prefix_stack(
        &self,
        runname: &str,
        schedule: &PreemptionRecord,
        len: usize,
        position: usize,
        continuation: MaybeTimeslice,
        trace_from: Option<u64>,
    ) -> anyhow::Result<(bool, Option<PrettyBacktrace>, Option<TracedReplay>)> {
        let run = self.prefix_trial(runname, schedule, len, continuation)?;
        let (mut run, request) = self.request_trace(run, "target", trace_from);
        let stack_path = run.root_path().with_extension("stack");
        run.runopts.det_opts.det_config.stacktrace_event =
            vec![(position as u64, Some(stack_path.clone()))];
        let is_match = self.launch_prefix_trial(&mut run)?.reached_target();
        eprintln!(
            ":: {}\n{}",
            "Stack-trace run completed.  Repro command:".green().bold(),
            run.to_repro()
        );
        let stack = match File::open(&stack_path) {
            Ok(file) => Some(serde_json::from_reader(file).with_context(|| {
                format!("cannot parse the stack trace in {}", stack_path.display())
            })?),
            Err(_) => None,
        };
        let traced = request.map(|request| {
            let realized = run.sched_path_out().to_path_buf();
            request.ran(schedule.schedevents(), &realized, len)
        });
        Ok((is_match, stack, traced))
    }

    /// The schedule a prefix trial of the first `len` events of `schedule`
    /// realized: the replayed events, then the events the scheduler ran after
    /// them, and the file it is recorded in. Empty if the trial wrote no
    /// schedule (it did not finish).
    fn prefix_continuation(
        &self,
        runname: &str,
        schedule: &PreemptionRecord,
        len: usize,
        continuation: MaybeTimeslice,
        trace: Option<(&'static str, u64)>,
    ) -> anyhow::Result<(Vec<SchedEvent>, PathBuf, Option<TracedReplay>)> {
        let run = self
            .prefix_trial(runname, schedule, len, continuation)?
            .with_schedule_recording();
        let (role, from) = trace.unzip();
        let (mut run, request) = self.request_trace(run, role.unwrap_or_default(), from);
        let path = run.sched_path_out().to_path_buf();
        self.launch_prefix_trial(&mut run)?;
        let realized = if path.exists() {
            PreemptionReader::new(&path).load_all().into_global()
        } else {
            Vec::new()
        };
        let traced = request.map(|request| request.ran(schedule.schedevents(), &path, len));
        Ok((realized, path, traced))
    }

    /// These options with the journal off, for a run that must never be a
    /// search answer: a race candidate's check. The budget and the progress
    /// stay shared, so --time-budget and --trial-budget still bound it and
    /// its verdict goes into the progress's own section.
    pub(super) fn unjournaled(&self) -> AnalyzeOpts {
        AnalyzeOpts {
            journal: Journal::default(),
            ..self.clone()
        }
    }

    /// The report's "Racing accesses" section for a prefix decision at
    /// `decision`: `target` replayed the first `len` events of `schedule` and
    /// `baseline` one fewer, both then continuing at `continuation`. The
    /// stacks come from a replay of the target's continuation. `None` when a
    /// side recorded no trace (`--no-racing-accesses`). `target_met`: whether
    /// the target replay met the target.
    fn prefix_racing_accesses(
        &self,
        decision: usize,
        (schedule, len, continuation): (&PreemptionRecord, usize, MaybeTimeslice),
        target: Option<TracedReplay>,
        baseline: Option<TracedReplay>,
        target_met: bool,
    ) -> Option<RacingAccesses> {
        let (target, baseline) = (target?, baseline?);
        let record = continued_record(schedule, len, &target.realized);
        let racing = self.racing_accesses(
            decision,
            target,
            baseline,
            target_met,
            |runname| self.prefix_trial(runname, &record, record.schedevents().len(), continuation),
            // A candidate's check replays a schedule of the run it checks
            // under the callback checkpoints of that run's prefix, up to where
            // the edit starts, then continues as the search's trials did.
            |runname, role, edited, unchanged, replay| {
                let edited =
                    continued_record(schedule, check_prefix_len(len, role, unchanged), edited);
                self.unjournaled()
                    .prefix_trial(runname, &edited, replay, continuation)
            },
        );
        Some(racing)
    }

    /// The report of `--prefix-search`: the stacks of the two threads that
    /// could run at the deciding event.
    pub fn phase6_record_prefix_outputs(&self, found: PrefixDecision) -> anyhow::Result<Report> {
        let PrefixDecision {
            schedule,
            decision,
            refused,
            unfinished,
            continuation,
        } = found;
        self.progress.phase(Phase::StackTraces);
        self.progress.decided(
            format!(
                "event #{decision} of the target schedule decides the outcome ({})",
                schedule.schedevents()[decision]
            ),
            DecidedEvents::Deciding(decision),
        );
        let mut notes: Vec<String> = [refused, unfinished.clone()]
            .into_iter()
            .flatten()
            .collect();
        let trace_from = self.race_trace_from(decision);
        let (target_met, chosen, target_trace) = self.traced_prefix_stack(
            "final_target_for_stacktraces",
            &schedule,
            decision + 1,
            decision,
            continuation,
            trace_from,
        )?;
        // The thread the scheduler runs at event #decision once the prefix
        // ends. `--stacktrace-event` names a position of the replayed schedule
        // only, so the prefix trial without event #decision runs first with its
        // schedule recorded, and the stack is taken from a replay of that
        // schedule's first decision + 1 events.
        let (continued, continued_path, mut baseline_trace) = self.prefix_continuation(
            "final_baseline_schedule",
            &schedule,
            decision,
            continuation,
            trace_from.map(|from| ("baseline", from)),
        )?;
        let thread = schedule.schedevents()[decision].dettid;
        let same_thread = continued
            .get(decision)
            .is_some_and(|event| event.dettid == thread);
        // With the same thread there either way, the continuation with the
        // event shows what it changes.
        let mut target_continued = if same_thread {
            Some(self.prefix_continuation(
                "final_target_schedule",
                &schedule,
                decision + 1,
                continuation,
                trace_from.map(|from| ("target", from)),
            )?)
        } else {
            None
        };
        if let Some((target_continued, target_continued_path, continued_trace)) =
            &mut target_continued
            && let Some(report) = self.report_timing_decision(
                &schedule,
                decision,
                continuation,
                (target_met, &chosen),
                (
                    ((&continued, &continued_path), &mut baseline_trace),
                    ((target_continued, target_continued_path), continued_trace),
                ),
                &notes,
            )?
        {
            return Ok(report);
        }
        let plan = stack2_plan(
            thread,
            decision,
            &continued,
            target_continued
                .as_ref()
                .map(|(with, _, _)| with.as_slice()),
        );
        let (at, moved) = match &plan {
            Stack2Plan::Instead { at, partner } => (*at, partner.clone()),
            _ => (decision, None),
        };
        let mut partner = None;
        let (baseline_met, instead) = if continued.len() > decision {
            let baseline = continued_record(&schedule, decision, &continued);
            let (met, stack) = self.prefix_stack(
                "final_baseline_for_stacktraces",
                &baseline,
                at + 1,
                at,
                continuation,
            )?;
            match moved {
                Some(moved)
                    if at != decision
                        && stack.as_ref().and_then(stack_thread) != Some(moved.thread) =>
                {
                    notes.push(format!(
                        "the replay of the continuation without the event took no stack of thread \
                         {} at event #{at}, so stack2 is empty",
                        moved.thread
                    ));
                    (met, None)
                }
                Some(moved) if at != decision => {
                    partner = Some(moved);
                    (met, stack)
                }
                _ => (met, stack),
            }
        } else if unfinished.is_some() && continued.is_empty() {
            eprintln!(
                ":: {} the run without event #{decision} did not finish and recorded no \
                 schedule, so stack2 is empty",
                "Note:".yellow().bold(),
            );
            (false, None)
        } else {
            eprintln!(
                ":: {} the run without event #{decision} ended after {} events, so no thread \
                 runs there instead and stack2 is empty",
                "WARNING:".yellow().bold(),
                continued.len()
            );
            (false, None)
        };
        // Without the event the scheduler runs the same thread there: stack2
        // is then the first thread whose turn differs between the two
        // continuations, or, when they do not differ before one ends, the
        // thread that runs after its slice without the event, so the two
        // stacks are two threads.
        let mut next_thread = None;
        let mut instead = instead;
        if let Stack2Plan::Changed(changed) = plan {
            let (runname, record) = match changed.side {
                Side::With => (
                    "final_target_next_for_stacktraces",
                    continued_record(
                        &schedule,
                        decision + 1,
                        &target_continued
                            .as_ref()
                            .expect("a continuation with the event")
                            .0,
                    ),
                ),
                Side::Without => (
                    "final_baseline_next_for_stacktraces",
                    continued_record(&schedule, decision, &continued),
                ),
            };
            match self.prefix_stack(
                runname,
                &record,
                changed.event + 1,
                changed.event,
                continuation,
            ) {
                Ok((_, Some(stack))) if stack_thread(&stack) == Some(changed.thread) => {
                    next_thread = Some((changed.event, changed.thread));
                    instead = Some(stack);
                    partner = Some(changed);
                }
                Ok(_) => notes.push(format!(
                    "the replay of the continuation {} the event took no stack of thread {} at \
                     event #{}, so stack2 is thread {thread} there",
                    changed.side.name(),
                    changed.thread,
                    changed.event,
                )),
                Err(error) => notes.push(format!(
                    "the replay for thread {}'s stack at event #{} failed to run ({error:#}), so \
                     stack2 is thread {thread} there",
                    changed.thread, changed.event,
                )),
            }
        } else if let Stack2Plan::NextSlice {
            index,
            thread: next,
        } = plan
        {
            let baseline = continued_record(&schedule, decision, &continued);
            match self.prefix_stack(
                "final_baseline_next_for_stacktraces",
                &baseline,
                index + 1,
                index,
                continuation,
            ) {
                Ok((_, Some(stack))) if stack_thread(&stack) == Some(next) => {
                    next_thread = Some((index, next));
                    instead = Some(stack);
                }
                Ok(_) => notes.push(format!(
                    "the replay of the continuation without the event took no stack of thread \
                     {next} at event #{index}, so stack2 is thread {thread} there"
                )),
                Err(error) => notes.push(format!(
                    "the replay for thread {next}'s stack at event #{index} failed to run \
                     ({error:#}), so stack2 is thread {thread} there"
                )),
            }
        }
        if !target_met || baseline_met {
            eprintln!(
                ":: {} the stack-trace runs did not repeat the search's outcomes (target met: {}, \
                 baseline met: {}); read the stacks with care",
                "WARNING:".yellow().bold(),
                target_met,
                baseline_met
            );
        }

        let misses = if unfinished.is_some() {
            "does not finish, which the search counts as not meeting the target criteria (a hang, \
             see the note below)"
        } else {
            "does not meet the target criteria"
        };
        let mut header = format!(
            "The scheduling decision at event #{decision} of the target schedule decides the \
             outcome.\nReplaying the first {decision} events and then scheduling without chaos \
             {} {misses}; replaying event #{decision} too ({}) meets them ({}).\n",
            describe_continuation(continuation),
            schedule.schedevents()[decision],
            self.display_criteria()
        );
        if unfinished.is_some() && continued.is_empty() {
            header.push_str(
                "stack1 is the thread the target schedule runs at that point; stack2 is empty: the \
                 run without the event did not finish and recorded no schedule.\nWithout the event \
                 the guest may wait for something that never comes: look for the wait it hangs in \
                 (a lock or a join that nothing releases), which the event avoids.\n",
            );
        } else {
            header.push_str(&stack_pair_sentences(
                thread,
                continued.get(decision).map(|event| event.dettid),
                next_thread,
                partner.as_ref(),
            ));
        }
        for note in &notes {
            header.push_str(&format!("Note: {note}\n"));
        }
        let context = Self::generate_context(
            schedule.schedevents(),
            decision.max(1),
            self.execution_context,
        );
        let racing_accesses = self.prefix_racing_accesses(
            decision,
            (&schedule, decision + 1, continuation),
            target_trace,
            baseline_trace,
            target_met,
        );

        println!(
            "\n------------------------------ hermit analyze report ------------------------------"
        );
        if let Some(warning) = &self.branch_counter_warning {
            println!("{warning}");
        }
        println!("{}", header);
        Self::print_stack("stack1", &chosen);
        Self::print_stack("stack2", &instead);
        Self::print_racing_accesses(&racing_accesses);
        println!("\n{}", context);

        Ok(Report {
            verdict: Verdict::CriticalEvents,
            verdict_reason: None,
            header,
            additional_context: context,
            baseline_run: false,
            critical_event1: Some(ReportCriticalEvent {
                event_index: decision,
                stack: chosen,
            }),
            critical_event2: Some(ReportCriticalEvent {
                event_index: partner
                    .as_ref()
                    .map(|partner| partner.event)
                    .or(next_thread.map(|(index, _)| index))
                    .unwrap_or(decision),
                stack: instead,
            }),
            branch_counter_warning: self.branch_counter_warning.clone(),
            deciding_event: None,
            partial: None,
            racing_accesses,
        })
    }

    /// The report of `--prefix-search` when the scheduler runs the same
    /// thread at the deciding event without it (`continued`, recorded at
    /// `continued_path`, is the schedule without it; `target_continued`, at
    /// `target_continued_path`, the one with it) as the target schedule
    /// does: the decision is how long that thread runs, so the report shows
    /// the thread that runs next in each continuation, and the deciding
    /// thread's own stack (`deciding`, from a trial that met the target or
    /// not) separately. `None` when the continuation with the event does not
    /// bear that out (it does not run the thread there, or the thread runs
    /// exactly as long in both): the usual report follows.
    fn report_timing_decision(
        &self,
        schedule: &PreemptionRecord,
        decision: usize,
        continuation: MaybeTimeslice,
        (target_met, deciding): (bool, &Option<PrettyBacktrace>),
        (
            ((continued, continued_path), baseline_trace),
            ((target_continued, target_continued_path), target_trace),
        ): (TracedContinuation<'_, '_>, TracedContinuation<'_, '_>),
        notes: &[String],
    ) -> anyhow::Result<Option<Report>> {
        let events = schedule.schedevents();
        let thread = events[decision].dettid;
        let with = slice_from(target_continued, decision, thread);
        let without = slice_from(continued, decision, thread);
        if with.events == 0 || (with.events, with.branches) == (without.events, without.branches) {
            eprintln!(
                ":: {} without event #{decision} the scheduler runs thread {thread} there too, \
                 but the run with it {}; reporting the first thread whose turn differs instead",
                "WARNING:".yellow().bold(),
                if with.events == 0 {
                    "does not run it there (its continuation was not recorded, or left the \
                     schedule)"
                } else {
                    "runs it for exactly as long"
                }
            );
            return Ok(None);
        }
        // Each continuation replays under the checkpoints of the prefix it
        // continued.
        let with_record = continued_record(schedule, decision + 1, target_continued);
        let without_record = continued_record(schedule, decision, continued);
        let next_stack = |runname: &str, variant: &PreemptionRecord, slice: &Slice| match slice.next
        {
            Some((index, _)) => self.prefix_stack(runname, variant, index + 1, index, continuation),
            None => Ok((false, None)),
        };
        let (next_target_met, stack1) =
            next_stack("final_target_next_for_stacktraces", &with_record, &with)?;
        let (baseline_met, stack2) = next_stack(
            "final_baseline_next_for_stacktraces",
            &without_record,
            &without,
        )?;
        if !target_met || (with.next.is_some() && !next_target_met) || baseline_met {
            eprintln!(
                ":: {} the stack-trace runs did not repeat the search's outcomes; read the \
                 stacks with care",
                "WARNING:".yellow().bold(),
            );
        }
        let next_index = |variant: &[SchedEvent], slice: &Slice| {
            slice.next.map_or(variant.len(), |(index, _)| index)
        };
        let mut critical = [
            (next_index(target_continued, &with), stack1),
            (next_index(continued, &without), stack2),
        ];
        // When the threads that run next have the same stack in both
        // continuations, those stacks tell nothing apart; where the deciding
        // thread stops does. Its stacks replace them only when both were
        // captured.
        let mut slice_ends = slice_end_events(
            &with,
            &without,
            [critical[0].1.as_ref(), critical[1].1.as_ref()],
        );
        // stack1 becomes where the deciding thread stops with the event;
        // stack2 stays the next thread, so the two stacks are two threads.
        let mut slice_end_note = None;
        if let Some(ends) = slice_ends {
            let with_end = if ends[0] == decision {
                // A slice of one event ends where it starts.
                deciding.clone()
            } else {
                match self.prefix_stack(
                    "final_target_slice_end_for_stacktraces",
                    &with_record,
                    ends[0] + 1,
                    ends[0],
                    continuation,
                ) {
                    Ok((_, stack)) => stack,
                    Err(error) => {
                        slice_end_note = Some(format!(
                            "the replay for thread {thread}'s stack where its slice ends failed \
                             to run ({error:#}), so stack1 is the thread that runs next"
                        ));
                        None
                    }
                }
            };
            match with_end {
                Some(with_end) => critical[0] = (ends[0], Some(with_end)),
                None => slice_ends = None,
            }
        }
        let [(event1, stack1), (event2, stack2)] = critical;
        let mut header = timing_decision_header(
            decision,
            &events[decision],
            (&with, &without),
            &self.display_criteria(),
            continuation,
            slice_ends,
        );
        let name = |path: &Path| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        };
        header.push_str(&format!(
            "Event numbers after #{decision} are positions in each continuation's recorded \
             schedule, in the workspace: {} with the event, {} without it.\n",
            name(target_continued_path),
            name(continued_path),
        ));
        for note in notes.iter().chain(&slice_end_note) {
            header.push_str(&format!("Note: {note}\n"));
        }
        let context = format!(
            "With event #{decision} replayed:\n{}\nWithout it:\n{}",
            Self::generate_context(
                target_continued,
                with.next.map_or(decision.max(1), |(index, _)| index),
                self.execution_context
            ),
            Self::generate_context(
                continued,
                without.next.map_or(decision.max(1), |(index, _)| index),
                self.execution_context
            ),
        );

        println!(
            "\n------------------------------ hermit analyze report ------------------------------"
        );
        if let Some(warning) = &self.branch_counter_warning {
            println!("{warning}");
        }
        println!("{}", header);
        // `target_met` is the stack-trace replay's (final_target_for_stacktraces)
        // while `target_trace` is final_target_schedule's, above: both replay the
        // same first `decision + 1` events of `schedule` and continue at
        // `continuation`, so they agree on whether the target is met.
        let racing_accesses = self.prefix_racing_accesses(
            decision,
            (schedule, decision + 1, continuation),
            target_trace.take(),
            baseline_trace.take(),
            target_met,
        );
        println!("Thread {thread} at the deciding event #{decision}:");
        Self::print_stack("the deciding thread's stack", deciding);
        Self::print_stack("stack1", &stack1);
        Self::print_stack("stack2", &stack2);
        Self::print_racing_accesses(&racing_accesses);
        println!("\n{}", context);

        Ok(Some(Report {
            verdict: Verdict::CriticalEvents,
            verdict_reason: None,
            header,
            additional_context: context,
            baseline_run: false,
            critical_event1: Some(ReportCriticalEvent {
                event_index: event1,
                stack: stack1,
            }),
            critical_event2: Some(ReportCriticalEvent {
                event_index: event2,
                stack: stack2,
            }),
            branch_counter_warning: self.branch_counter_warning.clone(),
            deciding_event: Some(ReportCriticalEvent {
                event_index: decision,
                stack: deciding.clone(),
            }),
            partial: None,
            racing_accesses,
        }))
    }

    /// It's weird if no filter is specified.
    fn has_filters(&self) -> bool {
        self.target_stdout.is_some()
            || self.target_stderr.is_some()
            || self.target_exit_code != ExitStatusConstraint::Any
    }

    /// Is the criteria the most common setting of target = failure = nonzero exit.
    fn is_vanilla_criteria(&self) -> bool {
        self.target_stdout.is_none()
            && self.target_stderr.is_none()
            && self.target_exit_code == ExitStatusConstraint::NonZero
    }

    /// Write analyze's final on-target and baseline schedules, stamped
    /// ([`Self::stamp_trial_record`]) and with the callback checkpoints of
    /// the part each shares with one of `sources`, the search's endpoint
    /// records ([`trial_record_from`](crate::analyze::rundata::trial_record_from)), and say where.
    pub fn write_final_schedules(
        &self,
        failing: Vec<SchedEvent>,
        failing_path: &Path,
        passing: Vec<SchedEvent>,
        passing_path: &Path,
        sources: &[&PreemptionRecord],
    ) {
        self.write_trial_schedule_from(failing, sources, failing_path)
            .unwrap();
        eprintln!(
            "Wrote final on-target ({}) schedule to {}",
            self.display_criteria(),
            failing_path.display()
        );
        self.write_trial_schedule_from(passing, sources, passing_path)
            .unwrap();
        eprintln!(
            "Wrote final baseline (off-target) schedule to {}",
            passing_path.display()
        );
    }

    fn display_criteria(&self) -> String {
        let mut strs: Vec<String> = Vec::new();
        match &self.target_exit_code {
            ExitStatusConstraint::Exact(c) => {
                strs.push(format!("exit code={}", c));
            }
            ExitStatusConstraint::NonZero => {
                strs.push("nonzero exit".to_string());
            }
            ExitStatusConstraint::Any => {}
        }
        if self.target_stdout.is_some() {
            strs.push("matching stdout".to_string());
        }
        if self.target_stderr.is_some() {
            strs.push("matching stderr".to_string());
        }
        strs.join(", ")
    }

    /// Create the workspace in `--tmp-dir` and make it `tmp_dir`, where every
    /// run puts its files. The returned guard removes or keeps it, as
    /// `retention` says, when it is dropped.
    fn phase0_initialize(&mut self, retention: Retention) -> anyhow::Result<Workspace> {
        let workspace = Workspace::create(self.tmp_dir.as_deref(), retention)?;
        eprintln!(
            ":: Temp workspace: {}{}",
            workspace.path().display(),
            match retention {
                Retention::Remove => " (removed when analyze exits; --keep-tmp keeps it)",
                Retention::Keep { .. } => "",
            }
        );
        self.tmp_dir = Some(workspace.path().to_path_buf());
        Ok(workspace)
    }

    /// Write the analysis's checkpoint into the new workspace and open its
    /// journal and progress there (`checkpoint`). Without --analyze-seed,
    /// the seed of analyze's own random choices is drawn here, once, and
    /// recorded, so that a resume makes the same choices.
    fn start_checkpoint(&mut self) -> anyhow::Result<()> {
        if self.analyze_seed.is_none() {
            self.analyze_seed = Some(rand::random());
            self.analyze_seed_drawn = true;
        }
        let workspace = self.get_tmp()?.to_path_buf();
        Checkpoint {
            version: CHECKPOINT_VERSION,
            hermit_version: crate::version::Version::get().to_owned(),
            identity: self.identity()?,
        }
        .write(&workspace)?;
        self.journal = Journal::open(&workspace)?;
        self.progress.write_into(&workspace);
        Ok(())
    }

    /// `--resume`: adopt the workspace `resumed` and its journal, after
    /// checking that this invocation analyzes what the recorded one did. A
    /// difference refuses (exit 122) and names each one.
    fn phase0_resume(&mut self, resumed: &Path) -> anyhow::Result<Workspace> {
        let refuse =
            |message: String| anyhow::Error::new(crate::container::PolicyRefusal).context(message);
        let checkpoint = Checkpoint::read(resumed).map_err(|error| {
            refuse(format!(
                "{error:#}. To analyze anyway, run the same command without --resume: that \
                 starts a new analysis (in a new workspace)."
            ))
        })?;
        let recorded = &checkpoint.identity;
        if self.analyze_seed.is_none() {
            self.analyze_seed = Some(recorded.analyze_seed);
        }
        let now = self.identity()?;
        let differences = recorded.differences(&now);
        if !differences.is_empty() {
            return Err(refuse(format!(
                "hermit analyze cannot resume the analysis in {}: it was of something else, so the \
                 outcomes its journal records do not apply. What differs:\n  - {}\nTo continue \
                 anyway, run the same command without --resume: that starts a new analysis (in a \
                 new workspace) and leaves this one as it is.",
                resumed.display(),
                differences.join("\n  - ")
            )));
        }
        let workspace = Workspace::adopt(resumed, self.workspace_retention())?;
        self.tmp_dir = Some(workspace.path().to_path_buf());
        self.journal = Journal::open(workspace.path())?;
        self.resumed_progress = Progress::read(workspace.path());
        if let Some(earlier) = &self.resumed_progress {
            self.progress.carry(earlier);
        }
        self.progress.write_into(workspace.path());
        eprintln!(
            ":: Resuming the analysis in {} (started by {}): {} runs are journaled, and each \
             takes its recorded outcome instead of running again.",
            workspace.path().display(),
            checkpoint.hermit_version,
            self.journal.len()
        );
        Ok(workspace)
    }

    /// Why the workspace stays, whatever its retention says, after the
    /// analysis ended with `result`: a partial report gave the command that
    /// continues it, or a resumed analysis did not finish, and its adopted
    /// workspace holds an earlier invocation's journaled runs.
    fn keep_workspace_because(&self, result: &anyhow::Result<ExitStatus>) -> Option<&'static str> {
        if self.partial_report_written {
            Some("a budget ended the analysis; --resume continues it, as the report above says")
        } else if self.resume.is_some() && result.is_err() {
            Some(
                "a resumed analysis that does not finish keeps its workspace and journal; \
                 --resume continues it again",
            )
        } else {
            None
        }
    }

    /// What this analysis is of: what a resume must find unchanged.
    fn identity(&self) -> anyhow::Result<Identity> {
        let hermit = FileIdentity {
            path: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/proc/self/exe")),
            ..FileIdentity::of(Path::new("/proc/self/exe"))?
        };
        let runopts = RunData::raw_runopts(self);
        let program = find_program(runopts.program())
            .map(|path| FileIdentity::of(&path))
            .transpose()?;
        let unset = || "unset".to_owned();
        let target = vec![
            (
                "--target-stdout".to_owned(),
                self.target_stdout
                    .as_ref()
                    .map_or_else(unset, |regex| regex.as_str().to_owned()),
            ),
            (
                "--target-stderr".to_owned(),
                self.target_stderr
                    .as_ref()
                    .map_or_else(unset, |regex| regex.as_str().to_owned()),
            ),
            (
                "--target-exit-code".to_owned(),
                format!("{:?}", self.target_exit_code),
            ),
        ];
        let search = [
            ("--search", self.search.to_string()),
            ("--prefix-search", self.prefix_search.to_string()),
            ("--minimize", self.minimize.to_string()),
            ("--run-needleman", self.run_needleman.to_string()),
            ("--imprecise-search", self.imprecise_search.to_string()),
            ("--selfcheck", self.selfcheck.to_string()),
            ("--run1-seed", format!("{:?}", self.run1_seed)),
            ("--run2-seed", format!("{:?}", self.run2_seed)),
            ("--jitter-dist", format!("{:?}", self.jitter_dist)),
            (
                "--continuation-timeslice",
                format!("{:?}", self.continuation_timeslice),
            ),
            ("--trial-timeout", format!("{:?}", self.trial_timeout)),
            ("--max-log-bytes", format!("{:?}", self.max_log_bytes)),
            ("--backend", format!("{:?}", self.backend)),
        ]
        .into_iter()
        .map(|(option, value)| (option.to_owned(), value))
        .collect();
        let mut records = Vec::new();
        for (option, path) in [
            ("--run1-preemptions", &self.run1_preemptions),
            ("--run2-preemptions", &self.run2_preemptions),
            ("--run1-schedule", &self.run1_schedule),
            ("--run2-schedule", &self.run2_schedule),
        ] {
            if let Some(path) = path {
                records.push((option.to_owned(), FileIdentity::of(path)?));
            }
        }
        Ok(Identity {
            hermit,
            program,
            run_args: self.run_arg.iter().chain(&self.run_args).cloned().collect(),
            target,
            search,
            records,
            analyze_seed: self
                .analyze_seed
                .context("the analyze seed is set before the identity is taken")?,
        })
    }

    /// What becomes of analyze's workspace: kept with `--keep-tmp`, with
    /// `--verbose`, whose reproducers name its files, and with `--trial-log`
    /// (or `--guest-log`) above warn, whose per-run logs are in it for the
    /// user to read; removed otherwise.
    fn workspace_retention(&self) -> Retention {
        if self.keep_tmp {
            Retention::Keep {
                because: Some("--keep-tmp"),
            }
        } else if self.verbose {
            Retention::Keep {
                because: Some("--verbose"),
            }
        } else if let Some(option) = self.trial_log_files_option() {
            Retention::Keep {
                because: Some(option),
            }
        } else {
            Retention::Remove
        }
    }

    /// Create our workspace and verify the input run matches the criteria, or find one that does.
    /// Returns the results of the target run.
    fn phase1_establish_target_run(&mut self) -> Result<RunData, Error> {
        let run1data = RunData::new_run1_target(self, "run1_target".to_string())?;
        eprintln!(
            // `to_repro` is already a complete `hermit ... run ...` command.
            ":: {} {}",
            "Studying target execution: ".yellow().bold(),
            run1data.to_repro()
        );

        // Run the target, from its seed or by replaying --run1-preemptions, and
        // record the preemptions and schedule the search works from. A replay
        // of the record is the target run like a seed's: it is measured for the
        // trial bound, and --selfcheck compares its log.
        let mut run1data = run1data.with_preemption_recording();
        run1data.launch()?;
        self.record_endpoint(&run1data);

        if !run1data.is_a_match() {
            if let Some(record) = &self.run1_preemptions {
                return Err(AnalyzePrecondition::target_not_reproduced(format!(
                    "the replay of --run1-preemptions {} did not meet the target criteria ({}). \
                     A record replays the same only under the run arguments it was recorded \
                     with (after `--`), --seed included: it sets the guest's random and fuzz \
                     seeds and is not stored in the record. --search does not apply to a record; \
                     to search, pass --run1-seed.",
                    record.display(),
                    self.display_criteria()
                ))
                .into());
            }
            self.after_a_first_run_that_missed(|| {
                self.progress.phase(Phase::SearchForTarget);
                self.do_search()
            })
        } else if self.has_filters() {
            eprintln!(
                ":: {}",
                format!(
                    "First run matched target criteria ({}).",
                    self.display_criteria()
                )
                .green()
                .bold(),
            );
            Ok(run1data)
        } else {
            eprintln!(":: {}", "WARNING: run without any --filter arguments, so accepting ALL runs. This is probably not what you wanted.".red().bold());
            Ok(run1data)
        }
    }

    /// Reduce the set of preemptions needed to match the criteria.
    ///
    /// Takes the input (non-minimized) preemptions as a file path and returns the minimized
    /// preemptions as a data structure in memory.
    ///
    /// # Returns
    /// - The on-target run with minimized schedule.
    fn phase2_minimize(
        &self,
        global: &GlobalOpts,
        mut last_run: RunData,
    ) -> anyhow::Result<RunData> {
        if self.minimize {
            // In this scenario we need to work with preemptions.
            self.progress.phase(Phase::Minimize);

            let preempts_path = last_run.preempts_path_out();
            let (min_pr, min_pr_path, min_log_path) = self.minimize(preempts_path, global)?;
            eprintln!(
                ":: {}\n {}",
                "Successfully minimized to these critical interventions:"
                    .green()
                    .bold(),
                truncated(1000, serde_json::to_string(&min_pr).unwrap())
            );

            // TEMP: construct a RunData post-facto, until we finish the minimize overhaul:
            let runname = "minimized".to_string();
            let min_run = RunData::from_minimize_output(
                self,
                runname,
                last_run.runopts.clone(),
                min_pr,
                min_pr_path,
                min_log_path,
            );
            Ok(min_run)
        } else {
            // In this scenario we only care about event traces, and never really need to work with
            // preemptions.  Still, we'll need to do another run to record the trace.
            Ok(last_run)
        }
    }

    /// A weaker log difference that does not expect certain lines to be conserved in preemption replay.
    fn log_diff_preemption_replay(
        &self,
        global: &GlobalOpts,
        run1_log_path: &Path,
        run2_log_path: &Path,
    ) -> ExitStatus {
        if self.verbose {
            yellow_msg("[comparing] with log-diff command:");
            eprintln!(
                "    hermit log-diff --record-envelope=all-records-v1 \
                 --ignore-lines=CHAOSRAND {} {}",
                run1_log_path.display(),
                run2_log_path.display(),
            );
        }
        let mut ldopts = LogDiffCLIOpts::new(run1_log_path, run2_log_path);
        ldopts.more.ignore_lines = vec!["CHAOSRAND".to_string(), "SCHEDRAND".to_string()];
        ldopts.main(global)
    }

    /// Optionally do an extra run to verify that preemptions replay and yield the exact same
    /// execution.a
    pub fn phase3_strict_preempt_replay_check(
        &self,
        global: &GlobalOpts,
        min_run: &mut RunData,
    ) -> Result<(), Error> {
        let min_log_path = &min_run.log_path().unwrap().to_path_buf();
        let min_preempts_path = min_run.preempts_path_out().to_path_buf();

        if self.selfcheck {
            self.progress.phase(Phase::Selfcheck);
            yellow_msg("[selfcheck] Verifying target run preserved under preemption-replay");

            let runname = "run1b_selfcheck";
            let run1b = RunData::new_run1_replay(self, runname.to_string(), &min_run.runopts)?;
            let mut run1b = self
                .replaying_the_target_record(run1b, min_preempts_path.clone())
                .with_preemption_recording();
            eprintln!("    {}", run1b.to_repro());

            run1b.launch()?;
            yellow_msg("[selfcheck] Comparing output from additional run (run1 vs run1b)");
            let run1b_log_path = run1b.log_path().unwrap();
            let status = self.log_diff_preemption_replay(global, min_log_path, run1b_log_path);

            let matched = run1b.is_a_match();
            let run1b_preempts_path = run1b.preempts_path_out();
            selfcheck_conclusion(matched, status.success(), || {
                preempt_files_equal(&min_preempts_path, run1b_preempts_path)
                    .then_some(())
                    .ok_or_else(|| {
                        format!(
                            "The preemptions recorded by the additional run did not match the \
                             preemptions replayed (no fixed point): {} vs {}",
                            min_preempts_path.display(),
                            run1b_preempts_path.display(),
                        )
                    })
            })?;

            eprintln!(
                ":: {}",
                "Identical executions confirmed between target run and its preemption-based replay."
                    .green()
                    .bold()
            );
        }
        Ok(())
    }

    /// Once we have the target MATCHING run in hand (usually crashing/failing), we need to
    /// determine which baseline, non-matching run to use. Then we need to extract the schedule from
    /// it.
    ///
    /// Returns a path to a file containing recorded schedule events for the baseline run.
    pub fn phase4_choose_baseline_sched_events(
        &mut self,
        matching_pr: PreemptionRecord,
    ) -> anyhow::Result<RunData> {
        self.progress.phase(Phase::Baseline);
        if self.minimize {
            // Enforced by the clap conflicts_with annotations:
            assert!(self.run2_seed.is_none());
            assert!(self.run2_preemptions.is_none());
            assert!(self.run2_schedule.is_none());

            // If we're minimizing, then we know that ALL interventions in the schedule are critical.
            // Thus omitting any of them is sufficient to exit the target schedule space.
            // Omitting the last one should yield the lowest distance match/non-match schedule pair.
            knock_out_until_missed(matching_pr, |ix, knocked_out| {
                let runname = format!("run2_baseline_try{:03}", ix);
                let (still_matching, newrun) =
                    self.save_nearby_non_matching_sched_events(&runname, knocked_out)?;
                Ok((!still_matching).then_some(newrun))
            })
        } else {
            let runname = "run2_baseline".to_string();
            let mut newrun = RunData::new_baseline(self, runname)?.with_preemption_recording();

            // Tweak the runopts according to several different scenarios:
            let ro = &mut newrun.runopts;
            let from_where;
            if let Some(seed) = self.run2_seed {
                // Replay from seed to record schedule.
                ro.det_opts.det_config.seed = seed;
                from_where = "--run2-seed";
            } else if let Some(path) = &self.run2_preemptions {
                // Replay from preemption record to record schedule.
                ro.det_opts.det_config.replay_preemptions_from = Some(path.clone());
                // TODO: if the file already contains a schedule, we don't need to rerun it.
                // Unless selfcheck is specified.
                from_where = "--run2-preemptions";
            } else if let Some(path) = &self.run2_schedule {
                if self.selfcheck {
                    // TODO: Don't trust the recorded schedule is a baseline, replay and check it.
                }
                let runname = "from_existing_run2_schedule".to_string();
                let fakerun = RunData::from_schedule_trace(self, runname, ro.clone(), path.clone());
                return Ok(fakerun);
            } else {
                from_where = "non-chaos (0 extra preemptions) run";

                // Otherwise we just assume that a *baseline* (non-chaos) run will do the trick.
                // Without chaos the run arguments' timeslice range and draw mean nothing, and
                // validating the run again would refuse them.
                ro.turn_chaos_off();
            }
            if !newrun.launch_trial()?.finished() {
                // Without a baseline the user chose, analyze searches within
                // the target schedule instead; one the user chose is not
                // replaced behind their back.
                if self.run2_seed.is_none() && self.run2_preemptions.is_none() {
                    return Err(BaselineUnfinished(from_where).into());
                }
                return Err(AnalyzePrecondition::baseline_not_reproduced(format!(
                    "the baseline run ({from_where}) did not finish (a bound or a refusal \
                     stopped it; see above). Pass a larger --trial-timeout or \
                     --trial-virtual-timeout, or another baseline; without one, analyze bisects \
                     against the run without chaos, or searches within the target schedule when \
                     that does not finish either."
                ))
                .into());
            }
            self.record_endpoint(&newrun);

            eprintln!(
                ":: Recorded schedule from {} as baseline run ({})",
                from_where,
                newrun
                    .sched_path_out()
                    .file_name()
                    .unwrap()
                    .to_string_lossy(),
            );
            if newrun.is_a_match() {
                Err(AnalyzePrecondition::baseline_not_reproduced(
                    "Expectations not met... baseline run matched target criteria when it should \
                     not.",
                )
                .into())
            } else {
                eprintln!("Good: baseline run does not match criteria (e.g. pass not fail).");
                Ok(newrun)
            }
        }
    }

    /// Perform the binary search through schedule-space, identifying critical events.
    ///
    /// Each trial replays its schedule with the callback checkpoints of the
    /// part it shares with the `target` or `baseline` record
    /// ([`trial_record_from`](crate::analyze::rundata::trial_record_from)):
    /// an endpoint replayed whole keeps all of them, and a spliced schedule
    /// keeps those its unchanged prefix reaches, so its slices end where the
    /// recording's did up to the first edit.
    pub fn phase5_bisect_traces(
        &self,
        target: &PreemptionRecord,
        baseline: &PreemptionRecord,
    ) -> anyhow::Result<CriticalSchedule> {
        self.progress.phase(Phase::Bisect);
        let endpoints = events_digest(&[baseline.schedevents(), target.schedevents()]);
        let resumed = self.resumable_interval(&endpoints);
        let resume = resumed.as_ref().map(|(resume, ..)| resume);
        let trials = Cell::new(resume.map_or(0, |resume| resume.trials));
        let unfinished = Cell::new(resume.map_or(0, |resume| resume.unfinished));
        let refused = Cell::new(resume.map_or(0, |resume| resume.refused));

        // Each call is one trial. A trial that cannot finish (for example, one
        // that --max-log-bytes ended) returns its error unchanged, and the
        // search stops there. A trial that a wall-clock bound ended
        // (--trial-timeout, or the run arguments' --timeout) or that Hermit
        // refused is the exception: a spliced schedule can leave the guest
        // waiting for an event that never comes, or take it down a path Hermit
        // does not support, so it did not reach the target, and the search
        // goes on.
        let test_fn = |sched: &[SchedEvent]| -> TrialOutcome {
            trials.set(trials.get() + 1);
            let i = trials.get();
            let runname = format!("bisect_round_{:0wide$}", i, wide = 3);
            let mut newrun = RunData::new_baseline(self, runname)?
                .with_schedule_replay() // Default input path
                .with_schedule_recording(); // Default output path
            // Prepare the next synthetic schedule on disk:
            self.write_trial_schedule_from(
                sched.to_owned(),
                &[target, baseline],
                newrun.sched_path_in(),
            )?;

            if self.verbose {
                eprintln!(
                    ":: {}, repro command{}:\n    {}",
                    format!("Testing execution during search (#{})", i)
                        .yellow()
                        .bold(),
                    if self.keep_tmp {
                        ""
                    } else {
                        " (its schedules are removed after the trial; --keep-tmp keeps them)"
                    },
                    newrun.to_repro(),
                );
            }

            let is_match = match newrun.launch_trial()? {
                TrialEnd::Unfinished(stop) => {
                    unfinished.set(unfinished.get() + 1);
                    refused.set(refused.get() + usize::from(stop == Stop::Refusal));
                    newrun.discard_schedules();
                    return Ok((true, sched.to_owned()));
                }
                end => end.reached_target(),
            };
            if is_match {
                eprintln!(" => Target condition ({})", self.display_criteria());
            } else {
                eprintln!(" => Baseline condition (usually absence of crash)");
            }

            let sched_out = PreemptionReader::new(newrun.sched_path_out()).load_all();
            newrun.discard_schedules();
            Ok((!is_match, sched_out.into_global()))
        };

        // Only an analysis that journals keeps its interval (`hermit bisect`
        // keeps every trial's schedules anyway).
        let mut interval = if self.journal.is_on() {
            Some(IntervalFiles::new(self.get_tmp()?))
        } else {
            None
        };
        if let Some(interval) = &mut interval
            && resumed.is_none()
        {
            interval.record(
                self,
                None,
                [baseline.schedevents(), target.schedevents()],
                None,
                None,
            );
        }
        // TODO: have search_for_critical_schedule borrow only.
        let (start, baseline, target) = match resumed {
            Some((resume, pass, passing, failing)) => (
                SearchStart::Interval {
                    pass,
                    event_level: resume.event_level,
                },
                passing,
                failing,
            ),
            None => (
                SearchStart::Endpoints,
                baseline.schedevents().clone(),
                target.schedevents().clone(),
            ),
        };
        let cfg = self.bisect_config();
        let crit = search_for_critical_schedule_observed(
            test_fn,
            baseline,
            target,
            &cfg,
            start,
            &mut |at| {
                if let Some(interval) = &mut interval {
                    let state = SearchState {
                        endpoints: endpoints.clone(),
                        event_level: at.event_level,
                        trials: trials.get(),
                        unfinished: unfinished.get(),
                        refused: refused.get(),
                    };
                    interval.record(
                        self,
                        Some(at.pass),
                        [at.passing, at.failing],
                        Some((at.edit_distance, at.swap_distance)),
                        Some(state),
                    );
                }
            },
        )?;
        eprintln!(
            "Critical event of final on-target schedule is {}",
            crit.critical_event_index
        );
        for warning in search_warnings(&crit, unfinished.get()) {
            eprintln!(":: {} {warning}", "WARNING:".yellow().bold());
        }
        if let Some(warning) = refused_trials_warning(refused.get()) {
            eprintln!(":: {} {warning}", "WARNING:".yellow().bold());
        }
        Ok(crit)
    }

    /// `--resume`: the interval the earlier invocation's search had reached
    /// between `endpoints` (`events_digest` of the baseline and target
    /// schedules), with its pass and its two schedules, if the progress
    /// names one whose files are whole. The search restarts there: its
    /// trials keep no schedules, so the journal alone could not bring it
    /// back to that pass. With no such interval it starts over, and the
    /// journal answers what it can.
    fn resumable_interval(
        &self,
        endpoints: &str,
    ) -> Option<(IntervalResume, usize, Vec<SchedEvent>, Vec<SchedEvent>)> {
        let interval = self.resumed_progress.as_ref()?.interval.as_ref()?;
        let (Some(pass), Some(resume)) = (interval.pass, interval.resume.clone()) else {
            return None;
        };
        let load = |path: &Path, hash: &str| {
            let events = PreemptionReader::new(path).load_all().into_global();
            (events_digest(&[&events]) == hash).then_some(events)
        };
        let loaded = (resume.endpoints == endpoints)
            .then(|| {
                Some((
                    load(&interval.passing, &resume.passing_hash)?,
                    load(&interval.failing, &resume.failing_hash)?,
                ))
            })
            .flatten();
        let Some((passing, failing)) = loaded else {
            eprintln!(
                ":: The earlier invocation's search interval (pass {pass}) is not this search's, \
                 or its schedules are not whole; the search starts from its endpoints."
            );
            return None;
        };
        eprintln!(
            ":: Resuming the search at pass {pass}, from the interval the earlier invocation \
             reached ({} and {} events, {}); its {} trials do not run again.",
            passing.len(),
            failing.len(),
            interval.edit_distance.map_or_else(
                || "distance not measured".to_owned(),
                |edit| format!("edit distance {edit}")
            ),
            resume.trials,
        );
        Some((resume, pass, passing, failing))
    }

    /// Bisect a known passing/failing schedule pair and report the critical event ordering.
    pub fn bisect_schedule_pair(
        &mut self,
        good: PreemptionRecord,
        bad: PreemptionRecord,
    ) -> anyhow::Result<ExitStatus> {
        // Bisect keeps its workspace, and says where when it exits.
        let _workspace = self.phase0_initialize(Retention::Keep { because: None })?;
        eprintln!(
            ":: Beginning schedule bisection using good/bad endpoints ({} / {} events)",
            good.schedevents().len(),
            bad.schedevents().len(),
        );

        let critical = self.phase5_bisect_traces(&bad, &good)?;
        let index = critical.critical_event_index;
        if index == 0 || index >= critical.failing_schedule.len() {
            bail!("schedule search returned an invalid critical event index {index}");
        }

        println!("\n---------------- hermit bisect result ----------------");
        println!("Schedule divergence localized at bad event #{index}:");
        println!(
            "  preceding event #{}: {}",
            index - 1,
            critical.failing_schedule[index - 1]
        );
        println!(
            "  critical event  #{index}: {}",
            critical.failing_schedule[index]
        );
        println!("Swapping these adjacent events reproduces the good outcome.");

        let report = self.phase6_record_outputs(critical, &[&bad, &good], None)?;
        if let Some(path) = &self.report_file {
            let text = serde_json::to_string_pretty(&report)?;
            std::fs::write(path, text)?;
            eprintln!(":: Final bisection report written to {}", path.display());
        }

        Ok(ExitStatus::SUCCESS)
    }

    fn generate_context(
        sched: &[SchedEvent],
        critical_event_index: usize,
        window_size: usize,
    ) -> String {
        let mut additional_context = "Execution context for the critical events (*):\n".to_string();
        {
            let start = critical_event_index - 1;
            let start = start - cmp::min(window_size, start);
            let end = cmp::min(critical_event_index + window_size + 1, sched.len());

            for (ix, item) in sched.iter().enumerate().take(end).skip(start) {
                additional_context.push_str(&format!(
                    "  {} {}\n",
                    if ix == critical_event_index || ix == critical_event_index - 1 {
                        "*"
                    } else {
                        " "
                    },
                    item
                ));
            }
        }
        additional_context
    }

    /// Record the schedules on disk as reproducers and report stack-traces of
    /// critical events. `target_run` is the workspace root of the run whose
    /// schedule was the search's target endpoint, if one ran.
    pub fn phase6_record_outputs(
        &self,
        crit: CriticalSchedule,
        sources: &[&PreemptionRecord],
        target_run: Option<&Path>,
    ) -> Result<Report, Error> {
        let tmp_dir = self.get_tmp()?;
        let CriticalSchedule {
            failing_schedule,
            passing_schedule,
            critical_event_index,
        } = crit;
        self.progress.phase(Phase::StackTraces);
        self.progress.decided(
            format!(
                "events #{} and #{critical_event_index} of the failing schedule are the critical \
                 pair, in {}",
                critical_event_index - 1,
                self.get_tmp()?
                    .join("final_target_for_stacktraces")
                    .with_extension(SCHED_EXT)
                    .display()
            ),
            DecidedEvents::CriticalPair(critical_event_index - 1, critical_event_index),
        );

        let runname1 = "final_target_for_stacktraces";
        let runname2 = "final_baseline_for_stacktraces";
        let final_failing_path = tmp_dir.join(runname1).with_extension(SCHED_EXT);
        let final_passing_path = tmp_dir.join(runname2).with_extension(SCHED_EXT);

        let passing_context = Self::generate_context(
            &passing_schedule,
            critical_event_index,
            self.execution_context,
        );
        let failing_context = Self::generate_context(
            &failing_schedule,
            critical_event_index,
            self.execution_context,
        );

        self.write_final_schedules(
            failing_schedule.clone(),
            &final_failing_path,
            passing_schedule.clone(),
            &final_passing_path,
            sources,
        );

        // Both schedules are replayed: the passing schedule's events
        // #index - 1 and #index are the failing schedule's #index and
        // #index - 1, so each racing operation's stack can come from either
        // replay when the other one leaves its schedule first.
        // The schedules agree before event #index - 1, where the racing
        // accesses' window starts.
        let trace_from = self.race_trace_from(critical_event_index - 1);
        let mut baseline = self.replay_for_stacks(
            runname2,
            &final_passing_path,
            &passing_schedule,
            critical_event_index,
            trace_from.map(|from| ("baseline", from)),
        )?;
        let mut target = self.replay_for_stacks(
            runname1,
            &final_failing_path,
            &failing_schedule,
            critical_event_index,
            trace_from.map(|from| ("target", from)),
        )?;
        if (baseline.finished && baseline.met_target) || (target.finished && !target.met_target) {
            eprintln!(
                ":: {} the stack-trace replays did not repeat the search's outcomes (baseline \
                 met the target: {}, target met it: {}); read the stacks with care",
                "WARNING:".yellow().bold(),
                baseline.met_target,
                target.met_target,
            );
        }
        let threads = [
            passing_schedule[critical_event_index - 1].dettid,
            passing_schedule[critical_event_index].dettid,
        ];
        let merged = merge_stacks(&baseline, &target, critical_event_index, threads);
        let exact = [0, 1].map(|slot| exact_stack(&baseline, &target, critical_event_index, slot));
        // A replay that could not follow its schedule through the pair took
        // its stacks elsewhere. Its realized schedule replays exactly, and
        // the two realized schedules part where the two orders do.
        let mut sources = String::new();
        let realized = if exact == [true, true] {
            None
        } else {
            match self.realized_pair(&baseline, &target) {
                Ok(pair) => Some(pair),
                Err(reason) => {
                    eprintln!(":: {} {reason}", "Note:".yellow().bold());
                    sources.push_str(&format!(
                        "Note: no stacks from the schedules the replays realized: {reason}.\n"
                    ));
                    None
                }
            }
        };
        let (shown_threads, stack1, stack2) = match realized {
            Some(RealizedPair {
                event,
                at,
                stacks: [first, second],
            }) => {
                sources.push_str(&format!(
                    "The replays could not follow the passing and failing schedules through these \
                     events: {}. stack1 and stack2 come from replays of the schedules those two \
                     replays realized instead (a realized schedule replays exactly), at their \
                     event #{event}, where they first run different threads: thread {} in the \
                     replay of the passing schedule (stack1, {}), thread {} in the replay of the \
                     failing one (stack2, {}).\n",
                    realized_pair_reason(&baseline, &target, critical_event_index),
                    baseline.realized[event].dettid,
                    file_name(&baseline.realized_path),
                    target.realized[event].dettid,
                    file_name(&target.realized_path),
                ));
                for (which, slot, telling) in
                    [("passing", "stack1", &at[0]), ("failing", "stack2", &at[1])]
                {
                    sources.extend(telling_sentence(which, slot, event, telling));
                }
                ([at[0].thread, at[1].thread], Some(first), Some(second))
            }
            None => {
                let [stack1, stack2] = merged;
                for (which, stack, event) in [
                    ("stack1", &stack1, critical_event_index - 1),
                    ("stack2", &stack2, critical_event_index),
                ] {
                    match stack {
                        Some((_, source)) => {
                            sources.push_str(&format!("{which} is from {source}.\n"))
                        }
                        None => {
                            let target_event = 2 * critical_event_index - 1 - event;
                            let reason = missing_stack_reason(
                                which,
                                (event, target_event),
                                &baseline,
                                &target,
                            );
                            eprintln!(":: {} {reason}", "WARNING:".yellow().bold());
                            sources.push_str(&format!("{reason}\n"));
                        }
                    }
                }
                (
                    threads,
                    stack1.map(|(stack, _)| stack),
                    stack2.map(|(stack, _)| stack),
                )
            }
        };

        let (opening, racing) =
            racing_pair_opening(shown_threads, [stack1.as_ref(), stack2.as_ref()]);
        let mut header = opening;
        header.push_str(&format!(
            "The order of events (#{} and #{} in the schedule) determines the program outcome.\n",
            critical_event_index - 1,
            critical_event_index,
        ));
        if racing {
            header.push_str(
                "You must add synchronization to prevent these operations from racing, or give them a different order.\n",
            );
        }

        if self.is_vanilla_criteria() {
            header.push_str(
                "Attached are the stacktraces in the PASSING order, but flipping the order of the two events makes the program FAIL (nonzero exit).\n",
            );
        } else {
            header.push_str(&format!(
                "Attached are the stacktraces in the baseline order, while flipping the order makes the program exhibit the target criteria ({}).\n",
                self.display_criteria()
            ));
        }
        if target.met_target
            && let Some(change) = target_run.and_then(|run| {
                changed_output(
                    run,
                    &tmp_dir.join(runname1),
                    [
                        ("stdout", self.target_stdout.as_ref()),
                        ("stderr", self.target_stderr.as_ref()),
                    ],
                )
            })
        {
            eprintln!(":: {} {change}", "WARNING:".yellow().bold());
            header.push_str(&format!("Note: {change}\n"));
        }
        header.push_str(&sources);
        let target_met = target.finished && target.met_target;
        let racing_accesses = match (target.traced.take(), baseline.traced.take()) {
            (Some(target), Some(baseline)) => {
                let realized = target.realized_path.clone();
                let baseline_realized = baseline.realized_path.clone();
                Some(self.racing_accesses(
                    critical_event_index - 1,
                    target,
                    baseline,
                    target_met,
                    |runname| {
                        Ok(RunData::new_baseline(self, runname.to_string())?
                            .with_schedule_replay_from(realized.clone()))
                    },
                    // A candidate's check replays a schedule of the run it
                    // checks under the callback checkpoints of that run's
                    // recording, up to where the edit starts, then continues
                    // without chaos at the trials' timeslice.
                    |runname, role, edited, unchanged, replay| {
                        let path = if role == "baseline" {
                            &baseline_realized
                        } else {
                            &realized
                        };
                        let edited = Recording::read(path)
                            .and_then(|recording| recording.into_legacy("a race candidate's check"))
                            .map_err(|error| anyhow::anyhow!("{error:#}"))?
                            .schedule_prefix(unchanged)
                            .with_schedule(edited.to_vec())
                            .unwrap_or_else(|| {
                                PreemptionRecord::from_sched_events(edited.to_vec())
                            });
                        self.unjournaled().prefix_trial(
                            runname,
                            &edited,
                            replay,
                            self.trial_max_timeslice(),
                        )
                    },
                ))
            }
            _ => None,
        };

        // Also print to the screen, the branch-counter caveat first: the
        // report must not read as reproducible where its trials may not
        // have been.
        println!(
            "\n------------------------------ hermit analyze report ------------------------------"
        );
        if let Some(warning) = &self.branch_counter_warning {
            println!("{warning}");
        }
        println!("{}", header);
        Self::print_stack("stack1", &stack1);
        Self::print_stack("stack2", &stack2);
        Self::print_racing_accesses(&racing_accesses);
        println!("\n{}", passing_context);

        if self.verbose {
            println!(
                "\n----------------------- stacks from final on-target run -----------------------"
            );
            Self::print_stack(
                &format!("event #{} (stack2's operation)", critical_event_index - 1),
                &target.stacks[0],
            );
            Self::print_stack(
                &format!("event #{critical_event_index} (stack1's operation)"),
                &target.stacks[1],
            );
            println!("\n{}", failing_context);
        }

        Ok(Report {
            verdict: Verdict::CriticalEvents,
            verdict_reason: None,
            header,
            additional_context: passing_context,
            baseline_run: true,
            critical_event1: Some(ReportCriticalEvent {
                event_index: critical_event_index - 1,
                stack: stack1,
            }),
            critical_event2: Some(ReportCriticalEvent {
                event_index: critical_event_index,
                stack: stack2,
            }),
            branch_counter_warning: self.branch_counter_warning.clone(),
            deciding_event: None,
            partial: None,
            racing_accesses,
        })
    }

    /// Print the report's "Racing accesses" block, when there is one.
    fn print_racing_accesses(racing: &Option<RacingAccesses>) {
        if let Some(racing) = racing {
            println!("\n{}", render_racing_accesses(racing));
        }
    }

    fn print_stack(which: &str, m_stack: &Option<PrettyBacktrace>) {
        if let Some(s) = m_stack {
            println!("{}", s);
        } else {
            println!(" ({} not available) ", which);
        }
    }

    /// Everything `main` does before phase 0 creates the workspace: a
    /// refusal here starts nothing.
    fn prepare(&mut self, global: &GlobalOpts) -> anyhow::Result<()> {
        self.apply_global(global);
        self.refuse_unsupervised_log_cap()?;
        self.refuse_options_trials_do_not_apply()?;
        self.refuse_outputs_trials_overwrite()?;
        self.refuse_unqualified_trial_timeout()?;
        self.refuse_unenforceable_trial_timeout()?;
        self.refuse_inapplicable_trial_virtual_timeout()?;
        self.refuse_unsound_continuation_timeslice()?;
        self.install_trial_pmu_config()?;
        self.admit_branch_counter(&mut crate::tracing::write_stderr_diagnostic)?;
        if let Some(notice) =
            self.small_trial_max_timeslice_notice(crate::run::installed_skid_margin)
        {
            crate::tracing::write_stderr_diagnostic(&notice);
        }
        // `--run1-schedule` and `--run2-schedule` parse but have no
        // implementation. Refuse them before any workspace or trial, rather
        // than panicking here.
        let unimplemented: Vec<&str> = [
            (self.run1_schedule.is_some(), "--run1-schedule"),
            (self.run2_schedule.is_some(), "--run2-schedule"),
        ]
        .into_iter()
        .filter_map(|(given, option)| given.then_some(option))
        .collect();
        if !unimplemented.is_empty() {
            return Err(
                anyhow::Error::new(crate::container::PolicyRefusal).context(format!(
                    "hermit analyze does not implement {}. Identify a run by a preemption record \
                 (--run1-preemptions or --run2-preemptions, written by `hermit run \
                 --record-preemptions-to`) or by a seed (--run1-seed or --run2-seed).",
                    unimplemented.join(" or ")
                )),
            );
        }
        // The trials that replay these records start from the epoch they were
        // recorded under (https://github.com/rrnewton/hermit/issues/3870).
        let run1 = self.run1_preemptions.clone();
        let run2 = self.run2_preemptions.clone();
        let recordings: Vec<(&str, &Path)> = [
            ("--run1-preemptions", run1.as_deref()),
            ("--run2-preemptions", run2.as_deref()),
        ]
        .into_iter()
        .filter_map(|(option, path)| Some((option, path?)))
        .collect();
        self.adopt_recorded_epoch(&recordings)?;
        self.adopt_recorded_timeslice(&recordings)?;
        // Every trial charges expired timed waits as the target did.
        self.adopt_expired_wait_charge(run1.as_deref())?;
        // Every trial registers queued sleeps as the target did.
        self.adopt_sleep_registration(run1.as_deref())?;
        self.refuse_recordings_under_another_pipe_wake_latency(&recordings)
    }

    /// Take the settings `analyze` inherits from the global options: every
    /// trial runs on the globally selected backend
    /// (`hermit --backend <BACKEND> analyze ...`) and charges the invocation's
    /// shared `--max-log-bytes` budget.
    pub fn apply_global(&mut self, global: &GlobalOpts) {
        self.backend = global.backend;
        self.max_log_bytes = global.max_log_bytes;
        self.log_budget = global.log_budget();
    }

    pub fn main(&mut self, global: &GlobalOpts) -> anyhow::Result<ExitStatus> {
        // The budget counts from here, before anything that takes time.
        self.budget = Budget::new(self.time_budget, self.trial_budget);
        // Every trial reads the one property snapshot this invocation takes
        // (`RunOpts::take_property_snapshot`); it goes when analyze ends.
        let _remove_property_snapshot = crate::property_snapshot::RemoveOnExit;
        self.prepare(global)?;
        let _watchdog = self.max_memory.enforce("hermit analyze")?;
        // From here SIGTERM, SIGINT and SIGHUP end the run in progress and
        // the analysis, which then removes what it created like any other
        // ending, and the process dies of the signal (`raise_or_exit`).
        let stop_signals = StopSignals::install()?;
        let mut workspace = match self.resume.clone() {
            Some(resumed) => self.phase0_resume(&resumed)?,
            None => {
                let workspace = self.phase0_initialize(self.workspace_retention())?;
                self.start_checkpoint()?;
                workspace
            }
        };
        let result = self.analyze(global);
        if let Some(because) = self.keep_workspace_because(&result) {
            workspace.keep(because);
        }
        drop(workspace);
        // Restored before the last check, so a signal from here on has its
        // default action rather than being recorded too late to act on.
        drop(stop_signals);
        let Err(Stopped(signal)) = stop::check() else {
            return result;
        };
        match result {
            Err(error) if error.downcast_ref::<Stopped>().is_none() => note(&format!(
                ":: hermit analyze stopped on {signal}, after this error: {error:#}"
            )),
            _ => note(&format!(":: hermit analyze stopped on {signal}.")),
        }
        Ok(ExitStatus::Signaled(signal, false))
    }

    /// The analysis, in the workspace phase 0 created; a partial report
    /// (exit 120) when a budget ends it first.
    fn analyze(&mut self, global: &GlobalOpts) -> anyhow::Result<ExitStatus> {
        let result = self.analyze_steps(global);
        self.end_on_budget(result)
    }

    /// `result`, or the partial report when a budget ended the analysis.
    fn end_on_budget(&mut self, result: anyhow::Result<ExitStatus>) -> anyhow::Result<ExitStatus> {
        match result {
            Err(error) => match error.downcast::<BudgetExpired>() {
                Ok(expired) => self.report_partial(expired),
                Err(error) => Err(error),
            },
            done => done,
        }
    }

    /// The report of an analysis a budget ended: why and where it stopped,
    /// its best answer so far from the progress (`checkpoint`), the stacks of
    /// the default search's pair when two replays fit the grace period, and
    /// how to continue. Exits [`hermit::HERMIT_ANALYZE_PARTIAL_EXIT`].
    fn report_partial(&mut self, expired: BudgetExpired) -> anyhow::Result<ExitStatus> {
        let progress = self.progress.snapshot();
        let workspace = self.get_tmp()?.to_path_buf();
        let budget = self.budget.clone();
        let elapsed = budget.elapsed();
        let in_workspace = |path: &Path| {
            path.strip_prefix(&workspace)
                .unwrap_or(path)
                .display()
                .to_string()
        };

        let mut header = format!(
            "PARTIAL RESULT. hermit analyze reached its {}{} after {} s, while {}, so what \
             follows is its best answer so far, not the critical events.\n",
            expired.kind.option(),
            match expired.kind {
                BudgetKind::TimeBudget =>
                    budget
                        .time_limit()
                        .map_or_else(String::new, |limit| format!(
                            " ({})",
                            budget::describe(limit)
                        )),
                BudgetKind::TrialBudget => budget
                    .trial_limit()
                    .map_or_else(String::new, |limit| format!(" ({limit} runs)")),
            },
            elapsed.as_secs(),
            progress.phase.describe(),
        );
        if let Some(run) = &expired.cut {
            header.push_str(&format!(
                "The budget cut {run} short; its outcome is not counted, and a resumed analysis \
                 runs it again.\n"
            ));
        }
        let mut replay_commands = Vec::new();
        let mut critical = [None, None];
        let mut stacks =
            "not applicable: the default search had no pair of schedules yet".to_owned();
        // The events the report's structured fields name: the critical pair's
        // and the deciding event's indices.
        let mut critical_indices = progress
            .interval
            .as_ref()
            .map_or([0, 0], |interval| [interval.common_prefix; 2]);
        let mut deciding_event = None;
        if let Some(decided) = &progress.decided {
            header.push_str(&format!(
                "The search had finished: {decided}. Its stack-trace runs did not finish within \
                 the budget; --resume takes them.\n"
            ));
            // A budget hit after the search decided still reports the
            // decision, in the fields a complete report puts it in; only the
            // stacks are missing.
            stacks = "not taken: the budget ran out during the stack-trace runs; --resume takes \
                      them"
                .to_owned();
            match progress.decision {
                Some(DecidedEvents::Deciding(decision)) => {
                    critical_indices = [decision; 2];
                    deciding_event = Some(ReportCriticalEvent {
                        event_index: decision,
                        stack: None,
                    });
                }
                Some(DecidedEvents::CriticalPair(first, second)) => {
                    critical_indices = [first, second];
                }
                None => {}
            }
        } else if let Some(interval) = &progress.interval
            && progress.phase == Phase::Bisect
        {
            header.push_str(&format!(
                "The closest pair the default search found{}: a schedule whose replay misses the \
                 target ({}, {} events) and one whose replay meets it ({}, {} events){}. ",
                match interval.pass {
                    Some(pass) => format!(" in {} passes", pass),
                    None => " (its endpoint runs; the search had not replayed them yet)".to_owned(),
                },
                in_workspace(&interval.passing),
                interval.passing_events,
                in_workspace(&interval.failing),
                interval.failing_events,
                match (interval.edit_distance, interval.swap_distance) {
                    (Some(edit), Some(swap)) => {
                        format!(", at edit distance {edit} and swap distance {swap}")
                    }
                    _ => String::new(),
                },
            ));
            header.push_str(&format!(
                "They agree on their first {} events, so the deciding event is event #{} or a \
                 later one: {}.\n",
                interval.common_prefix,
                interval.common_prefix,
                match (&interval.passing_event, &interval.failing_event) {
                    (Some(passing), Some(failing)) => format!(
                        "there the passing schedule runs {passing}, and the failing one {failing}"
                    ),
                    _ => "there one of them has already ended".to_owned(),
                }
            ));
            for (which, path) in [
                ("passing", &interval.passing),
                ("failing", &interval.failing),
            ] {
                // Each its own name, so that the two can run at once.
                replay_commands.push(
                    RunData::new_baseline(self, format!("interval_{which}_replay"))?
                        .with_schedule_replay_from(path.clone())
                        .to_repro(),
                );
            }
            let taken;
            (critical, taken) = self.partial_stacks(interval);
            stacks = taken;
            header.push_str(&format!("Stack traces: {stacks}.\n"));
        } else if let Some(bracket) = &progress.bracket
            && progress.phase == Phase::PrefixSearch
        {
            stacks = "not taken: a prefix search's bracket names a range of events".to_owned();
            header.push_str(&describe_bracket(bracket));
            for run in [&bracket.misses_run, &bracket.meets_run]
                .into_iter()
                .flatten()
            {
                if let Ok(command) =
                    std::fs::read_to_string(workspace.join(run).with_extension("repro"))
                {
                    replay_commands.push(command.trim_end().to_owned());
                }
            }
        } else {
            header.push_str(
                "The analysis had not reached its search yet, so there is no pair of schedules or \
                 bracket to report.\n",
            );
        }
        let runs_from_journal = self.journal.answered();
        header.push_str(&format!(
            "This invocation started {} runs{}.\n",
            budget.trials_started(),
            if runs_from_journal > 0 {
                format!(" and took {runs_from_journal} from the journal of an earlier one")
            } else {
                String::new()
            }
        ));
        let resume_command = resume_command(&workspace);
        header.push_str(&format!(
            "The workspace is kept: {}\nContinue the analysis with (add a budget to bound it \
             again):\n  {resume_command}\n",
            workspace.display()
        ));

        let [critical1, critical2] = critical;
        let report = Report {
            header: header.clone(),
            additional_context: String::new(),
            baseline_run: true,
            critical_event1: Some(ReportCriticalEvent {
                event_index: critical_indices[0],
                stack: critical1,
            }),
            critical_event2: Some(ReportCriticalEvent {
                event_index: critical_indices[1],
                stack: critical2,
            }),
            branch_counter_warning: self.branch_counter_warning.clone(),
            deciding_event,
            partial: Some(PartialReport {
                reason: expired.kind,
                phase: progress.phase,
                elapsed_seconds: elapsed.as_secs(),
                time_budget_seconds: budget.time_limit().map(|limit| limit.as_secs()),
                runs_started: budget.trials_started(),
                trial_budget: budget.trial_limit(),
                runs_from_journal,
                cut_run: expired.cut.clone(),
                interval: progress.interval.clone(),
                bracket: progress.bracket.clone(),
                decided: progress.decided.clone(),
                stacks,
                replay_commands,
                workspace: workspace.clone(),
                resume_command,
            }),
            racing_accesses: None,
            verdict: Verdict::CriticalEvents,
            verdict_reason: None,
        };
        println!(
            "\n------------------------- hermit analyze report (PARTIAL) -------------------------"
        );
        if let Some(warning) = &self.branch_counter_warning {
            println!("{warning}");
        }
        println!("{header}");
        if let Some(ReportCriticalEvent {
            event_index: event_index_1,
            stack: Some(stack),
            ..
        }) = &report.critical_event1
        {
            println!("The passing schedule's thread at event #{}:", event_index_1);
            println!("{stack}");
        }
        if let Some(ReportCriticalEvent {
            event_index: event_index_2,
            stack: Some(stack),
            ..
        }) = &report.critical_event2
        {
            println!("The failing schedule's thread at event #{}:", event_index_2);
            println!("{stack}");
        }
        note(&format!(
            "HERMIT_ANALYZE_PARTIAL class={} phase={} workspace={}",
            expired.kind.class(),
            serde_json::to_value(progress.phase)
                .ok()
                .and_then(|phase| phase.as_str().map(str::to_owned))
                .unwrap_or_default(),
            workspace.display()
        ));
        if let Some(path) = &self.report_file {
            std::fs::write(path, serde_json::to_string(&report)?)
                .with_context(|| format!("cannot write the report to {}", path.display()))?;
            eprintln!(
                ":: {}\n {}",
                "Partial analysis report written to:".yellow().bold(),
                path.display()
            );
        }
        self.partial_report_written = true;
        Ok(ExitStatus::Exited(hermit::HERMIT_ANALYZE_PARTIAL_EXIT))
    }

    /// The stacks of the threads the two schedules of the default search's
    /// `interval` run at the first event at which they differ, and what the
    /// report says about them. They are taken only when two replays as slow
    /// as the slowest endpoint run fit the grace period after the budget ran
    /// out ([`Budget::stack_grace`]), and each replay is bounded by what is
    /// left of it.
    fn partial_stacks(&self, interval: &BisectInterval) -> ([Option<PrettyBacktrace>; 2], String) {
        let grace = self.budget.stack_grace();
        let fits = self
            .endpoints
            .slowest
            .is_some_and(|slowest| slowest * 2 <= grace);
        if !fits {
            return (
                [None, None],
                format!(
                    "not taken: two replays as slow as the slowest endpoint run ({}) do not fit \
                     the grace period of {} s after the budget ran out (min(120 s, 5% of \
                     --time-budget)); the replay commands below take them",
                    self.endpoints
                        .slowest
                        .map_or("not measured".to_owned(), |slowest| format!(
                            "{} s",
                            slowest.as_secs()
                        )),
                    grace.as_secs()
                ),
            );
        }
        self.budget.open_grace(grace);
        let mut stacks = [None, None];
        let mut missing = Vec::new();
        for (slot, (which, path)) in [
            ("passing", &interval.passing),
            ("failing", &interval.failing),
        ]
        .into_iter()
        .enumerate()
        {
            let taken = (|| -> anyhow::Result<Option<PrettyBacktrace>> {
                let mut run = RunData::new_baseline(self, format!("partial_{which}_stack"))?
                    .with_schedule_replay_from(path.clone());
                let stack_path = run.root_path().with_extension("stack");
                run.runopts.det_opts.det_config.stacktrace_event =
                    vec![(interval.common_prefix as u64, Some(stack_path.clone()))];
                match run.launch() {
                    Ok(()) => {}
                    Err(error) if error.downcast_ref::<RunTimeoutMarker>().is_some() => {}
                    Err(error) => return Err(error),
                }
                Ok(File::open(&stack_path)
                    .ok()
                    .and_then(|file| serde_json::from_reader(file).ok()))
            })();
            match taken {
                Ok(Some(stack)) => stacks[slot] = Some(stack),
                Ok(None) => missing.push(format!("the {which} replay left no stack there")),
                Err(error) if error.downcast_ref::<BudgetExpired>().is_some() => {
                    missing.push(format!(
                        "the {which} replay did not fit the grace period of {} s",
                        grace.as_secs()
                    ));
                }
                Err(error) => missing.push(format!("the {which} replay failed: {error:#}")),
            }
        }
        self.budget.close_grace();
        let said = if missing.is_empty() {
            format!(
                "taken from replays of both schedules within the grace period of {} s",
                grace.as_secs()
            )
        } else {
            format!("partly or not taken: {}", missing.join("; "))
        };
        (stacks, said)
    }

    /// The analysis, in the workspace phase 0 created.
    fn analyze_steps(&mut self, global: &GlobalOpts) -> anyhow::Result<ExitStatus> {
        self.progress.phase(Phase::TargetRun);
        {
            let dummy = RunData::new_baseline(self, "dummy".to_string())?;
            if !dummy.runopts.det_opts.det_config.chaos {
                eprintln!(
                    ":: {} You may want to turn it on explicitly, along with a --max-timeslice that works well for this program.",
                    "WARNING: implicitly activating --chaos.".yellow().bold()
                );
            }
        }

        let run1data = self.phase1_establish_target_run()?;

        let mut min_run = self.phase2_minimize(global, run1data)?;
        self.phase3_strict_preempt_replay_check(global, &mut min_run)?;

        // The record the target endpoint replays, and the one --minimize's
        // baseline knocks a preemption out of, is the record that met the
        // target: a normalized copy renumbers its priorities across the
        // scheduler's fixed ones (the default priority, among others), and
        // can run another schedule.
        let (normalized_path, normalized) = min_run.write_normalized_preempts();
        eprintln!(
            ":: {}\n {}",
            format!(
                "Normalized for reading ({}; analyze uses {}), that preemption record \
                 becomes:",
                normalized_path.file_name().unwrap().to_string_lossy(),
                min_run
                    .preempts_path_out()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
            )
            .green()
            .bold(),
            truncated(
                1000,
                serde_json::to_string_pretty(&normalized.clone_preemptions_only()).unwrap()
            )
        );
        let target_preempts = min_run.preempts_out().clone();

        // One endpoint of the bisection search:
        let mut target_endpoint_run = self.save_final_target_sched_events(min_run)?;

        if self.prefix_search {
            return self.prefix_search_and_report(&mut target_endpoint_run);
        }

        // The other endpoint of the bisection search:
        // What we thought was the final_pr can change here:
        let mut baseline_endpoint_run =
            match self.phase4_choose_baseline_sched_events(target_preempts) {
                Ok(run) => run,
                // A baseline run that did not finish, or no knock-out left,
                // gives no schedule to bisect against; the decision is still
                // within the target schedule, which a prefix search needs
                // alone.
                Err(error)
                    if error.downcast_ref::<BaselineUnfinished>().is_some()
                        || error.downcast_ref::<NothingToKnockOut>().is_some() =>
                {
                    let hint = if error.downcast_ref::<BaselineUnfinished>().is_some() {
                        "; a larger --trial-timeout or --trial-virtual-timeout may let the \
                         baseline finish"
                    } else {
                        ""
                    };
                    eprintln!(
                        ":: {} {error}\n:: Searching within the target schedule instead \
                         (--prefix-search){hint}.",
                        "No baseline:".yellow().bold(),
                    );
                    return self.prefix_search_and_report(&mut target_endpoint_run);
                }
                Err(error) => return Err(error),
            };

        // Endpoints recorded while replaying preemptions ran slices longer
        // than the bound, and the bisection's schedules must say so.
        let target_out = target_endpoint_run.sched_path_out().to_owned();
        let baseline_out = baseline_endpoint_run.sched_path_out().to_owned();
        self.adopt_uncapped_slices(&[target_out.as_path(), baseline_out.as_path()])?;
        let baseline_sched_name = baseline_endpoint_run.sched_out_file_name();
        let target_sched_name = target_endpoint_run.sched_out_file_name();
        let target = target_endpoint_run.preempts_out().clone();
        let baseline = baseline_endpoint_run.preempts_out().clone();

        eprintln!(
            ":: {} (event lengths {} / {}): {} {}",
            "Beginning bisection using endpoints".yellow().bold(),
            baseline.schedevents().len(),
            target.schedevents().len(),
            baseline_sched_name,
            target_sched_name,
        );
        let crit_sched = match own_bisection_end(self.phase5_bisect_traces(&target, &baseline))? {
            OwnBisectionEnd::Critical(crit_sched) => crit_sched,
            OwnBisectionEnd::SearchPrefixes(error) => {
                eprintln!(
                    ":: {} {error:#}\n:: Searching within the failing schedule instead \
                     (--prefix-search).",
                    "No single swap separates the endpoints:".yellow().bold(),
                );
                return self.prefix_search_and_report(&mut target_endpoint_run);
            }
        };

        let target_run = target_endpoint_run.root_path();
        let report =
            self.phase6_record_outputs(crit_sched, &[&target, &baseline], Some(&target_run))?;
        self.write_report_and_exit(report)
    }

    /// `--prefix-search` over the target endpoint's schedule, and its report.
    fn prefix_search_and_report(
        &mut self,
        target_endpoint_run: &mut RunData,
    ) -> anyhow::Result<ExitStatus> {
        let target = target_endpoint_run.preempts_out().clone();
        eprintln!(
            ":: {} ({} events): {}",
            "Beginning prefix search within the target schedule"
                .yellow()
                .bold(),
            target.schedevents().len(),
            target_endpoint_run.sched_out_file_name(),
        );
        let searched = self.phase5_prefix_search(&target);
        self.finish_prefix_search(searched)
    }

    /// Report what the prefix search `searched` found: the deciding event, or
    /// a verdict that names none, which completes the analysis too. Any other
    /// error ends it.
    pub(super) fn finish_prefix_search(
        &self,
        searched: anyhow::Result<PrefixDecision>,
    ) -> anyhow::Result<ExitStatus> {
        let decision = match searched {
            Ok(decision) => decision,
            Err(error) => {
                let verdict = error.downcast::<AnalyzeVerdict>()?;
                let verdict = self.with_timing_tried(verdict, |timing, continuation| {
                    self.try_alternative_timing(timing, continuation)
                });
                return self.write_verdict_and_exit(&verdict);
            }
        };
        let report = self.phase6_record_prefix_outputs(decision)?;
        self.write_report_and_exit(report)
    }

    /// `verdict`, reached by trials that all kept the recording's timing
    /// settings ([`Self::continuation_timing`]), with what one more trial
    /// shows about them: `try_alternative` runs the empty prefix under their
    /// alternatives. A recording given with `--run1-preemptions` fixes the
    /// trials' settings, so that trial is not run and the verdict says a new
    /// failing run can tell.
    pub(super) fn with_timing_tried(
        &self,
        verdict: AnalyzeVerdict,
        try_alternative: impl FnOnce(&[TimingSetting], MaybeTimeslice) -> AlternativeTiming,
    ) -> AnalyzeVerdict {
        let timing = self.continuation_timing();
        if timing.is_empty() {
            return verdict;
        }
        let tried = if self.run1_preemptions.is_some() {
            AlternativeTiming::Untried {
                why: "the failing run is a recording (--run1-preemptions), which every trial \
                      replays under the run arguments it was made with, so analyze runs no trial \
                      under others (a record stamped with one --pipe-wake-latency is refused \
                      under another)"
                    .to_owned(),
            }
        } else {
            try_alternative(&timing, verdict.continuation())
        };
        verdict.with_timing(&timing, tried)
    }

    /// Run the empty prefix, continued without chaos at `continuation` as
    /// the search's trials were, with the alternatives of `timing` in place
    /// of the settings: one deterministic trial, outside the search, that
    /// shows whether those settings make the scheduler alone meet the
    /// target.
    fn try_alternative_timing(
        &self,
        timing: &[TimingSetting],
        continuation: MaybeTimeslice,
    ) -> AlternativeTiming {
        self.try_alternative_timing_with(timing, |alternative, runname| {
            let empty = PreemptionRecord::from_sched_events(Vec::new());
            alternative
                .prefix_trial(runname, &empty, 0, continuation)
                .and_then(|mut run| alternative.launch_prefix_trial(&mut run))
        })
    }

    /// [`Self::try_alternative_timing`], with `launch` running the trial
    /// (`runname`) on the options it is given, these options under the
    /// alternatives: how it ended decides the cause. A trial that missed
    /// shows the settings cause the outcome; one that met the target shows
    /// they do not; one that did not finish (a bound or a refusal) or could
    /// not run shows nothing, and the verdict says it was not tried.
    fn try_alternative_timing_with(
        &self,
        timing: &[TimingSetting],
        launch: impl FnOnce(&AnalyzeOpts, &str) -> anyhow::Result<TrialEnd>,
    ) -> AlternativeTiming {
        let runname = "prefix_alternative_timing";
        let trial = format!("{runname}.repro");
        let mut alternative = self.clone();
        for setting in timing {
            alternative.run_arg = without_option(&alternative.run_arg, setting.drops);
            alternative.run_args = without_option(&alternative.run_args, setting.drops);
            alternative.run_arg.extend(setting.adds.clone());
        }
        eprintln!(
            ":: Trying the empty prefix with {} instead of {}",
            timing
                .iter()
                .map(|t| t.alternative.as_str())
                .collect::<Vec<_>>()
                .join(" and "),
            timing
                .iter()
                .map(|t| t.option.as_str())
                .collect::<Vec<_>>()
                .join(" and ")
        );
        match launch(&alternative, runname) {
            Ok(TrialEnd::Missed) => AlternativeTiming::Missed { trial },
            Ok(TrialEnd::Met) => AlternativeTiming::Met { trial },
            Ok(end @ TrialEnd::Unfinished(_)) => AlternativeTiming::Untried {
                why: format!(
                    "the trial with them ({trial} in the workspace) {}",
                    describe_trial_end(end, None)
                ),
            },
            Err(error) => AlternativeTiming::Untried {
                why: format!("the trial with them could not run ({error:#})"),
            },
        }
    }

    /// What follows a first run that missed the target: `--search` (`search`),
    /// or the end of the analysis, its input not giving it a target run.
    pub(super) fn after_a_first_run_that_missed(
        &self,
        search: impl FnOnce() -> anyhow::Result<RunData>,
    ) -> anyhow::Result<RunData> {
        if self.search {
            eprintln!(
                ":: {}",
                "First run did not match target criteria; now searching for a matching run..."
                    .red()
                    .bold()
            );
            search()
        } else {
            Err(AnalyzePrecondition::target_not_reproduced(
                "FAILED. The run did not match the target criteria. Try --search.",
            )
            .into())
        }
    }

    /// Report `verdict`, a completed analysis that names no event: print it
    /// as analyze prints any report, write it to `--report-file`, if given,
    /// and return the exit status of a successful analysis, with the class
    /// line on stderr.
    pub(super) fn write_verdict_and_exit(
        &self,
        verdict: &AnalyzeVerdict,
    ) -> anyhow::Result<ExitStatus> {
        println!(
            "\n------------------------------ hermit analyze report ------------------------------"
        );
        if let Some(warning) = &self.branch_counter_warning {
            println!("{warning}");
        }
        println!("{verdict}");
        self.write_report_file(&Report {
            verdict: verdict.verdict(),
            verdict_reason: Some(verdict.reason().clone()),
            header: verdict.to_string(),
            additional_context: String::new(),
            baseline_run: false,
            critical_event1: None,
            critical_event2: None,
            branch_counter_warning: self.branch_counter_warning.clone(),
            deciding_event: None,
            partial: None,
            racing_accesses: None,
        });
        eprintln!("{}", verdict.class_line());
        self.success_status()
    }

    /// Write `report` to `--report-file`, if given, and return the exit status
    /// of a successful analysis.
    fn write_report_and_exit(&self, report: Report) -> anyhow::Result<ExitStatus> {
        self.write_report_file(&report);
        self.success_status()
    }

    /// Write `report` to `--report-file`, if given.
    fn write_report_file(&self, report: &Report) {
        if let Some(path) = &self.report_file {
            let txt = serde_json::to_string(report).unwrap();
            std::fs::write(path, txt).expect("Unable to write report file");
            eprintln!(
                ":: {}\n {}",
                "Final analysis report written to:".green().bold(),
                path.display()
            );
        }
    }

    /// The exit status of a successful analysis: 0, or `--success-exit-code`.
    fn success_status(&self) -> anyhow::Result<ExitStatus> {
        self.success_exit_code
            .map_or(Ok(ExitStatus::SUCCESS), |exit_code| {
                Ok(ExitStatus::Exited(exit_code))
            })
    }

    /// This extra run, to record the schedule, thus converting Preemptions to a full Schedule
    /// would be unnecessary if we recorded that each time as we minimize.
    ///
    /// Argument: the last on-target run that was preemption based.
    fn save_final_target_sched_events(&mut self, mut last_run: RunData) -> anyhow::Result<RunData> {
        let pr = last_run.preempts_out();
        if pr.contains_schedevents() {
            let path = last_run.preempts_path_out();
            // This run already has sched events recorded... no extra run necessary.
            yellow_msg(&format!(
                "Using the last run as the target endpoint ({} contains sched events)",
                path.file_name().unwrap().to_string_lossy()
            ));
            Ok(last_run)
        } else {
            // Verify that the new preemption record does in fact now cause a matching execution,
            // and rerecord during this verification with full recording that include sched events
            self.progress.phase(Phase::TargetSchedule);
            yellow_msg(
                "Verify target endpoint preemption record causes criteria to hold and record sched events",
            );
            let runname = "verify_target_endpoint";
            let newrun = RunData::new(self, runname.to_string(), last_run.runopts.clone());
            let mut newrun = self
                .replaying_the_target_record(newrun, last_run.preempts_path_out().to_path_buf())
                .with_schedule_recording();
            newrun.launch()?;
            self.record_endpoint(&newrun);
            eprintln!("    {}", newrun.to_repro());
            if !newrun.is_a_match() {
                return Err(AnalyzePrecondition::target_not_reproduced(
                    "Final preemption record still does not match target criteria",
                )
                .into());
            }
            Ok(newrun)
        }
    }

    // Returns the record, with one knockout, if it still satisfies the criteria that we want it not to.
    fn save_nearby_non_matching_sched_events(
        &self,
        runname: &str,
        non_matching_preempts: &PreemptionRecord,
    ) -> anyhow::Result<(bool, RunData)> {
        // Given preemptions that hermit analyze has determined are critical to match the criteria
        // (most commonly, a failing execution), removing the last critical preemption
        // ([`knock_out_latest`]) should cause the minimal execution change to now no longer match
        // the criteria (most commonly, an execution that now passes).

        // Validate the preemption record
        if let Err(e) = non_matching_preempts.validate() {
            bail!(
                "Hermit analyzer produced corrupt nearby non-matching preemption record, cannot proceed.\n\
                Error: {}\n\n\
                Corrupt record: {}",
                e,
                non_matching_preempts,
            );
        }

        let mut newrun = RunData::new_baseline(self, runname.to_string())?
            .with_preempts_in(non_matching_preempts.clone())
            .with_schedule_recording();

        // Verify that the new preemption record does in fact now cause a non-matching execution,
        // and rerecord during this verification with full recording that include sched events
        yellow_msg(
            "Verify preemption record *without* latest critical preempt causes criteria non-match. Also record sched events.",
        );
        if !newrun.launch_trial()?.finished() {
            return Err(BaselineUnfinished("--minimize's knock-out of its last preemption").into());
        }
        eprintln!("    {}", newrun.to_repro());
        if newrun.is_a_match() {
            eprintln!(
                "{}",
                ":: New preemption record still matches criteria! Attempting further knockouts.."
                    .red()
                    .bold(),
            );
            Ok((true, newrun))
        } else {
            Ok((false, newrun))
        }
    }

    /// Search for a target run. Return the run when found.
    fn do_search(&self) -> Result<RunData, Error> {
        self.search_rounds(|round, sched_seed| self.launch_search(round, sched_seed))
    }

    /// The `--search` loop: one chaos trial per round, each with the next
    /// schedule seed from the search RNG, until a trial matches. A trial that
    /// cannot finish (for example, one that `--max-log-bytes` ended) ends the
    /// search with its error unchanged, so main still reports it by its class.
    fn search_rounds(
        &self,
        mut launch: impl FnMut(u64, u64) -> Result<Option<RunData>, Error>,
    ) -> Result<RunData, Error> {
        let search_seed = match self.analyze_seed {
            Some(seed) if !self.analyze_seed_drawn => seed,
            drawn => {
                let seed = drawn.unwrap_or_else(rand::random);
                yellow_msg(&format!(
                    "WARNING: performing --search with system randomness, use --analyze-seed={} to repro.",
                    seed
                ));
                seed
            }
        };
        yellow_msg(&format!("Failure search using RNG seed {}", search_seed));
        let mut rng = Pcg64Mcg::seed_from_u64(search_seed);

        let mut round = 0;
        loop {
            let sched_seed = rng.random();
            if let Some(mut rundat) = launch(round, sched_seed)? {
                if self.verbose {
                    let preempts = rundat.preempts_path_out();
                    let init_schedule: PreemptionRecord =
                        PreemptionReader::new(preempts).load_all();
                    eprintln!(
                        ":: {}:\nSchedule:\n {}",
                        "Search successfully found a failing run with schedule:"
                            .green()
                            .bold(),
                        truncated(
                            1000,
                            serde_json::to_string(&init_schedule.clone_preemptions_only()).unwrap()
                        ),
                    );
                }
                return Ok(rundat);
            }
            round += 1;
        }
    }

    /// Does the run meet the criteria we are looking for (e.g. a particular error message).
    /// With `--verbose`, says which criteria it misses.
    pub fn output_matches(&self, out: &Output) -> bool {
        let misses = self.criteria_misses(out);
        if self.verbose {
            for miss in &misses {
                eprintln!("{miss}");
            }
        }
        misses.is_empty()
    }

    /// The target criteria `out` does not meet. (`RunData::launch` prints
    /// the guest's output under `--verbose`.)
    fn criteria_misses(&self, out: &Output) -> Vec<String> {
        let mut misses = Vec::new();
        for (stream, pattern, text) in [
            ("stdout", &self.target_stdout, &out.stdout),
            ("stderr", &self.target_stderr, &out.stderr),
        ] {
            if let Some(pattern) = pattern
                && !pattern.is_match(&String::from_utf8_lossy(text))
            {
                misses.push(format!("Mismatch for {stream} pattern {pattern}"));
            }
        }
        if !self.target_exit_code.is_match(out.status) {
            misses.push(format!(
                "  Exit code {} is not what we're looking for.",
                crate::analyze::types::run_exit_code(out.status)
            ));
        }
        misses
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser as _;

    use super::*;
    use crate::container::LogCapExceeded;
    use crate::container::PolicyRefusal;

    fn critical(tids: &[i32], index: usize) -> CriticalSchedule {
        let schedule: Vec<SchedEvent> = tids
            .iter()
            .map(|&tid| SchedEvent::branches(detcore::types::DetTid::from_raw(tid), 1))
            .collect();
        CriticalSchedule {
            failing_schedule: schedule.clone(),
            passing_schedule: schedule,
            critical_event_index: index,
        }
    }

    /// A `--prefix-search` trial replays the target record's first events
    /// together with the callback checkpoints of the slices those events
    /// end, so its slices end where the recording's did; a checkpoint past
    /// the prefix is dropped, and so is the one at its end while an event
    /// follows: that slice end is the next event's decision.
    /// A check of the baseline keeps the checkpoints of the baseline's own
    /// prefix, one event shorter than the target's, and neither keeps any
    /// past where the edit starts.
    #[test]
    fn a_check_keeps_the_checkpoints_of_its_own_runs_prefix() {
        assert_eq!(check_prefix_len(10, "target", 20), 10);
        assert_eq!(check_prefix_len(10, "baseline", 20), 9);
        assert_eq!(check_prefix_len(10, "target", 4), 4);
        assert_eq!(check_prefix_len(10, "baseline", 4), 4);
    }

    #[test]
    fn a_prefix_trial_keeps_the_target_checkpoints_within_its_prefix() {
        let parent = tempfile::tempdir().unwrap();
        let tmp_dir = format!("--tmp-dir={}", parent.path().display());
        let mut options =
            AnalyzeOpts::try_parse_from(["analyze", tmp_dir.as_str(), "--", "/bin/true"]).unwrap();
        let _workspace = options.phase0_initialize(Retention::Remove).unwrap();
        let branches = |tid: i32, count: u32| {
            serde_json::json!({
                "dettid": tid, "op": "Branch", "count": count,
                "start_rip": null, "end_rip": null, "end_time": null
            })
        };
        let checkpoint = |row: usize, progress: u64, time: u64| {
            serde_json::json!({
                "history_index": row,
                "origin": {
                    "callback": "PmuTimer", "site": "Prehook", "progress": progress,
                    "last_op": "Branch", "time": time, "rcbs": progress
                }
            })
        };
        let target: PreemptionRecord = serde_json::from_value(serde_json::json!({
            "per_thread": {
                "3": {
                    "final_prio": 1000,
                    "prio_changes": [[100, 1000], [300, 1000]],
                    "preemption_rcbs": [10, 15]
                },
                "5": {"final_prio": 1000, "prio_changes": [[200, 1000]], "preemption_rcbs": [4]}
            },
            "global": [branches(3, 10), branches(5, 4), branches(3, 5)],
            "callback_checkpoints": {
                "3": [checkpoint(0, 10, 100), checkpoint(1, 15, 300)],
                "5": [checkpoint(0, 4, 200)]
            }
        }))
        .unwrap();
        target.validate().unwrap();
        for (len, kept) in [(0, 0), (1, 0), (2, 1), (3, 3)] {
            let mut run = options
                .prefix_trial("prefix_round", &target, len, None)
                .unwrap();
            let written: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(run.sched_path_in()).unwrap())
                    .unwrap();
            assert_eq!(written["global"].as_array().unwrap().len(), len);
            let points: usize = ["3", "5"]
                .iter()
                .map(|tid| {
                    written["callback_checkpoints"][tid]
                        .as_array()
                        .map_or(0, |points| points.len())
                })
                .sum();
            assert_eq!(points, kept, "prefix of {len}: {written}");
            PreemptionReader::new(run.sched_path_in())
                .load_all()
                .validate()
                .unwrap();
        }
    }

    /// The sentences a `--prefix-search` report gives its stacks present two
    /// threads at the deciding event as the pair whose order decides the
    /// outcome, and one thread, which the scheduler runs there without the
    /// event too, as that one thread: never as a race with itself.
    #[test]
    fn a_prefix_report_says_when_both_stacks_are_one_thread() {
        let (reader, binder) = (
            detcore::types::DetTid::from_raw(7),
            detcore::types::DetTid::from_raw(9),
        );
        let pair = stack_pair_sentences(binder, Some(reader), None, None);
        assert!(
            pair.contains("stack2 is the thread that runs there instead"),
            "{pair}"
        );
        assert!(pair.contains("which of the two runs first"), "{pair}");

        let one = stack_pair_sentences(reader, Some(reader), None, None);
        assert!(one.contains("both belong to thread 7"), "{one}");
        assert!(one.contains("not two threads racing"), "{one}");
        for race in ["runs there instead", "which of the two runs first"] {
            assert!(!one.contains(race), "{race:?} in\n{one}");
        }

        // A run without the event that ended before it keeps the usual
        // sentences: its stack2 is empty, and a warning says why.
        assert_eq!(stack_pair_sentences(reader, None, None, None), pair);

        // When a thread runs after the deciding thread's slice without the
        // event, stack2 is that thread: two threads, not one twice.
        let next = stack_pair_sentences(reader, Some(reader), Some((65712, binder)), None);
        assert!(
            next.contains("stack1 is thread 7 there; stack2 is thread 9, which runs after thread 7's slice without the event, at event #65712 of that continuation."),
            "{next}"
        );
        assert!(!next.contains("both belong to thread 7"), "{next}");
    }

    /// Realized-schedule events for the stack2 tests: a syscall stop and a
    /// branch event of thread `thread`.
    fn call(
        thread: i32,
        sysno: reverie::syscalls::Sysno,
        phase: detcore_model::schedule::SyscallPhase,
    ) -> SchedEvent {
        SchedEvent::syscall(DetTid::from_raw(thread), sysno, phase)
    }

    fn branch(thread: i32) -> SchedEvent {
        SchedEvent::branches(DetTid::from_raw(thread), 7)
    }

    /// A thread created at the deciding event's boundary. Thread 3's slice
    /// (the event) runs first with it; without it, thread 1 returns from
    /// creating a thread, thread 2 (created before, never run) takes its
    /// first turn and sleeps, and thread 4 wakes, all before thread 3. stack2
    /// was thread 1 in pthread_create; it is now thread 2, at the end of its
    /// first turn (where it starts says nothing), and the report says that
    /// thread 1 was passed over.
    #[test]
    fn a_thread_created_at_the_boundary_is_passed_over_for_the_thread_it_moves() {
        use detcore_model::schedule::SyscallPhase::Posthook;
        use detcore_model::schedule::SyscallPhase::Prehook;
        use reverie::syscalls::Sysno;
        // Threads 3 and 4 run before thread 1 calls clone, so it creates
        // neither of them.
        let prefix = [
            branch(3),
            call(3, Sysno::nanosleep, Prehook),
            branch(4),
            call(4, Sysno::nanosleep, Prehook),
            call(1, Sysno::clone, Prehook),
        ];
        let decision = prefix.len();
        let creator = [
            call(1, Sysno::clone, Posthook),
            call(1, Sysno::rt_sigprocmask, Prehook),
            call(1, Sysno::rt_sigprocmask, Posthook),
            call(1, Sysno::futex, Prehook),
        ];
        let consumer = [
            branch(2),
            call(2, Sysno::prctl, Prehook),
            call(2, Sysno::prctl, Posthook),
            call(2, Sysno::nanosleep, Prehook),
        ];
        let sleeper = [
            call(4, Sysno::nanosleep, Posthook),
            call(4, Sysno::nanosleep, Prehook),
        ];
        let deciding = [
            call(3, Sysno::nanosleep, Posthook),
            branch(3),
            call(3, Sysno::write, Prehook),
        ];
        let without: Vec<SchedEvent> =
            [&prefix[..], &creator, &consumer, &sleeper, &deciding].concat();
        let with: Vec<SchedEvent> =
            [&prefix[..], &deciding, &creator, &consumer, &sleeper].concat();
        let consumer_ends = decision + creator.len() + consumer.len() - 1;
        let thread3 = DetTid::from_raw(3);
        let moved = moved_past(&without, Side::Without, decision, thread3).unwrap();
        assert_eq!(
            (moved.side, moved.thread, moved.event),
            (Side::Without, DetTid::from_raw(2), consumer_ends)
        );
        assert!(
            moved.why.starts_with(
                "thread 2 runs before thread 3's turn without the event and after it with it; \
                 thread 1, which runs before it, only returns from creating a thread. Thread 2 \
                 starts in that turn, so its stack is where the turn ends, at its nanosleep \
                 call, where it blocks or waits"
            ),
            "{}",
            moved.why
        );
        // The two continuations say the same.
        assert_eq!(
            partner_turn(&with, &without, decision, thread3),
            Some(moved.clone())
        );
        let header = stack_pair_sentences(thread3, Some(DetTid::from_raw(1)), None, Some(&moved));
        assert!(
            header.contains(&format!(
                "without the event the scheduler runs thread 1 there instead. stack2 is thread 2, \
                 at event #{consumer_ends} of the continuation without the event: thread 2 runs"
            )),
            "{header}"
        );
        assert!(
            header.contains("which of threads 3 and 2 runs first"),
            "{header}"
        );

        // When only the creator moved, it is stack2 after all.
        let alone: Vec<SchedEvent> = [&prefix[..], &creator, &deciding].concat();
        let moved = moved_past(&alone, Side::Without, decision, thread3).unwrap();
        assert_eq!((moved.thread, moved.event), (DetTid::from_raw(1), decision));
        assert!(
            moved.why.ends_with("as every thread that moved does"),
            "{}",
            moved.why
        );
    }

    /// A consumer whose order against the deciding thread flips: without the
    /// event, the consumer wakes from its wait and drains before thread 3's
    /// next turn; with it, after. stack2 is the consumer where it resumes,
    /// in either continuation's terms.
    #[test]
    fn the_consumer_the_deciding_turn_moves_past_is_stack2() {
        use detcore_model::schedule::SyscallPhase::Posthook;
        use detcore_model::schedule::SyscallPhase::Prehook;
        use reverie::syscalls::Sysno;
        let prefix = [
            branch(2),
            call(2, Sysno::futex, Prehook),
            branch(3),
            call(3, Sysno::nanosleep, Prehook),
        ];
        let decision = prefix.len();
        let consumer = [
            call(2, Sysno::futex, Posthook),
            branch(2),
            call(2, Sysno::read, Prehook),
            call(2, Sysno::read, Posthook),
            call(2, Sysno::futex, Prehook),
        ];
        let producer = [
            call(3, Sysno::nanosleep, Posthook),
            branch(3),
            call(3, Sysno::write, Prehook),
            call(3, Sysno::write, Posthook),
            call(3, Sysno::nanosleep, Prehook),
        ];
        let without: Vec<SchedEvent> = [&prefix[..], &consumer, &producer].concat();
        let with: Vec<SchedEvent> = [&prefix[..], &producer, &consumer].concat();
        let thread3 = DetTid::from_raw(3);
        let partner = partner_turn(&with, &without, decision, thread3).unwrap();
        assert_eq!(
            (partner.side, partner.thread, partner.event),
            (Side::Without, DetTid::from_raw(2), decision)
        );
        assert_eq!(
            partner.why,
            "thread 2 runs before thread 3's turn without the event and after it with it"
        );
        // The other way round, the consumer moved in the continuation with
        // the event, and its stack comes from there.
        let partner = partner_turn(&without, &with, decision, thread3).unwrap();
        assert_eq!(
            (partner.side, partner.thread, partner.event),
            (Side::With, DetTid::from_raw(2), decision)
        );
    }

    /// The deciding thread runs the same slice either way, and the
    /// continuations run the same turns until thread 19's, which runs longer
    /// with the event. stack2 was the thread after the deciding thread's
    /// slice, created there (its stack at its start); it is now thread 19,
    /// at the last event both continuations give its turn.
    #[test]
    fn a_turn_that_runs_longer_names_its_thread_where_the_continuations_part() {
        use detcore_model::schedule::SyscallPhase::Posthook;
        use detcore_model::schedule::SyscallPhase::Prehook;
        use reverie::syscalls::Sysno;
        let prefix = [
            call(19, Sysno::futex, Prehook),
            call(3, Sysno::futex, Prehook),
        ];
        let decision = prefix.len();
        let shared = [
            call(3, Sysno::futex, Posthook),
            call(3, Sysno::clone3, Prehook),
            branch(21),
            call(21, Sysno::futex, Prehook),
            call(3, Sysno::clone3, Posthook),
            call(3, Sysno::futex, Prehook),
        ];
        let reads = |count: usize| {
            let mut turn = vec![call(19, Sysno::futex, Posthook)];
            for _ in 0..count {
                turn.push(call(19, Sysno::clock_gettime, Prehook));
                turn.push(call(19, Sysno::clock_gettime, Posthook));
            }
            turn.push(call(19, Sysno::futex, Prehook));
            turn
        };
        let after = [
            call(21, Sysno::futex, Posthook),
            call(21, Sysno::exit, Prehook),
        ];
        let with: Vec<SchedEvent> = [&prefix[..], &shared, &reads(5), &after].concat();
        let without: Vec<SchedEvent> = [&prefix[..], &shared, &reads(1), &after].concat();
        let partner = partner_turn(&with, &without, decision, DetTid::from_raw(3)).unwrap();
        let turn_starts = decision + shared.len();
        assert_eq!(
            (partner.side, partner.thread, partner.event),
            (Side::Without, DetTid::from_raw(19), turn_starts + 3)
        );
        assert_eq!(
            partner.why,
            format!(
                "the continuations run the same turns until thread 19's from event \
                 #{turn_starts}, which runs 12 events with the event and 4 without it; its \
                 stack is where the two part"
            )
        );
        // Continuations that do not differ before one ends name no thread.
        assert_eq!(
            partner_turn(&with, &with, decision, DetTid::from_raw(3)),
            None
        );
    }

    /// Where two realized schedules first run different threads, a turn
    /// that only returns from creating a thread gives way to the next one,
    /// a thread's first turn is shown where it ends, and a turn that runs on
    /// from before stays where the schedules part.
    #[test]
    fn a_realized_pair_passes_over_a_creator_and_a_thread_start() {
        use detcore_model::schedule::SyscallPhase::Posthook;
        use detcore_model::schedule::SyscallPhase::Prehook;
        use reverie::syscalls::Sysno;
        let schedule = [
            call(3, Sysno::read, Prehook),
            call(1, Sysno::clone, Prehook),
            call(3, Sysno::read, Posthook),
            call(1, Sysno::clone, Posthook),
            call(1, Sysno::futex, Prehook),
            branch(2),
            call(2, Sysno::nanosleep, Prehook),
            call(3, Sysno::write, Prehook),
            call(3, Sysno::write, Posthook),
        ];
        let tid = DetTid::from_raw;
        // Against thread 3, which ran before the clone, thread 1 only
        // finishes creating thread 2, which starts next.
        let creating_two = telling_event_at(&schedule, 3, tid(3)).unwrap();
        assert_eq!(
            creating_two,
            Telling {
                event: 6,
                thread: tid(2),
                creator: Some(tid(1)),
                starts: true,
                ends_at: Some(Sysno::nanosleep),
            }
        );
        // Against thread 2 itself, the creator stays: what it does next is
        // what its new thread races with.
        assert_eq!(
            telling_event_at(&schedule, 3, tid(2)),
            Some(Telling {
                event: 3,
                thread: tid(1),
                creator: None,
                starts: false,
                ends_at: Some(Sysno::futex),
            })
        );
        // A turn that runs on from before stays where the schedules part;
        // one that starts there is shown where it resumes.
        assert_eq!(
            telling_event_at(&schedule, 8, tid(1)),
            Some(Telling {
                event: 8,
                thread: tid(3),
                creator: None,
                starts: false,
                ends_at: None,
            })
        );
        assert_eq!(
            telling_event_at(&schedule, 7, tid(1)).map(|at| at.event),
            Some(7)
        );
        assert_eq!(
            telling_sentence("failing", "stack2", 3, &creating_two).as_deref(),
            Some(
                "In the replay of the failing schedule, thread 1 at event #3 only returns from \
                 creating a thread, so stack2 is thread 2, which runs next, which starts in that \
                 turn: it is shown where the turn ends, at event #6, at its nanosleep call, \
                 where it blocks or waits.\n"
            )
        );
        assert_eq!(
            telling_sentence(
                "passing",
                "stack1",
                8,
                &telling_event_at(&schedule, 8, tid(1)).unwrap()
            ),
            None
        );
    }

    /// A creator is passed over only when its turn only finishes the
    /// creation, and never for the thread it created: in a thread-start
    /// race the creator's next steps are what the new thread races with. A
    /// creator that goes on to make another call, or runs long after the
    /// return, is a thread like any other, and a forked child, whose first
    /// turn begins with the fork's return too, is not a creator. A first
    /// turn the scheduler preempted is shown where it was preempted.
    #[test]
    fn a_creator_is_passed_over_only_when_it_only_finishes_creating_another_thread() {
        use detcore_model::schedule::SyscallPhase::Posthook;
        use detcore_model::schedule::SyscallPhase::Prehook;
        use reverie::syscalls::Sysno;
        let tid = DetTid::from_raw;
        let epilogue = [
            call(1, Sysno::clone, Posthook),
            call(1, Sysno::rt_sigprocmask, Prehook),
            call(1, Sysno::rt_sigprocmask, Posthook),
            call(1, Sysno::futex, Prehook),
        ];
        let consumer = [
            call(2, Sysno::futex, Posthook),
            call(2, Sysno::read, Prehook),
        ];
        let deciding = [call(3, Sysno::nanosleep, Posthook), branch(3)];
        let moved = |prefix: &[SchedEvent], creator: &[SchedEvent]| {
            let without: Vec<SchedEvent> = [prefix, creator, &consumer, &deciding].concat();
            moved_past(&without, Side::Without, prefix.len(), tid(3)).unwrap()
        };
        // Threads 2 and 3 ran before thread 1's clone: it only finishes
        // creating another thread, and is passed over.
        let before = [
            call(2, Sysno::futex, Prehook),
            call(3, Sysno::nanosleep, Prehook),
            call(1, Sysno::clone, Prehook),
        ];
        assert_eq!(moved(&before, &epilogue).thread, tid(2));
        // Thread 3 starts after the clone: thread 1 created it, and its
        // turn after the return is what thread 3 races with.
        let creates_three = [
            call(2, Sysno::futex, Prehook),
            call(1, Sysno::clone, Prehook),
            branch(3),
            call(3, Sysno::nanosleep, Prehook),
        ];
        let partner = moved(&creates_three, &epilogue);
        assert_eq!(
            (partner.thread, partner.event),
            (tid(1), creates_three.len())
        );
        assert!(
            partner
                .why
                .ends_with("; it returns from creating thread 3, which its next steps race with"),
            "{}",
            partner.why
        );
        // A creator that goes on to write, or to run long, is not passed over.
        let mut writes = epilogue.to_vec();
        writes.insert(3, call(1, Sysno::write, Prehook));
        writes.insert(4, call(1, Sysno::write, Posthook));
        assert_eq!(moved(&before, &writes).thread, tid(1));
        let mut runs_long = epilogue.to_vec();
        runs_long.insert(3, SchedEvent::branches(tid(1), 257));
        assert_eq!(moved(&before, &runs_long).thread, tid(1));
        let mut runs_briefly = epilogue.to_vec();
        runs_briefly.insert(3, SchedEvent::branches(tid(1), 256));
        assert_eq!(moved(&before, &runs_briefly).thread, tid(2));
        // A forked child's first turn begins with the fork's return.
        let child = [
            call(4, Sysno::clone, Posthook),
            call(4, Sysno::futex, Prehook),
        ];
        let without: Vec<SchedEvent> = [&before[..], &child, &consumer, &deciding].concat();
        let partner = moved_past(&without, Side::Without, before.len(), tid(3)).unwrap();
        assert_eq!((partner.thread, partner.event), (tid(4), before.len() + 1));
        assert!(
            partner
                .why
                .ends_with("at its futex call, where it blocks or waits"),
            "{}",
            partner.why
        );
        // A first turn that ends without entering a call was preempted.
        let preempted = [branch(5), SchedEvent::branches(tid(5), 9)];
        let without: Vec<SchedEvent> = [&before[..], &preempted, &deciding].concat();
        let partner = moved_past(&without, Side::Without, before.len(), tid(3)).unwrap();
        assert!(
            partner
                .why
                .ends_with("where it was preempted, at an arbitrary instruction"),
            "{}",
            partner.why
        );
    }

    /// Phase 6 takes stack2 where [`stack2_plan`] says: past a creator to
    /// the thread the deciding turn moved, at the end of its first turn,
    /// when another thread runs at the decision without the event; the first
    /// thread whose turn differs when the deciding thread runs there either
    /// way; the thread after its slice only when the continuations do not
    /// differ.
    #[test]
    fn phase6_takes_stack2_where_the_plan_says() {
        use detcore_model::schedule::SyscallPhase::Posthook;
        use detcore_model::schedule::SyscallPhase::Prehook;
        use reverie::syscalls::Sysno;
        let tid = DetTid::from_raw;
        // Another thread runs at the decision without the event.
        let prefix = [
            call(2, Sysno::futex, Prehook),
            call(3, Sysno::nanosleep, Prehook),
            call(1, Sysno::clone, Prehook),
        ];
        let creator = [
            call(1, Sysno::clone, Posthook),
            call(1, Sysno::futex, Prehook),
        ];
        let starter = [branch(5), call(5, Sysno::nanosleep, Prehook)];
        let deciding = [call(3, Sysno::nanosleep, Posthook), branch(3)];
        let without: Vec<SchedEvent> = [&prefix[..], &creator, &starter, &deciding].concat();
        let plan = stack2_plan(tid(3), prefix.len(), &without, None);
        let Stack2Plan::Instead {
            at,
            partner: Some(partner),
        } = plan
        else {
            panic!("{plan:?}");
        };
        assert_eq!((at, partner.thread), (prefix.len() + 3, tid(5)));
        // Without a creator or a new thread there, the decision itself.
        let resumes = [
            call(2, Sysno::futex, Posthook),
            call(2, Sysno::read, Prehook),
        ];
        let without: Vec<SchedEvent> = [&prefix[..], &resumes, &deciding].concat();
        assert_eq!(
            stack2_plan(tid(3), prefix.len(), &without, None),
            Stack2Plan::Instead {
                at: prefix.len(),
                partner: None
            }
        );
        // The deciding thread runs there either way; thread 19's turn after
        // it runs longer with the event.
        let shared = [
            call(3, Sysno::nanosleep, Posthook),
            call(3, Sysno::futex, Prehook),
            call(21, Sysno::futex, Posthook),
            call(21, Sysno::futex, Prehook),
        ];
        let turn = |reads: usize| {
            let mut turn = vec![call(19, Sysno::futex, Posthook)];
            turn.extend(std::iter::repeat_n(
                call(19, Sysno::clock_gettime, Prehook),
                reads,
            ));
            turn.push(call(19, Sysno::futex, Prehook));
            turn
        };
        let with: Vec<SchedEvent> = [&prefix[..], &shared, &turn(4)].concat();
        let without: Vec<SchedEvent> = [&prefix[..], &shared, &turn(1)].concat();
        let plan = stack2_plan(tid(3), prefix.len(), &without, Some(&with));
        let Stack2Plan::Changed(changed) = plan else {
            panic!("{plan:?}");
        };
        assert_eq!(
            (changed.thread, changed.event),
            (tid(19), prefix.len() + shared.len() + 2)
        );
        // Continuations that do not differ: the thread after its slice.
        assert_eq!(
            stack2_plan(tid(3), prefix.len(), &without, Some(&without)),
            Stack2Plan::NextSlice {
                index: prefix.len() + 2,
                thread: tid(21)
            }
        );
        assert_eq!(
            stack2_plan(tid(3), without.len(), &without, None),
            Stack2Plan::Nothing
        );
    }

    /// A bisection trial replays its schedule with the callback checkpoints,
    /// per-thread histories and epoch of the endpoint record it shares the
    /// longest prefix with (on a tie, one it replays whole, then the first),
    /// as far as that prefix reaches: an endpoint replayed whole keeps all of
    /// its checkpoints, and one that shares nothing is written as events
    /// alone. A schedule edited right after its first event keeps none of the
    /// target's checkpoints, though it takes the target's histories and
    /// epoch: the one at that event's progress ended its slice, which decides
    /// the edited event, so the scheduler decides it, as in a prefix trial
    /// (`PreemptionRecord::schedule_prefix`).
    #[test]
    fn a_bisection_trial_keeps_the_checkpoints_of_the_part_it_shares_with_an_endpoint() {
        let parent = tempfile::tempdir().unwrap();
        let tmp_dir = format!("--tmp-dir={}", parent.path().display());
        let mut options =
            AnalyzeOpts::try_parse_from(["analyze", tmp_dir.as_str(), "--", "/bin/true"]).unwrap();
        let _workspace = options.phase0_initialize(Retention::Remove).unwrap();
        let branches = |tid: u64, count: u32| {
            serde_json::json!({
                "dettid": tid, "op": "Branch", "count": count,
                "start_rip": null, "end_rip": null, "end_time": null
            })
        };
        let checkpoint = |row: usize, progress: u64, time: u64| {
            serde_json::json!({
                "history_index": row,
                "origin": {
                    "callback": "PmuTimer", "site": "Prehook", "progress": progress,
                    "last_op": "Branch", "time": time, "rcbs": progress
                }
            })
        };
        let target: PreemptionRecord = serde_json::from_value(serde_json::json!({
            "per_thread": {"3": {
                "final_prio": 1000,
                "prio_changes": [[100, 1000], [200, 1000]],
                "preemption_rcbs": [10, 15]
            }},
            "global": [branches(3, 10), branches(3, 5)],
            "epoch": "2026-01-01T00:00:00Z",
            "callback_checkpoints": {"3": [checkpoint(0, 10, 100), checkpoint(1, 15, 200)]}
        }))
        .unwrap();
        target.validate().unwrap();
        let events = |list: Vec<serde_json::Value>| -> Vec<SchedEvent> {
            serde_json::from_value(serde_json::Value::Array(list)).unwrap()
        };
        // The baseline has the same events and no checkpoints: on the tie the
        // target, listed first, is the source.
        let baseline = PreemptionRecord::from_sched_events(target.schedevents().clone());
        let path = parent.path().join("trial.preempts");
        // A second endpoint whose schedule only starts with the target's
        // first event, and keeps no checkpoints.
        let short = PreemptionRecord::from_sched_events(events(vec![branches(3, 10)]));
        // (sources, schedule, checkpoints kept, whether the target's histories
        // and epoch come with them)
        for (sources, schedule, kept, from_target) in [
            (
                [&target, &baseline],
                events(vec![branches(3, 10), branches(3, 5)]),
                2,
                true,
            ),
            (
                [&target, &baseline],
                events(vec![branches(3, 10), branches(5, 5), branches(3, 5)]),
                0,
                true,
            ),
            (
                [&target, &baseline],
                events(vec![branches(5, 5), branches(3, 10)]),
                0,
                false,
            ),
            // The longer shared prefix wins, whichever source is listed first.
            (
                [&short, &target],
                events(vec![branches(3, 10), branches(3, 5)]),
                2,
                true,
            ),
            // A source that ends where the schedule goes on keeps its last
            // slice end: no event of its own follows it.
            (
                [&target, &short],
                events(vec![branches(3, 10), branches(3, 5), branches(5, 1)]),
                2,
                true,
            ),
            // On a tie, the source replayed whole wins.
            ([&target, &short], events(vec![branches(3, 10)]), 0, false),
        ] {
            options
                .write_trial_schedule_from(schedule.clone(), &sources, &path)
                .unwrap();
            let written = PreemptionReader::new(&path).load_all();
            written.validate().unwrap();
            assert_eq!(written.schedevents(), &schedule);
            let points = serde_json::to_value(&written).unwrap()["callback_checkpoints"]["3"]
                .as_array()
                .map_or(0, |points| points.len());
            assert_eq!(points, kept, "{schedule:?}");
            // Every trial schedule states the trials' epoch (#4853).
            assert!(written.epoch().is_some(), "{schedule:?}");
            assert_eq!(
                serde_json::to_value(&written).unwrap()["per_thread"]
                    .as_object()
                    .map_or(0, |rows| rows.len()),
                usize::from(from_target),
                "{schedule:?}"
            );
        }
    }

    /// A workspace kept for the level `--guest-log` gave names the option, and
    /// HERMIT_LOG too when the level came from that variable.
    #[test]
    fn a_workspace_kept_for_the_guest_log_level_names_its_source() {
        let mut options =
            AnalyzeOpts::try_parse_from(["analyze", "-g", "debug", "--", "/bin/true"]).unwrap();
        assert_eq!(
            options.workspace_retention(),
            Retention::Keep {
                because: Some("--guest-log")
            }
        );
        options.guest_log_from_env = true;
        assert_eq!(
            options.workspace_retention(),
            Retention::Keep {
                because: Some("--guest-log (HERMIT_LOG)")
            }
        );
    }

    /// `--tmp-dir` names the directory the workspace is created in, and is
    /// created if it is missing. The workspace goes when analyze is done
    /// with it, unless `--keep-tmp`, `--verbose`, or `--trial-log` above warn
    /// keeps it (not `--selfcheck`, though it writes run logs there too);
    /// the `--tmp-dir` stays.
    #[test]
    fn the_workspace_is_created_in_the_tmp_dir() {
        for (option, kept) in [
            (None, None),
            (Some("--keep-tmp"), Some("--keep-tmp")),
            (Some("--verbose"), Some("--verbose")),
            (Some("--selfcheck"), None),
            (Some("--trial-log=debug"), Some("--trial-log")),
            (Some("--trial-log=warn"), None),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let requested = parent.path().join("not-yet-created");
            let tmp_dir = format!("--tmp-dir={}", requested.display());
            let mut argv = vec!["analyze", tmp_dir.as_str(), "--", "/bin/true"];
            argv.splice(1..1, option);
            let mut options = AnalyzeOpts::try_parse_from(argv).unwrap();
            let retention = options.workspace_retention();
            assert_eq!(
                retention,
                match kept {
                    Some(because) => Retention::Keep {
                        because: Some(because),
                    },
                    None => Retention::Remove,
                },
                "{option:?}"
            );
            let guard = options.phase0_initialize(retention).unwrap();
            let workspace = options.get_tmp().unwrap().to_path_buf();
            assert_eq!(
                workspace.parent(),
                Some(std::fs::canonicalize(&requested).unwrap().as_path())
            );
            assert!(workspace.is_dir(), "{}", workspace.display());
            drop(guard);
            assert_eq!(
                workspace.exists(),
                kept.is_some(),
                "{option:?}: {}",
                workspace.display()
            );
            assert!(requested.is_dir(), "{}", requested.display());
        }

        // Through a symlink, the workspace is named by its canonical path.
        let parent = tempfile::tempdir().unwrap();
        let real = parent.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = parent.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let tmp_dir = format!("--tmp-dir={}", link.display());
        let mut options =
            AnalyzeOpts::try_parse_from(["analyze", tmp_dir.as_str(), "--", "/bin/true"]).unwrap();
        let _guard = options.phase0_initialize(Retention::Remove).unwrap();
        let workspace = options.get_tmp().unwrap().to_path_buf();
        assert_eq!(
            workspace.parent(),
            Some(std::fs::canonicalize(&real).unwrap().as_path()),
            "{}",
            workspace.display()
        );
    }

    /// The prefix search finds the event at which the outcome flips, wherever
    /// it lies, in about log2(len) trials once its endpoints differ.
    #[test]
    fn the_prefix_search_finds_the_deciding_event() {
        for (len, decision) in [
            (1, 0),
            (2, 1),
            (37_710, 0),
            (37_710, 33_225),
            (37_710, 37_709),
        ] {
            let mut trials = 0;
            let found = search_prefix_boundary(len, TrialEnd::Missed, |prefix, purpose| {
                assert_eq!(purpose, TrialPurpose::Search);
                trials += 1;
                Ok(Some(if prefix > decision {
                    TrialEnd::Met
                } else {
                    TrialEnd::Missed
                }))
            })
            .unwrap();
            assert_eq!(
                found,
                Boundary {
                    passing: decision,
                    passing_end: TrialEnd::Missed
                },
                "len {len}"
            );
            assert!(
                trials <= (len as f64).log2().ceil() as usize,
                "{trials} trials"
            );
        }
    }

    /// The shape of the case that showed it (37,407 events, decided between
    /// #28,055 and #30,393): every prefix past `decision` meets the target,
    /// but under the usual bound only those past `quick` finish; the trials
    /// of the prefixes in between, whose continuations run longer, are
    /// stopped, and so are all those on the baseline side. A trial stopped by
    /// a bound does not decide the boundary: confirmed with a longer bound it
    /// meets the target, and the search goes on below it, under the longer
    /// bound. Counting stopped trials as outcomes ends next to `quick`
    /// instead, on a run that never finished. Returns the boundary and the
    /// number of confirmations.
    fn search_with_slow_continuations(
        len: usize,
        decision: usize,
        quick: usize,
        confirm: bool,
    ) -> (Boundary, usize) {
        let (mut longer, mut confirmations) = (false, 0);
        let found =
            search_prefix_boundary(len, TrialEnd::Unfinished(Stop::Bound), |prefix, purpose| {
                if purpose == TrialPurpose::Confirm {
                    if !confirm || longer {
                        return Ok(None);
                    }
                    confirmations += 1;
                    longer = true;
                }
                let end = if prefix > decision && (prefix > quick || longer) {
                    TrialEnd::Met
                } else {
                    TrialEnd::Unfinished(Stop::Bound)
                };
                if purpose == TrialPurpose::Confirm && end != TrialEnd::Met {
                    longer = false;
                }
                Ok(Some(end))
            })
            .unwrap();
        (found, confirmations)
    }

    /// When even the confirmation leaves the boundary's trial unfinished, the
    /// report calls it a hang, a third outcome rather than a run that misses,
    /// says that the boundary rests on a wall-clock bound, and names the
    /// longest shorter prefix the search replayed that finished, or that none
    /// did. Before, the progress line and the header called such a trial the
    /// baseline condition.
    #[test]
    fn a_boundary_trial_still_stopped_is_reported_as_a_hang() {
        let note = unfinished_boundary_warning(
            35_631,
            TrialEnd::Unfinished(Stop::Bound),
            Some(60),
            Some(240),
            Some((9_000, TrialEnd::Missed)),
            "raise --trial-timeout",
        );
        for expected in [
            "replaying the first 35631 events and then scheduling without chaos did not finish \
             within 60 s, nor within 240 s when it ran again to confirm it",
            "A hang is a third outcome, not a run that misses the target",
            "this boundary rests on a wall-clock bound, not on an outcome",
            "(raise --trial-timeout)",
            "the prefix of 9000 events, which missed the target.",
        ] {
            assert!(note.contains(expected), "no {expected:?} in {note}");
        }
        let unconfirmed = unfinished_boundary_warning(
            1,
            TrialEnd::Unfinished(Stop::Bound),
            Some(120),
            None,
            None,
            "raise the run arguments' --timeout",
        );
        for expected in [
            "did not finish within 120 s, and no longer bound could be given to confirm it",
            "(raise the run arguments' --timeout)",
            "No shorter prefix the search replayed finished.",
        ] {
            assert!(
                unconfirmed.contains(expected),
                "no {expected:?} in {unconfirmed}"
            );
        }
    }

    /// A trial the virtual-time bound stopped is a hang the search does not
    /// confirm with a longer bound, since every run of it at that bound
    /// stops at the same scheduler turn. On the boundary's baseline side it
    /// is the boundary, unconfirmed, the empty prefix's included. Below a
    /// refuted wall-clock confirmation it still bounds the search from below,
    /// as a trial that missed does. A confirmation it stopped keeps the
    /// raised wall-clock bound, which the stack-trace runs of that prefix
    /// need to reach the same stop. The final recheck runs it once more and
    /// warns when that run ends otherwise.
    #[test]
    fn a_trial_the_virtual_bound_stopped_is_not_confirmed() {
        let hang = TrialEnd::Unfinished(Stop::VirtualBound(60_000_000_000));
        let found = search_prefix_boundary(100, TrialEnd::Missed, |prefix, purpose| {
            assert_eq!(purpose, TrialPurpose::Search, "prefix {prefix}");
            Ok(Some(if prefix > 40 {
                TrialEnd::Met
            } else if prefix == 40 {
                hang
            } else {
                TrialEnd::Missed
            }))
        })
        .unwrap();
        assert_eq!(
            found,
            Boundary {
                passing: 40,
                passing_end: hang
            }
        );
        let found = search_prefix_boundary(10, hang, |prefix, purpose| {
            assert_eq!(purpose, TrialPurpose::Search, "prefix {prefix}");
            Ok(Some(TrialEnd::Met))
        })
        .unwrap();
        assert_eq!(
            found,
            Boundary {
                passing: 0,
                passing_end: hang
            }
        );

        // Prefixes past 600 meet the target, but under the usual wall-clock
        // bound only those past 900 finish; the prefix of 500 hangs.
        let (mut longer, mut log) = (false, Vec::new());
        let found = search_prefix_boundary(1000, TrialEnd::Missed, |prefix, purpose| {
            log.push((prefix, purpose));
            longer |= purpose == TrialPurpose::Confirm;
            Ok(Some(if prefix > 600 && (prefix > 900 || longer) {
                TrialEnd::Met
            } else if prefix == 500 {
                hang
            } else if prefix > 600 {
                TrialEnd::Unfinished(Stop::Bound)
            } else {
                TrialEnd::Missed
            }))
        })
        .unwrap();
        assert_eq!(
            found,
            Boundary {
                passing: 600,
                passing_end: TrialEnd::Missed
            }
        );
        let confirmed = log
            .iter()
            .position(|&entry| entry == (900, TrialPurpose::Confirm))
            .unwrap();
        assert_eq!(log[confirmed + 1], (700, TrialPurpose::Search), "{log:?}");
        assert_eq!(
            log.iter()
                .filter(|(_, purpose)| *purpose == TrialPurpose::Confirm)
                .count(),
            1,
            "{log:?}"
        );

        assert_eq!(factor_after_confirmation(4, true, hang), 4);

        // The final recheck runs such a trial again, and warns when that run
        // does not stop at the same bound, as when the target's outcome
        // changes; a trial the wall-clock bound stops again is close to it.
        let bound = TrialEnd::Unfinished(Stop::Bound);
        let refusal = TrialEnd::Unfinished(Stop::Refusal);
        assert_eq!(recheck(hang, hang), Recheck::Repeated);
        for again in [TrialEnd::Missed, TrialEnd::Met, refusal] {
            assert_eq!(recheck(hang, again), Recheck::Other, "{again:?}");
        }
        assert_eq!(recheck(TrialEnd::Missed, hang), Recheck::Other);
        assert_eq!(recheck(hang, bound), Recheck::CloseToTheBound);
        assert_eq!(recheck(TrialEnd::Missed, refusal), Recheck::Repeated);
        assert_eq!(recheck(TrialEnd::Met, TrialEnd::Missed), Recheck::Other);
    }

    /// When the boundary's baseline side stopped at the virtual-time bound, the
    /// note calls it a hang, says the boundary rests on that bound, which is
    /// the same on every host, and that the trial was not confirmed with a
    /// longer bound because a rerun at the same bound stops at the same
    /// scheduler turn; it never mentions a wall-clock bound or a confirmation
    /// that was not run. When it was a confirmation of a trial the wall-clock
    /// bound stopped that the virtual bound stopped, the note says both. The
    /// advice names the flag that raises the bound that stopped it.
    #[test]
    fn a_virtual_bound_boundary_is_reported_as_a_hang_without_a_longer_bound() {
        let hang = TrialEnd::Unfinished(Stop::VirtualBound(60_000_000_000));
        assert_eq!(
            describe_trial_end(hang, Some(240)),
            "did not finish within 60000000000 ns of virtual time"
        );
        let note = unfinished_boundary_warning(
            812,
            hang,
            Some(240),
            None,
            Some((700, TrialEnd::Missed)),
            "raise --trial-virtual-timeout",
        );
        for expected in [
            "replaying the first 812 events and then scheduling without chaos did not finish \
             within 60000000000 ns of virtual time: the guest hangs",
            "A hang is a third outcome, not a run that misses the target",
            "this boundary rests on a virtual-time bound, not on an outcome. That bound is the \
             same on every host, and a rerun at the same bound stops at the same scheduler turn, \
             so the trial was not confirmed with a longer bound.",
            "(raise --trial-virtual-timeout)",
            "the prefix of 700 events, which missed the target.",
        ] {
            assert!(note.contains(expected), "no {expected:?} in {note}");
        }
        assert!(
            !note.contains("wall-clock") && !note.contains("no longer bound"),
            "{note}"
        );
        let confirmed = unfinished_boundary_warning(
            812,
            hang,
            Some(240),
            Some(960),
            None,
            "raise --trial-virtual-timeout",
        );
        for expected in [
            "did not finish within 240 s, nor within 60000000000 ns of virtual time when it ran \
             again with a bound of 960 s to confirm it",
            "this boundary rests on a virtual-time bound, not on an outcome",
        ] {
            assert!(
                confirmed.contains(expected),
                "no {expected:?} in {confirmed}"
            );
        }
        assert!(!confirmed.contains("was not confirmed"), "{confirmed}");

        let own = "raise the run arguments' --virtual-timeout";
        let trial = "raise --trial-virtual-timeout";
        let floor = Some(60_000_000_000);
        assert_eq!(virtual_bound_remedy(Some(5_000_000), floor, 5_000_000), own);
        assert_eq!(
            virtual_bound_remedy(Some(5_000_000), floor, 60_000_000_000),
            trial
        );
        assert_eq!(virtual_bound_remedy(None, floor, 60_000_000_000), trial);
        assert_eq!(
            virtual_bound_remedy(floor, floor, 60_000_000_000),
            "raise both the run arguments' --virtual-timeout and --trial-virtual-timeout"
        );
    }

    /// The longest shorter prefix the hang note names finished: a stopped or
    /// a refused trial does not count, nor a prefix at or past the boundary,
    /// nor another continuation's trial, and a prefix's last trial (a
    /// confirmation, say) is the one that counts.
    #[test]
    fn the_longest_finished_prefix_below_the_boundary_is_named() {
        let ns = NonZeroU64::new(100_000);
        let other = NonZeroU64::new(200_000_000);
        let bound = TrialEnd::Unfinished(Stop::Bound);
        let refusal = TrialEnd::Unfinished(Stop::Refusal);
        let ends = BTreeMap::from([
            ((0, ns), (TrialEnd::Missed, Some(60))),
            ((10, ns), (TrialEnd::Missed, Some(240))),
            ((20, ns), (refusal, Some(60))),
            ((25, other), (TrialEnd::Missed, Some(60))),
            ((30, ns), (bound, Some(60))),
            ((40, ns), (bound, Some(240))),
            ((41, ns), (TrialEnd::Met, Some(60))),
        ]);
        assert_eq!(
            longest_finished_below(&ends, ns, 40),
            Some((10, TrialEnd::Missed))
        );
        assert_eq!(
            longest_finished_below(&ends, ns, 10),
            Some((0, TrialEnd::Missed))
        );
        assert_eq!(longest_finished_below(&ends, ns, 0), None);
        assert_eq!(
            longest_finished_below(&ends, other, 40),
            Some((25, TrialEnd::Missed))
        );
    }

    /// The confirmation's bound and what it leaves behind: the first raises
    /// every later run's bound; once raised, a prefix whose trial ran under
    /// the shorter bound runs again under the longer one, and one that ran
    /// under the longer one cannot be confirmed; a confirmation stopped again
    /// returns to the usual bound, and one that finished keeps the longer
    /// one whatever its outcome (the earlier blocker was dropping it after a
    /// confirmation that finished and missed).
    #[test]
    fn a_confirmation_raises_the_bound_and_keeps_it_once_finished() {
        use ConfirmationBound::*;
        assert_eq!(
            confirmation_bound(Some(240), 1, Some(60), Some(60)),
            Raise(240)
        );
        assert_eq!(confirmation_bound(None, 4, Some(240), Some(60)), Rerun(240));
        assert_eq!(
            confirmation_bound(None, 4, Some(240), Some(240)),
            Unavailable
        );
        assert_eq!(confirmation_bound(None, 1, Some(60), Some(60)), Unavailable);
        assert_eq!(confirmation_bound(None, 4, None, Some(60)), Unavailable);

        let bound = TrialEnd::Unfinished(Stop::Bound);
        let refusal = TrialEnd::Unfinished(Stop::Refusal);
        assert_eq!(factor_after_confirmation(4, true, bound), 1);
        for end in [TrialEnd::Met, TrialEnd::Missed, refusal] {
            assert_eq!(factor_after_confirmation(4, true, end), 4, "{end:?}");
        }
        // A rerun under the raised bound leaves it raised either way.
        assert_eq!(factor_after_confirmation(4, false, bound), 4);

        // The advice names the flag whose bound stopped the trial.
        let own = "raise the run arguments' --timeout";
        let trial = "raise --trial-timeout";
        assert_eq!(bound_remedy(Some(120), false, Some(120)), own);
        assert_eq!(bound_remedy(Some(120), false, Some(240)), own);
        assert_eq!(bound_remedy(Some(120), true, None), own);
        assert_eq!(bound_remedy(Some(600), false, Some(240)), trial);
        assert_eq!(bound_remedy(None, false, Some(60)), trial);
    }

    #[test]
    fn a_trial_a_bound_stopped_does_not_decide_the_boundary() {
        let unfinished = |passing| Boundary {
            passing,
            passing_end: TrialEnd::Unfinished(Stop::Bound),
        };
        assert_eq!(
            search_with_slow_continuations(37_407, 30_000, 32_117, false),
            (unfinished(32_117), 0),
            "without confirmation"
        );
        assert_eq!(
            search_with_slow_continuations(37_407, 30_000, 32_117, true),
            (unfinished(30_000), 1),
        );
        // When the search already ends at the decision, the one confirmation
        // finds nothing longer to change it.
        assert_eq!(
            search_with_slow_continuations(37_407, 30_000, 30_000, true),
            (unfinished(30_000), 1),
        );
    }

    /// A confirmation that finishes and misses the target, or that is still
    /// stopped, leaves the boundary where the search put it, and says how
    /// that trial ended; a prefix the search saw finish is not confirmed.
    #[test]
    fn a_confirmed_trial_keeps_the_boundary() {
        for (confirmed, passing_end) in [
            (Some(TrialEnd::Missed), TrialEnd::Missed),
            (
                Some(TrialEnd::Unfinished(Stop::Bound)),
                TrialEnd::Unfinished(Stop::Bound),
            ),
            (None, TrialEnd::Unfinished(Stop::Bound)),
        ] {
            let mut confirmations = Vec::new();
            let found = search_prefix_boundary(100, TrialEnd::Missed, |prefix, purpose| {
                Ok(match purpose {
                    TrialPurpose::Confirm => {
                        confirmations.push(prefix);
                        confirmed
                    }
                    TrialPurpose::Search if prefix > 40 => Some(TrialEnd::Met),
                    TrialPurpose::Search if prefix == 40 => Some(TrialEnd::Unfinished(Stop::Bound)),
                    TrialPurpose::Search => Some(TrialEnd::Missed),
                })
            })
            .unwrap();
            assert_eq!(
                found,
                Boundary {
                    passing: 40,
                    passing_end
                }
            );
            assert_eq!(confirmations, [40]);
        }
        let found = search_prefix_boundary(100, TrialEnd::Missed, |prefix, purpose| {
            assert_eq!(purpose, TrialPurpose::Search, "prefix {prefix}");
            Ok(Some(if prefix > 40 {
                TrialEnd::Met
            } else if prefix == 40 {
                TrialEnd::Unfinished(Stop::Refusal)
            } else {
                TrialEnd::Missed
            }))
        })
        .unwrap();
        assert_eq!(found.passing_end, TrialEnd::Unfinished(Stop::Refusal));
    }

    /// After a confirmation meets the target, the search goes on above the
    /// longest prefix that missed it and was not stopped (500 here), not
    /// above a stopped one, and a prefix whose trial already ran under the
    /// longer bound is not run again.
    #[test]
    fn a_refuted_boundary_resumes_above_the_last_finished_miss() {
        let (mut longer, mut log) = (false, Vec::new());
        let found = search_prefix_boundary(1000, TrialEnd::Missed, |prefix, purpose| {
            log.push((prefix, purpose));
            if purpose == TrialPurpose::Confirm {
                if longer {
                    return Ok(None);
                }
                longer = true;
            }
            Ok(Some(if prefix > 600 && (prefix > 900 || longer) {
                TrialEnd::Met
            } else if prefix == 500 {
                TrialEnd::Missed
            } else {
                TrialEnd::Unfinished(Stop::Bound)
            }))
        })
        .unwrap();
        assert_eq!(
            found,
            Boundary {
                passing: 600,
                passing_end: TrialEnd::Unfinished(Stop::Bound)
            }
        );
        let confirmations: Vec<usize> = log
            .iter()
            .filter(|(_, purpose)| *purpose == TrialPurpose::Confirm)
            .map(|(prefix, _)| *prefix)
            .collect();
        assert_eq!(confirmations, [900, 600]);
        let first = log
            .iter()
            .position(|&entry| entry == (900, TrialPurpose::Confirm))
            .unwrap();
        assert_eq!(log[first + 1], (700, TrialPurpose::Search), "{log:?}");
    }

    /// The empty prefix's trial is confirmed like any other; if it meets the
    /// target given longer, the scheduler alone does, and the search ends
    /// with an error instead of naming event #0.
    #[test]
    fn an_empty_prefix_that_meets_the_target_given_longer_ends_the_search() {
        let error =
            search_prefix_boundary(10, TrialEnd::Unfinished(Stop::Bound), |prefix, purpose| {
                Ok(Some(match purpose {
                    TrialPurpose::Confirm => TrialEnd::Met,
                    TrialPurpose::Search if prefix > 0 => TrialEnd::Met,
                    TrialPurpose::Search => TrialEnd::Missed,
                }))
            })
            .unwrap_err();
        assert!(
            error.downcast_ref::<EmptyPrefixMeetsTarget>().is_some(),
            "{error}"
        );
    }

    /// `auto` continues at the run's own timeslice, then at hermit's default
    /// 200 ms when that is coarser, never at a shorter one; a run without PMU
    /// timeslices continues as it is.
    #[test]
    fn auto_continuations_only_get_coarser() {
        let ns = |nanos: u64| NonZeroU64::new(nanos);
        assert_eq!(continuation_candidates(ns(200_000_000)), [ns(200_000_000)]);
        assert_eq!(
            continuation_candidates(ns(1_000)),
            [ns(1_000), ns(200_000_000)]
        );
        assert_eq!(continuation_candidates(ns(500_000_000)), [ns(500_000_000)]);
        assert_eq!(continuation_candidates(None), [None]);
    }

    /// The search continues at the first timeslice whose endpoint trials
    /// differ: one at which the scheduler alone meets the target, or the
    /// whole schedule's replay misses it or does not finish, is skipped. When
    /// every timeslice fails, the error names each, says what it showed, and
    /// what to do.
    #[test]
    fn the_prefix_search_continues_at_the_first_usable_timeslice() {
        let ns = |nanos: u64| NonZeroU64::new(nanos);
        let candidates = [ns(1_000), ns(200_000_000)];
        let end = |met: bool| if met { TrialEnd::Met } else { TrialEnd::Missed };
        // At 1000 ns the scheduler alone already meets the target (a race
        // found only at a short timeslice); at 200 ms it does not.
        let mut trials = Vec::new();
        let chosen = choose_continuation(&candidates, 50, |prefix, timeslice| {
            trials.push((prefix, timeslice));
            Ok(end(prefix > 0 || timeslice == ns(1_000)))
        })
        .unwrap();
        assert_eq!(chosen, ns(200_000_000));
        assert_eq!(
            trials,
            [(0, ns(1_000)), (0, ns(200_000_000)), (50, ns(200_000_000))]
        );
        assert_eq!(
            choose_continuation(&candidates, 50, |prefix, _| Ok(end(prefix > 0))).unwrap(),
            ns(1_000),
            "the first usable one wins"
        );

        let alone = choose_continuation(&candidates, 50, |_, _| Ok(TrialEnd::Met)).unwrap_err();
        // A completed analysis that names no event, not a failure.
        assert!(
            matches!(
                alone.downcast_ref::<AnalyzeVerdict>(),
                Some(AnalyzeVerdict::NoDecidingEvent { .. })
            ),
            "{alone:#}"
        );
        let message = alone.to_string();
        assert!(
            message.contains("the scheduler alone already meets the target criteria at a 1000 ns timeslice and at a 200000000 ns timeslice"),
            "{message}"
        );
        assert!(
            message.contains("prefix_round_001.repro") && message.contains("--run2-seed"),
            "{message}"
        );
        let replay = choose_continuation(&candidates, 50, |_, _| Ok(TrialEnd::Missed)).unwrap_err();
        assert!(
            replay.to_string().contains(
                "at a 1000 ns timeslice replaying the whole target schedule misses the target"
            ),
            "{replay}"
        );
        assert!(replay.to_string().contains("--selfcheck"), "{replay}");
        assert_eq!(
            replay
                .downcast_ref::<AnalyzePrecondition>()
                .map(|precondition| precondition.class.name()),
            Some("no-prefix-continuation"),
            "{replay:#}"
        );
        assert_eq!(crate::failure_exit_code(&replay), 2);
        assert_eq!(
            crate::classify_failure(&replay),
            "HERMIT_ANALYZE_PRECONDITION class=no-prefix-continuation"
        );
        let unfinished = choose_continuation(&candidates, 50, |prefix, _| {
            Ok(if prefix == 0 {
                TrialEnd::Missed
            } else {
                TrialEnd::Unfinished(Stop::Bound)
            })
        })
        .unwrap_err();
        assert!(
            unfinished
                .to_string()
                .contains("did not finish (a bound or a refusal stopped it)")
                && unfinished.to_string().contains("raise --trial-timeout"),
            "{unfinished}"
        );
    }

    /// A prefix search whose empty prefix already meets the target concludes
    /// that no event decides the outcome, naming a coarser continuation it did
    /// not try.
    #[test]
    fn an_empty_prefix_that_meets_the_target_is_a_verdict() {
        let ns = |nanos: u64| NonZeroU64::new(nanos);
        let candidates = [ns(1_000), ns(200_000_000)];
        let error = Error::new(EmptyPrefixMeetsTarget);
        let AnalyzeVerdict::NoDecidingEvent { explanation, .. } =
            empty_prefix_verdict(&error, &candidates, ns(1_000));
        assert!(
            explanation.starts_with("no event of the target schedule decides the outcome: ")
                && explanation
                    .contains("The search did not try continuing at a 200000000 ns timeslice"),
            "{explanation}"
        );
        let AnalyzeVerdict::NoDecidingEvent { explanation, .. } =
            empty_prefix_verdict(&error, &candidates, ns(200_000_000));
        assert!(!explanation.contains("did not try"), "{explanation}");
    }

    /// A verdict that names no event is reported as a completed analysis:
    /// its report carries `"verdict": "no_deciding_event"`, its reason and the
    /// explanation, and analyze exits as it does after naming an event (0, or
    /// `--success-exit-code`). `main.rs` never sees it as an error. Without
    /// timing settings in force no other trial runs. With them, a recording
    /// given with `--run1-preemptions` leaves them untried; otherwise the
    /// trial under their alternatives decides the cause, shown here with
    /// stand-ins for that trial.
    /// A trial under another timing setting drops the option, as
    /// `name=VALUE` or as `name VALUE`, from analyze's arguments and the run
    /// arguments before the guest command, and keeps the guest's own.
    #[test]
    fn a_trial_under_another_setting_drops_the_option() {
        let args = |list: &[&str]| -> Vec<String> { list.iter().map(|a| a.to_string()).collect() };
        assert_eq!(
            without_option(
                &args(&[
                    "--pipe-wake-latency=50000",
                    "--strict",
                    "--pipe-wake-latency",
                    "7",
                    "--pipe-wake-latency-extra=1",
                    "--",
                    "/bin/guest",
                    "--pipe-wake-latency=3",
                ]),
                "--pipe-wake-latency"
            ),
            args(&[
                "--strict",
                "--pipe-wake-latency-extra=1",
                "--",
                "/bin/guest",
                "--pipe-wake-latency=3",
            ])
        );
    }

    #[test]
    fn a_verdict_is_reported_and_ends_analyze_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report.json");
        let verdict = AnalyzeVerdict::no_deciding_event("no event decides the outcome.", None);
        let written = |status: anyhow::Result<ExitStatus>, expected: ExitStatus| {
            assert_eq!(status.unwrap(), expected);
            let text = std::fs::read_to_string(&report).unwrap();
            std::fs::remove_file(&report).unwrap();
            // One schema reads both kinds of report.
            let parsed: Report = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed.verdict, Verdict::NoDecidingEvent);
            assert_eq!(parsed.critical_event1, None);
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        };
        let parse = |extra: &[&str], run_args: &[&str]| {
            let mut argv = vec![
                "analyze".to_string(),
                format!("--report-file={}", report.display()),
            ];
            argv.extend(extra.iter().map(|flag| flag.to_string()));
            argv.push("--".to_string());
            argv.extend(run_args.iter().map(|flag| flag.to_string()));
            argv.push("/bin/true".to_string());
            AnalyzeOpts::try_parse_from(argv).unwrap()
        };
        for (extra, status) in [
            (&[][..], ExitStatus::SUCCESS),
            (&["--success-exit-code=3"][..], ExitStatus::Exited(3)),
        ] {
            // Through the prefix search's end, as analyze reaches it.
            let options = parse(extra, &[]);
            let searched = Err(Error::new(verdict.clone()));
            assert_eq!(
                written(options.finish_prefix_search(searched), status),
                serde_json::json!({
                    "verdict": "no_deciding_event",
                    "verdict_reason": {"cause": "scheduler_alone"},
                    "header": "no event decides the outcome.",
                    "additional_context": "",
                    "baseline_run": false,
                })
            );
        }

        // A recording fixes the settings, so no trial tries others.
        let recorded = parse(
            &["--run1-preemptions=/nonexistent.preempts"],
            &["--pipe-wake-latency=50000"],
        );
        let searched = Err(Error::new(verdict.clone()));
        let json = written(recorded.finish_prefix_search(searched), ExitStatus::SUCCESS);
        assert_eq!(
            json["verdict_reason"],
            serde_json::json!({
                "cause": "scheduler_alone",
                "timing_in_force": ["--pipe-wake-latency=50000"],
            })
        );
        let header = json["header"].as_str().unwrap();
        assert!(
            header.contains("was not tried: the failing run is a recording (--run1-preemptions)")
                && header.contains("A new failing run with no --pipe-wake-latency"),
            "{header}"
        );

        // Otherwise the trial without the setting decides the cause.
        let options = parse(&[], &["--pipe-wake-latency=50000"]);
        let trial = || "prefix_alternative_timing.repro".to_owned();
        let shown = options.with_timing_tried(verdict.clone(), |timing, continuation| {
            assert_eq!(timing.len(), 1);
            assert_eq!(timing[0].drops, "--pipe-wake-latency");
            assert_eq!(continuation, None);
            AlternativeTiming::Missed { trial: trial() }
        });
        let json = written(options.write_verdict_and_exit(&shown), ExitStatus::SUCCESS);
        assert_eq!(
            json["verdict_reason"],
            serde_json::json!({
                "cause": "timing_semantics",
                "options": ["--pipe-wake-latency=50000"],
                "alternatives": ["no --pipe-wake-latency"],
                "trial": "prefix_alternative_timing.repro",
            })
        );
        assert!(
            json["header"]
                .as_str()
                .unwrap()
                .contains("meets the target because of --pipe-wake-latency=50000"),
            "{json}"
        );
        let met = options.with_timing_tried(verdict.clone(), |_, _| AlternativeTiming::Met {
            trial: trial(),
        });
        assert_eq!(
            serde_json::to_value(met.reason()).unwrap(),
            serde_json::json!({
                "cause": "scheduler_alone",
                "timing_in_force": ["--pipe-wake-latency=50000"],
            })
        );

        // Any other end of the search ends the analysis, writing no report.
        let options = AnalyzeOpts::try_parse_from([
            "analyze".to_string(),
            format!("--report-file={}", report.display()),
            "--".to_string(),
            "/bin/true".to_string(),
        ])
        .unwrap();
        let other = options
            .finish_prefix_search(Err(
                AnalyzePrecondition::no_prefix_continuation("none").into()
            ))
            .unwrap_err();
        assert!(
            other.downcast_ref::<AnalyzePrecondition>().is_some(),
            "{other:#}"
        );
        assert!(!report.exists());
        assert_eq!(
            verdict.class_line(),
            "HERMIT_ANALYZE_VERDICT class=no-deciding-event"
        );
    }

    /// The trial under the alternative timing runs without the settings it
    /// drops, and its end decides the cause: missed shows the settings cause
    /// the outcome, met shows they do not, and an unfinished (bound or
    /// refused) or failed trial shows nothing.
    #[test]
    fn the_alternative_timing_trial_decides_the_cause_by_how_it_ends() {
        use crate::analyze::rundata::Stop;
        let options = AnalyzeOpts::try_parse_from([
            "analyze",
            "--run-arg=--scheduler-turn-cost=10000",
            "--",
            "--pipe-wake-latency=50000",
            "/bin/true",
        ])
        .unwrap();
        let timing = options.continuation_timing();
        assert_eq!(
            timing.iter().map(|t| t.option.as_str()).collect::<Vec<_>>(),
            ["--pipe-wake-latency=50000", "--scheduler-turn-cost=10000"]
        );
        // How the trial ends, and what the cause must then be.
        type Case = (anyhow::Result<TrialEnd>, fn(&AlternativeTiming) -> bool);
        let cases: [Case; 5] = [
            (
                Ok(TrialEnd::Missed),
                |t| matches!(t, AlternativeTiming::Missed { trial } if trial == "prefix_alternative_timing.repro"),
            ),
            (Ok(TrialEnd::Met), |t| {
                matches!(t, AlternativeTiming::Met { .. })
            }),
            (
                Ok(TrialEnd::Unfinished(Stop::Bound)),
                |t| matches!(t, AlternativeTiming::Untried { why } if why.contains("prefix_alternative_timing.repro")),
            ),
            (Ok(TrialEnd::Unfinished(Stop::Refusal)), |t| {
                matches!(t, AlternativeTiming::Untried { .. })
            }),
            (
                Err(anyhow::anyhow!("no such binary")),
                |t| matches!(t, AlternativeTiming::Untried { why } if why.contains("could not run (no such binary)")),
            ),
        ];
        // An explicit turn cost equal to the default charge is no setting.
        let default_cost = AnalyzeOpts::try_parse_from([
            "analyze",
            "--run-arg=--scheduler-turn-cost=500000",
            "--",
            "/bin/true",
        ])
        .unwrap();
        assert_eq!(default_cost.continuation_timing(), Vec::new());
        for (end, expected) in cases {
            let tried = options.try_alternative_timing_with(&timing, |alternative, runname| {
                assert_eq!(runname, "prefix_alternative_timing");
                let args: Vec<&String> = alternative
                    .run_arg
                    .iter()
                    .chain(&alternative.run_args)
                    .collect();
                assert!(
                    args.iter()
                        .all(|arg| !arg.starts_with("--pipe-wake-latency")
                            && !arg.starts_with("--scheduler-turn-cost")),
                    "{args:?}"
                );
                assert_eq!(alternative.continuation_timing(), Vec::new());
                end
            });
            assert!(expected(&tried), "{tried:?}");
        }
    }

    /// A first run that misses the target ends the analysis without --search,
    /// an input that gives it no target run (exit 2, `target-not-reproduced`),
    /// and searches with it.
    #[test]
    fn a_first_run_that_misses_ends_the_analysis_or_searches() {
        let options = AnalyzeOpts::try_parse_from(["analyze", "--", "/bin/true"]).unwrap();
        let mut searched = false;
        let error = options
            .after_a_first_run_that_missed(|| {
                searched = true;
                bail!("searched")
            })
            .err()
            .unwrap();
        assert!(!searched);
        assert_eq!(crate::failure_exit_code(&error), 2, "{error:#}");
        assert_eq!(
            crate::classify_failure(&error),
            "HERMIT_ANALYZE_PRECONDITION class=target-not-reproduced"
        );
        assert!(error.to_string().contains("Try --search"), "{error}");

        let options =
            AnalyzeOpts::try_parse_from(["analyze", "--search", "--", "/bin/true"]).unwrap();
        let error = options
            .after_a_first_run_that_missed(|| bail!("searched"))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "searched");
    }

    /// Both of the bisection's ends that no single reordering separates the
    /// endpoints send analyze to a prefix search; other ends do not. An
    /// endpoint of analyze's own that did not reproduce is pointed at replay.
    #[test]
    fn bisection_ends_are_answered_by_their_kind() {
        assert!(no_swap_separates(&Error::new(NoSingleSwap {
            unshared_events: 1,
            swaps_left: 1,
            trimmed_failing_passed: false,
        })));
        assert!(no_swap_separates(&Error::new(NoReorderableDistance {
            edit_distance: 2
        })));
        assert!(!no_swap_separates(&Error::new(
            AnalyzePrecondition::target_not_reproduced("no")
        )));

        for precondition in [
            AnalyzePrecondition::target_not_reproduced("the failing endpoint did not."),
            AnalyzePrecondition::baseline_not_reproduced("the passing endpoint did not."),
        ] {
            let class = precondition.class;
            let pointed = point_endpoint_misses_at_replay(precondition.into());
            let pointed_precondition = pointed.downcast_ref::<AnalyzePrecondition>().unwrap();
            assert_eq!(pointed_precondition.class, class);
            let message = pointed.to_string();
            assert!(
                message.contains("--selfcheck") && message.contains("hermit host-capabilities"),
                "{message}"
            );
        }
        let other = point_endpoint_misses_at_replay(anyhow::anyhow!("other"));
        assert_eq!(other.to_string(), "other");
    }

    /// Analyze's own bisection goes on to a prefix search when no swap
    /// separates its endpoints, and an endpoint that did not reproduce ends it
    /// pointed at replay: --selfcheck and `hermit host-capabilities`, with the
    /// class kept (exit 2). Other errors pass through unchanged.
    #[test]
    fn analyze_own_bisection_points_endpoint_misses_at_replay() {
        let separable =
            own_bisection_end(Err(Error::new(NoReorderableDistance { edit_distance: 1 })));
        assert!(matches!(separable, Ok(OwnBisectionEnd::SearchPrefixes(_))));
        for (precondition, class) in [
            (
                AnalyzePrecondition::target_not_reproduced(
                    "the failing schedule endpoint did not reproduce the target failure",
                ),
                "target-not-reproduced",
            ),
            (
                AnalyzePrecondition::baseline_not_reproduced(
                    "the passing schedule endpoint did not reproduce a passing outcome",
                ),
                "baseline-not-reproduced",
            ),
        ] {
            let Err(error) = own_bisection_end(Err(precondition.into())) else {
                panic!("an endpoint miss ended no analysis")
            };
            let message = error.to_string();
            assert!(
                message.contains("--selfcheck") && message.contains("`hermit host-capabilities`"),
                "{message}"
            );
            assert_eq!(crate::failure_exit_code(&error), 2);
            assert_eq!(
                crate::classify_failure(&error),
                format!("HERMIT_ANALYZE_PRECONDITION class={class}")
            );
        }
        let Err(other) = own_bisection_end(Err(anyhow::anyhow!("other"))) else {
            panic!("an error ended no analysis")
        };
        assert_eq!(other.to_string(), "other");
    }

    /// --selfcheck's differences are replay not reproducing, Hermit's or the
    /// host's: exit 125 with `class=replay-not-reproducible`, never an input
    /// analyze cannot use. The first difference found is reported.
    #[test]
    fn a_selfcheck_difference_is_replay_not_reproducing() {
        assert!(selfcheck_conclusion(true, true, || Ok(())).is_ok());
        for (matched, logs, fixed_point, expected) in [
            (false, true, true, "second run did not"),
            (true, false, true, "Log differences found"),
            (true, true, false, "no fixed point"),
        ] {
            let error = selfcheck_conclusion(matched, logs, || {
                if fixed_point {
                    Ok(())
                } else {
                    Err("no fixed point".to_string())
                }
            })
            .unwrap_err();
            assert!(
                error.to_string().contains(expected)
                    && error.to_string().contains("hermit host-capabilities"),
                "{error}"
            );
            assert_eq!(crate::failure_exit_code(&error), 125);
            assert_eq!(
                crate::classify_failure(&error),
                "HERMIT_INTERNAL_FAILURE class=replay-not-reproducible"
            );
        }
    }

    /// `--success-exit-code` refuses the statuses that already mean something
    /// for analyze, naming why.
    #[test]
    fn a_success_exit_code_that_means_something_else_is_refused() {
        for code in ["2", "120", "122", "125", "127"] {
            let error = AnalyzeOpts::try_parse_from([
                "analyze",
                "--success-exit-code",
                code,
                "--",
                "/bin/true",
            ])
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(&format!("{code} is")) && error.contains("could not be told apart"),
                "{code}: {error}"
            );
        }
        for code in ["0", "1", "3", "119", "128"] {
            let options = AnalyzeOpts::try_parse_from([
                "analyze",
                "--success-exit-code",
                code,
                "--",
                "/bin/true",
            ])
            .unwrap();
            assert_eq!(options.success_exit_code, Some(code.parse().unwrap()));
        }
    }

    /// Only a criterion the run misses is reported. Before, `--verbose` printed "Mismatch for stderr pattern"
    /// for every run, right before saying that the stderr matched.
    #[test]
    fn only_the_criteria_a_run_misses_are_reported() {
        let options = AnalyzeOpts::try_parse_from([
            "analyze",
            "--target-stderr=double-close",
            "--target-stdout=^$",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let output = |stdout: &str, stderr: &str, code: i32| Output {
            status: ExitStatus::Exited(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };
        let met = output("", "fdsan: double-close of fd 5\n", 1);
        assert!(options.criteria_misses(&met).is_empty());
        assert!(options.output_matches(&met));

        let missed = options.criteria_misses(&output("ok\n", "all good\n", 0));
        assert_eq!(missed.len(), 3, "{missed:?}");
        assert_eq!(missed[0], "Mismatch for stdout pattern ^$");
        assert_eq!(missed[1], "Mismatch for stderr pattern double-close");
        assert!(missed[2].contains("Exit code 0 is not what we're looking for"));
    }

    fn events(tids: &[i32]) -> Vec<SchedEvent> {
        tids.iter()
            .map(|&tid| SchedEvent::branches(DetTid::from_raw(tid), 10))
            .collect()
    }

    /// A replay leaves its schedule at the first event that differs from the
    /// schedule's as the scheduler compares them when it takes a stack
    /// (another thread, operation or instruction pointer, but not another
    /// count), or where it ends; only the events up to the critical pair
    /// count.
    #[test]
    fn a_replay_leaves_its_schedule_at_the_first_other_event() {
        let requested = events(&[3, 5, 3, 5, 7]);
        assert_eq!(follow(&requested, &events(&[3, 5, 3, 5, 7]), 5).1, None);
        let mut other_count = events(&[3, 5, 3, 5, 7]);
        other_count[2].count = 99;
        assert_eq!(follow(&requested, &other_count, 5).1, None);
        let realized = events(&[3, 5, 9, 5, 7]);
        assert_eq!(
            follow(&requested, &realized, 5).1,
            Some(Departure::OtherEvent {
                index: 2,
                expected: requested[2].clone(),
                ran: realized[2].clone(),
            })
        );
        let mut other_op = requested.clone();
        other_op[1] = SchedEvent::syscall(
            DetTid::from_raw(5),
            reverie::syscalls::Sysno::write,
            detcore_model::schedule::SyscallPhase::Posthook,
        );
        assert!(matches!(
            follow(&requested, &other_op, 5).1,
            Some(Departure::OtherEvent { index: 1, .. })
        ));
        assert_eq!(follow(&requested, &events(&[3, 5, 3, 5, 9]), 4).1, None);
        assert_eq!(
            follow(&requested, &events(&[3, 5]), 5).1,
            Some(Departure::Ended { events: 2 })
        );
    }

    /// A replay may record branch events its schedule leaves out (the
    /// search's interleavings keep only the events both runs share) before
    /// the thread's next event: it still follows the schedule, but the
    /// events after such a branch sit at other positions, so a stack it took
    /// by position there is not that event's. A branch event of another
    /// thread is a departure. Before, the first such branch was reported as
    /// the replay leaving its schedule, at event #74 of a 595-event pair.
    #[test]
    fn a_branch_event_the_schedule_leaves_out_is_no_departure() {
        let tid = DetTid::from_raw;
        let other = |thread: i32, rip: usize| SchedEvent {
            dettid: tid(thread),
            op: detcore_model::schedule::Op::OtherInstructions,
            count: 1,
            start_rip: None,
            end_rip: detcore::types::InstructionPointer::new(rip),
            end_time: None,
            stopless: false,
            strex_fails: Default::default(),
        };
        let requested = vec![
            other(3, 0x10),
            other(3, 0x20),
            SchedEvent::branches(tid(5), 4),
        ];
        let realized = vec![
            other(3, 0x10),
            SchedEvent::branches(tid(3), 1598),
            other(3, 0x20),
            SchedEvent::branches(tid(5), 9),
        ];
        assert_eq!(follow(&requested, &realized, 3), (vec![0, 2, 3], None));
        // A replay that records where a timer cut a slice the schedule
        // records without it ran the same event.
        let mut cut = realized.clone();
        cut[3].end_rip = detcore::types::InstructionPointer::new(0x30);
        assert_eq!(follow(&requested, &cut, 3), (vec![0, 2, 3], None));
        assert!(
            follow(&cut[..], &realized, 4).1.is_some(),
            "the schedule's pointer must match"
        );
        assert_eq!(follow(&requested, &realized, 3).1, None);
        let shifted = StackReplay {
            finished: true,
            met_target: false,
            stacks: [None, None],
            left_schedule: None,
            shifted_at: Some(1),
            ran: [None, None],
            realized: realized.clone(),
            realized_path: PathBuf::new(),
            traced: None,
        };
        assert!(shifted.followed_through(0));
        assert!(
            !shifted.followed_through(1),
            "positions after the branch moved"
        );

        let mut elsewhere = realized.clone();
        elsewhere[1] = SchedEvent::branches(tid(9), 1598);
        assert_eq!(
            follow(&requested, &elsewhere, 3).1,
            Some(Departure::OtherEvent {
                index: 1,
                expected: requested[1].clone(),
                ran: elsewhere[1].clone(),
            })
        );
    }

    /// A replay that re-inserted a branch took its stacks one position
    /// early, on other threads than the pair's: those stacks are not kept,
    /// even under the caveat, and the opening does not call the pair a race.
    /// Before, the thread it ran was looked up by requested event, which
    /// always matched, and the report said "on threads 7 and 9, are RACING"
    /// over stacks of threads 5 and 7.
    #[test]
    fn stacks_a_shifted_replay_took_on_other_threads_are_left_out() {
        use detcore_model::schedule::SyscallPhase;
        use reverie::syscalls::Sysno;
        let tid = DetTid::from_raw;
        let call =
            |thread: i32, sysno| SchedEvent::syscall(tid(thread), sysno, SyscallPhase::Prehook);
        let requested = vec![
            call(5, Sysno::read),
            call(7, Sysno::write),
            call(9, Sysno::close),
        ];
        let realized = vec![
            SchedEvent::branches(tid(5), 12),
            call(5, Sysno::read),
            call(7, Sysno::write),
            call(9, Sysno::close),
        ];
        let (left_schedule, shifted_at, ran) = replay_positions(&requested, &realized, 2);
        assert_eq!((left_schedule.clone(), shifted_at), (None, Some(0)));
        assert_eq!(
            ran,
            [Some(tid(5)), Some(tid(7))],
            "the positions the stacks were taken at"
        );
        let on = |thread: i32| -> PrettyBacktrace {
            serde_json::from_value(serde_json::json!({
                "thread_id": thread, "thread_name": null, "frames": []
            }))
            .unwrap()
        };
        let replay = |stacks: [Option<PrettyBacktrace>; 2]| StackReplay {
            finished: true,
            met_target: false,
            stacks,
            left_schedule: left_schedule.clone(),
            shifted_at,
            ran,
            realized: realized.clone(),
            realized_path: PathBuf::new(),
            traced: None,
        };
        let shifted = replay([Some(on(5)), Some(on(7))]);
        let none = replay([None, None]);
        let threads = [tid(7), tid(9)];
        assert_eq!(merge_stacks(&shifted, &none, 2, threads), [None, None]);
        // A stack's own thread outranks the thread the replay is said to
        // have run there.
        let mut said = replay([Some(on(5)), Some(on(7))]);
        said.ran = [Some(tid(7)), Some(tid(9))];
        assert_eq!(merge_stacks(&said, &none, 2, threads), [None, None]);
        let stacks = [Some(on(5)), Some(on(7))];
        let (text, racing) = racing_pair_opening(threads, [stacks[0].as_ref(), stacks[1].as_ref()]);
        assert!(!racing, "{text}");
        assert!(
            text.contains("stack1 was taken on thread 5, not thread 7"),
            "{text}"
        );

        // A stack on its operation's thread from a shifted replay is kept
        // with a caveat that names the re-inserted branches.
        let kept = replay([Some(on(7)), Some(on(9))]);
        let [first, _] = merge_stacks(&kept, &none, 2, threads);
        let (stack, source) = first.unwrap();
        assert_eq!(stack, on(7));
        assert!(
            source.contains("recorded branch events its schedule leaves out before this operation"),
            "{source}"
        );
    }

    /// Two replays that share a schedule prefix part at the first event at
    /// which their realized schedules run different threads; a count that
    /// differs on one thread is not that.
    #[test]
    fn realized_schedules_part_at_their_first_thread_difference() {
        let passing = events(&[3, 3, 5, 3, 7]);
        let mut failing = events(&[3, 3, 5, 7, 3, 3]);
        failing[2].count = 99;
        assert_eq!(first_thread_difference(&passing, &failing), Some(3));
        assert_eq!(first_thread_difference(&passing, &passing[..4]), None);
    }

    /// The opening of an order-of-events report claims a race only when its
    /// two stacks show two threads. Before, every such report opened "These
    /// two operations, on different threads, are RACING", also with a stack
    /// missing and with both stacks on one thread.
    #[test]
    fn the_order_of_events_opening_says_what_the_stacks_show() {
        let tid = DetTid::from_raw;
        let on = |thread: i32| -> PrettyBacktrace {
            serde_json::from_value(serde_json::json!({
                "thread_id": thread, "thread_name": null, "frames": []
            }))
            .unwrap()
        };
        let (three, five) = (on(3), on(5));
        let (text, racing) = racing_pair_opening([tid(3), tid(5)], [Some(&three), Some(&five)]);
        assert!(racing);
        assert_eq!(
            text,
            "These two operations, on threads 3 and 5, are RACING with each other.\n"
        );
        let (text, racing) = racing_pair_opening([tid(3), tid(5)], [Some(&three), None]);
        assert!(!racing);
        assert!(text.contains("only one has a stack"), "{text}");
        let (text, _) = racing_pair_opening([tid(3), tid(5)], [None, None]);
        assert!(text.contains("neither has a stack"), "{text}");
        let (text, racing) = racing_pair_opening([tid(3), tid(5)], [Some(&three), Some(&three)]);
        assert!(!racing);
        assert!(
            text.contains("both stacks were taken on thread 3"),
            "{text}"
        );
        let (text, racing) = racing_pair_opening([tid(3), tid(3)], [Some(&three), Some(&three)]);
        assert!(!racing);
        assert!(
            text.contains("Both operations belong to thread 3"),
            "{text}"
        );
        for text in [
            racing_pair_opening([tid(3), tid(5)], [Some(&three), None]).0,
            racing_pair_opening([tid(3), tid(3)], [Some(&three), Some(&three)]).0,
        ] {
            assert!(!text.contains("RACING"), "{text}");
        }
    }

    /// When the replays could not follow their schedules, the report says
    /// why: a schedule that cannot be realized there (the replay ran another
    /// call), or branch events the schedules leave out.
    #[test]
    fn a_realized_pair_says_why_the_schedules_were_not_followed() {
        let tid = DetTid::from_raw;
        let replay = |left_schedule, shifted_at| StackReplay {
            finished: true,
            met_target: false,
            stacks: [None, None],
            left_schedule,
            shifted_at,
            ran: [None, None],
            realized: Vec::new(),
            realized_path: PathBuf::new(),
            traced: None,
        };
        let mprotect = SchedEvent::syscall(
            tid(11),
            reverie::syscalls::Sysno::mprotect,
            detcore_model::schedule::SyscallPhase::Prehook,
        );
        let munmap = SchedEvent::syscall(
            tid(11),
            reverie::syscalls::Sysno::munmap,
            detcore_model::schedule::SyscallPhase::Prehook,
        );
        let diverged = replay(
            Some(Departure::OtherEvent {
                index: 750,
                expected: mprotect,
                ran: munmap,
            }),
            None,
        );
        let reason = realized_pair_reason(&diverged, &replay(None, None), 1730);
        assert!(
            reason.starts_with("the replay of the passing schedule ran")
                && reason.contains("at event #750")
                && reason.contains("cannot be realized there"),
            "{reason}"
        );
        let reason = realized_pair_reason(&replay(None, Some(74)), &replay(None, Some(74)), 595);
        assert!(
            reason.contains("branch events the schedules leave out"),
            "{reason}"
        );
    }

    /// A stack either replay captured is reported, in the passing order, with
    /// the replay it came from: the target replay's events #index - 1 and
    /// #index are the passing schedule's #index and #index - 1. A replay that
    /// followed its schedule through the operation is preferred; a stack from
    /// one that did not is kept only if that replay ran the operation's
    /// thread there, and is said to be possibly another occurrence. One
    /// neither gives says where each replay left its schedule. Before, a
    /// baseline replay that left its schedule early reported both stacks as
    /// unavailable, without a reason.
    #[test]
    fn each_racing_stack_comes_from_a_replay_that_reached_it() {
        let tid = DetTid::from_raw;
        let on = |thread: i32, name: &str| -> PrettyBacktrace {
            serde_json::from_value(serde_json::json!({
                "thread_id": thread, "thread_name": name, "frames": []
            }))
            .unwrap()
        };
        let replay = |finished, stacks, left_schedule, ran| StackReplay {
            finished,
            met_target: false,
            stacks,
            left_schedule,
            shifted_at: None,
            ran,
            realized: Vec::new(),
            realized_path: PathBuf::new(),
            traced: None,
        };
        // The passing schedule runs thread 5's read at #1093, then thread 7's
        // close at #1094; the failing one the other way round.
        let threads = [tid(5), tid(7)];
        let left = Some(Departure::OtherEvent {
            index: 735,
            expected: SchedEvent::branches(tid(5), 10),
            ran: SchedEvent::branches(tid(9), 10),
        });
        let baseline = replay(
            true,
            [None, None],
            left.clone(),
            [Some(tid(9)), Some(tid(9))],
        );
        let target = replay(
            true,
            [Some(on(7, "close")), None],
            None,
            [Some(tid(7)), Some(tid(5))],
        );
        let [first, second] = merge_stacks(&baseline, &target, 1094, threads);
        assert_eq!(first, None);
        assert_eq!(
            second,
            Some((on(7, "close"), "the target replay".to_owned())),
            "the target's first is the passing second"
        );

        let ended = StackReplay {
            left_schedule: Some(Departure::Ended { events: 1093 }),
            ..target
        };
        let reason = missing_stack_reason("stack1", (1093, 1094), &baseline, &ended);
        assert!(
            reason.contains("The baseline replay left its schedule: it ran (tid9 cnt=10 Branch) at event #735, where the schedule has (tid5 cnt=10 Branch); the target replay left its schedule: it ended after 1093 events."),
            "{reason}"
        );
        assert!(reason.contains("--selfcheck"), "{reason}");
        let followed_without = replay(true, [None, None], None, [Some(tid(7)), Some(tid(5))]);
        let reason = missing_stack_reason("stack1", (1093, 1094), &baseline, &followed_without);
        assert!(
            reason.contains("the target replay followed its schedule through event #1094, but left no readable stack there"),
            "{reason}"
        );
        let stopped = replay(false, [None, None], Some(Departure::Unknown), [None, None]);
        let reason = missing_stack_reason("stack1", (1093, 1094), &baseline, &stopped);
        assert!(
            reason.contains("did not finish") && reason.contains("--trial-timeout"),
            "{reason}"
        );

        // The baseline replay took its stacks but left its schedule first:
        // the target replay, which followed its own, is preferred.
        let early = replay(
            true,
            [Some(on(5, "early-read")), Some(on(9, "early-write"))],
            left,
            [Some(tid(5)), Some(tid(9))],
        );
        let followed = replay(
            true,
            [Some(on(7, "close")), Some(on(5, "read"))],
            None,
            [Some(tid(7)), Some(tid(5))],
        );
        assert_eq!(
            merge_stacks(&early, &followed, 1094, threads),
            [
                Some((on(5, "read"), "the target replay".to_owned())),
                Some((on(7, "close"), "the target replay".to_owned())),
            ]
        );
        // With no replay that followed its schedule, a stack taken on the
        // operation's thread is kept with a caveat; one taken on another
        // thread (thread 9 where the schedule has thread 7) is left out.
        let [read, close] = merge_stacks(&early, &stopped, 1094, threads);
        let (read, source) = read.unwrap();
        assert_eq!(read, on(5, "early-read"));
        assert!(source.contains("may be another occurrence"), "{source}");
        assert_eq!(close, None);
        // A stopped replay recorded no schedule; its stack still counts when
        // it was taken on the operation's thread.
        let stopped_with = replay(
            false,
            [Some(on(7, "close")), Some(on(9, "other"))],
            Some(Departure::Unknown),
            [None, None],
        );
        let [read, close] = merge_stacks(&baseline, &stopped_with, 1094, threads);
        assert_eq!(read, None);
        assert_eq!(close.unwrap().0, on(7, "close"));

        let both = replay(
            true,
            [Some(on(5, "read")), Some(on(7, "close"))],
            None,
            [Some(tid(5)), Some(tid(7))],
        );
        assert_eq!(
            merge_stacks(&both, &followed, 1094, threads).map(|stack| stack.unwrap().1),
            ["the baseline replay", "the baseline replay"],
            "the baseline replay's own stacks come first"
        );
    }

    /// The final target schedule meets the criteria with another failure
    /// when the line its output pattern matches differs from the target
    /// run's; output the pattern does not match, which can differ with the
    /// interleaving, and line endings around the match are not compared.
    #[test]
    fn a_target_replay_with_another_failure_than_the_target_run_is_named() {
        let workspace = tempfile::tempdir().unwrap();
        let (target, replay) = (
            workspace.path().join("run1_target"),
            workspace.path().join("final_target_for_stacktraces"),
        );
        let pattern = Regex::new("fdsan: ").unwrap();
        let compare = |target_stderr: &str, replay_stderr: &str| {
            std::fs::write(target.with_extension("stderr"), target_stderr).unwrap();
            std::fs::write(replay.with_extension("stderr"), replay_stderr).unwrap();
            changed_output(
                &target,
                &replay,
                [("stdout", None), ("stderr", Some(&pattern))],
            )
        };
        assert_eq!(
            compare(
                "start\nfdsan: double-close\n",
                "other start\nfdsan: double-close"
            ),
            None
        );
        assert_eq!(compare("x\n\n", "x\n"), None, "no match, no comparison");
        let change = compare(
            "start\nfdsan: double-close\n",
            "start\nfdsan: failed to exchange ownership\n",
        )
        .unwrap();
        assert!(
            change.contains("the stderr line that --target-stderr matches is \"fdsan: failed to exchange ownership\", where the target run's is \"fdsan: double-close\""),
            "{change}"
        );
        assert!(change.contains("narrow --target-stderr"), "{change}");
        assert_eq!(
            changed_output(
                &workspace.path().join("absent"),
                &replay,
                [("stdout", None), ("stderr", Some(&pattern))],
            ),
            None,
            "no target run output (hermit bisect): no comparison"
        );
    }

    /// `--minimize`'s baseline knock-out removes a real intervention each
    /// time: the latest priority change, then whole threads, never a thread
    /// left at the default priority (which would change nothing), and gives
    /// up when none is left. Before, the records later knock-outs start
    /// from (recorded runs) named every thread, and once no priority change
    /// was left a knock-out could remove one of those, changing nothing.
    #[test]
    fn the_baseline_knock_out_removes_a_real_intervention_until_none_is_left() {
        use std::collections::BTreeMap;

        use detcore::types::LogicalTime;
        let at = LogicalTime::from_nanos;
        let record = PreemptionRecord::from_vecs(&BTreeMap::from([
            (DetTid::from_raw(3), vec![(at(0), 4923), (at(500), 1200)]),
            (DetTid::from_raw(5), vec![(at(0), 352)]),
            (DetTid::from_raw(9), vec![]),
        ]));
        let threads = |record: &PreemptionRecord| -> Vec<u32> {
            record
                .extract_all()
                .keys()
                .map(|tid| tid.as_raw() as u32)
                .collect()
        };
        let first = knock_out_latest(&record).unwrap();
        assert_eq!(threads(&first), [3, 5], "thread 9 had nothing to knock out");
        assert_ne!(
            first,
            record.without_default_threads(),
            "the knock-out changed the record"
        );
        let mut knocked = first;
        let mut steps = 1;
        while let Some(next) = knock_out_latest(&knocked) {
            assert!(!threads(&next).contains(&9));
            knocked = next;
            steps += 1;
            assert!(steps < 10, "the knock-outs do not end");
        }
        assert_eq!(
            threads(&knocked.without_default_threads()),
            Vec::<u32>::new()
        );
    }

    /// `--minimize`'s baseline search knocks out one more intervention of the
    /// record it last replayed each time, until a replay misses the target or
    /// none is left; it never starts again from a run's own recording, which
    /// holds more priority changes than it replayed. Before, a target whose
    /// replays kept meeting the target knocked out chaos's own changes
    /// without end.
    #[test]
    fn the_baseline_search_knocks_out_the_replayed_record_until_a_replay_misses() {
        use std::collections::BTreeMap;

        use detcore::types::LogicalTime;
        let at = LogicalTime::from_nanos;
        let record = PreemptionRecord::from_vecs(&BTreeMap::from([
            (DetTid::from_raw(3), vec![(at(0), 4923), (at(500), 1200)]),
            (DetTid::from_raw(5), vec![(at(0), 352)]),
        ]));
        let mut replayed = Vec::new();
        let missed = knock_out_until_missed(record.clone(), |attempt, knocked_out| {
            replayed.push(knocked_out.clone());
            Ok((attempt == 2).then_some(attempt))
        })
        .unwrap();
        assert_eq!(missed, 2);
        assert_eq!(replayed[0], knock_out_latest(&record).unwrap());
        assert_eq!(replayed[1], knock_out_latest(&replayed[0]).unwrap());

        let mut attempts = 0;
        let error = knock_out_until_missed(record, |_, _| {
            attempts += 1;
            Ok(None::<()>)
        })
        .unwrap_err();
        assert!(
            error.downcast_ref::<NothingToKnockOut>().is_some(),
            "{error:#}"
        );
        assert!(
            attempts == 3,
            "{attempts} knock-outs for three interventions"
        );
    }

    /// `--target-exit-code` compares the code `hermit run` exits with: the
    /// guest's own, or 128 plus the signal number. Before, it compared the
    /// raw wait status, so `--target-exit-code=121` never matched a run that
    /// exited 121 (raw 30976), and 134 matched SIGABRT only with a core dump.
    #[test]
    fn a_target_exit_code_is_the_one_hermit_run_exits_with() {
        use nix::sys::signal::Signal;
        let exact = |code: &str| code.parse::<ExitStatusConstraint>().unwrap();
        assert!(exact("121").is_match(ExitStatus::Exited(121)));
        assert!(!exact("121").is_match(ExitStatus::Exited(0)));
        assert!(exact("0").is_match(ExitStatus::Exited(0)));
        for coredump in [false, true] {
            let abort = ExitStatus::Signaled(Signal::SIGABRT, coredump);
            assert!(exact("134").is_match(abort), "core dump {coredump}");
            assert!(!exact("6").is_match(abort), "core dump {coredump}");
            assert!(exact("nonzero").is_match(abort));
        }
        assert!(exact("nonzero").is_match(ExitStatus::Exited(121)));
        assert!(!exact("nonzero").is_match(ExitStatus::Exited(0)));
        // A realtime signal, which nix's Signal cannot name: 128 + 40.
        assert!(exact("168").is_match(ExitStatus::SignaledRaw(40, false)));
        for out_of_range in ["256", "-1", "30976"] {
            assert!(
                out_of_range.parse::<ExitStatusConstraint>().is_err(),
                "{out_of_range} is not an exit code"
            );
        }
        // The line naming a missed exit code prints the code, not the raw
        // status (30976 for an exit of 121).
        let options =
            AnalyzeOpts::try_parse_from(["analyze", "--target-exit-code=3", "--", "/bin/true"])
                .unwrap();
        let missed = options.criteria_misses(&Output {
            status: ExitStatus::Exited(121),
            stdout: Vec::new(),
            stderr: Vec::new(),
        });
        assert_eq!(missed, ["  Exit code 121 is not what we're looking for."]);
    }

    /// A report written before the deciding event was reported still reads.
    #[test]
    fn a_report_without_a_deciding_event_reads() {
        let report: Report = serde_json::from_value(serde_json::json!({
            "header": "h",
            "additional_context": "c",
            "baseline_run": true,
            "critical_event1": {"event_index": 1, "stack": null},
            "critical_event2": {"event_index": 2, "stack": null},
        }))
        .unwrap();
        assert_eq!(report.deciding_event, None);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("deciding_event")
        );
        // Nor had it a verdict: it named the critical events, and says so now.
        assert_eq!(report.verdict, Verdict::CriticalEvents);
        assert!(
            serde_json::to_string(&report)
                .unwrap()
                .starts_with(r#"{"verdict":"critical_events","#)
        );
    }

    /// A timing decision: the deciding thread runs on in both continuations,
    /// and the report names how long, and which thread runs next in each.
    #[test]
    fn a_timing_decision_names_the_thread_that_runs_next_in_each_continuation() {
        let with = events(&[5, 3, 3, 3, 7, 5]);
        let without = events(&[5, 3, 3, 5, 7]);
        let thread = DetTid::from_raw(3);
        let with = slice_from(&with, 1, thread);
        let without = slice_from(&without, 1, thread);
        assert_eq!(
            with,
            Slice {
                events: 3,
                branches: 30,
                next: Some((4, DetTid::from_raw(7)))
            }
        );
        assert_eq!(without.next, Some((3, DetTid::from_raw(5))));
        assert_eq!(slice_from(&events(&[3, 3]), 0, thread).next, None);

        let header = timing_decision_header(
            1,
            &SchedEvent::branches(thread, 10),
            (&with, &without),
            "matching stderr",
            NonZeroU64::new(200_000_000),
            None,
        );
        for expected in [
            "it is a timing decision: with or without it, the scheduler runs thread 3 there",
            "thread 3 runs 3 events (30 retired conditional branches) from event #1 on, then thread 7 runs at event #4 (stack1), and the run meets the target criteria (matching stderr)",
            "Without it, scheduling without chaos at a 200000000 ns timeslice, thread 3 runs 2 events (20 retired conditional branches), then thread 5 runs at event #3 (stack2), and the run does not",
        ] {
            assert!(header.contains(expected), "no {expected:?} in\n{header}");
        }

        // The thread that runs next is where it was in both: stack1 and
        // stack2 show where thread 3 stops instead, and the next threads are
        // named without them.
        let header = timing_decision_header(
            1,
            &SchedEvent::branches(thread, 10),
            (&with, &without),
            "matching stderr",
            NonZeroU64::new(200_000_000),
            Some([3, 2]),
        );
        for expected in [
            "from event #1 on, then thread 7 runs at event #4, and the run meets",
            "then thread 5 runs at event #3 (stack2), and the run does not",
            "so stack1 shows where thread 3 is when its slice ends with the event, at event #3, and stack2 is that next thread, without the event (where thread 3's slice ends at event #2).",
        ] {
            assert!(header.contains(expected), "no {expected:?} in\n{header}");
        }
        assert!(!header.contains("(stack1)"), "{header}");
    }

    /// The deciding thread's slice ends replace the next threads' stacks only
    /// when those have the same frames (whichever threads they are) and both
    /// were captured.
    #[test]
    fn slice_ends_are_reported_only_when_the_next_stacks_tell_nothing_apart() {
        let stack = |thread: i32, ips: &[u64]| -> PrettyBacktrace {
            let frames: Vec<_> = ips
                .iter()
                .map(|ip| {
                    serde_json::json!({
                        "frame": {"ip": ip, "is_signal": false},
                        "symbol": null,
                        "locations": []
                    })
                })
                .collect();
            serde_json::from_value(serde_json::json!({
                "thread_id": thread, "thread_name": null, "frames": frames
            }))
            .unwrap()
        };
        let thread = DetTid::from_raw(3);
        let with = slice_from(&events(&[5, 3, 3, 3, 7, 5]), 1, thread);
        let without = slice_from(&events(&[5, 3, 3, 5, 7]), 1, thread);
        let started = [0x10, 0x20];
        // Two different threads, both just started.
        let (seven, five) = (stack(7, &started), stack(5, &started));
        assert_eq!(
            slice_end_events(&with, &without, [Some(&seven), Some(&five)]),
            Some([3, 2])
        );
        let elsewhere = stack(5, &[0x30, 0x20]);
        assert_eq!(
            slice_end_events(&with, &without, [Some(&seven), Some(&elsewhere)]),
            None
        );
        assert_eq!(
            slice_end_events(&with, &without, [Some(&seven), None]),
            None
        );
        let alone = slice_from(&events(&[5, 3, 3]), 1, thread);
        assert_eq!(
            slice_end_events(&alone, &without, [Some(&seven), Some(&five)]),
            None
        );
    }

    #[test]
    fn a_same_thread_critical_pair_is_flagged_and_a_cross_thread_one_is_not() {
        let caveat = critical_pair_caveat(&critical(&[3, 3, 5], 1))
            .expect("two events of thread 3 cannot be reordered");
        assert!(caveat.contains("both belong to thread 3"), "{caveat}");

        assert_eq!(
            critical_pair_caveat(&critical(&[3, 3, 5], 2)),
            None,
            "3 then 5 is a race"
        );
    }

    /// Trials the run arguments' `--timeout` stopped are counted on a line of
    /// their own whenever there are any, whatever the critical pair; the
    /// same-thread caveat is its own line too.
    #[test]
    fn timed_out_trials_are_reported_on_their_own_line() {
        let race = critical(&[3, 3, 5], 2);
        let warnings = search_warnings(&race, 2);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0]
                .starts_with("2 trial(s) did not finish within the run arguments' --timeout"),
            "{warnings:?}"
        );
        assert!(search_warnings(&race, 0).is_empty());

        let same_thread = critical(&[3, 3, 5], 1);
        let warnings = search_warnings(&same_thread, 0);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("both belong to thread 3"),
            "{warnings:?}"
        );
        assert_eq!(search_warnings(&same_thread, 3).len(), 2);
    }

    /// `analyze` and `bisect` take the small `--max-timeslice` notice from the
    /// run arguments every trial shares, where the host can arm the timer the
    /// trials need, and give none for the default.
    #[test]
    fn trials_get_the_small_max_timeslice_notice_from_their_run_arguments() {
        let parse = |run: &[&str]| {
            let mut argv = vec!["analyze", "--"];
            argv.extend(run);
            AnalyzeOpts::try_parse_from(argv).unwrap()
        };
        let timer = crate::run::reverie_timer_support_for_tests();
        let small = parse(&["--max-timeslice=1000", "/bin/true"]);
        // A margin of the test's own, not the process's PMU configuration,
        // which `--skid-margin` tests in this binary must install first.
        let margin: fn() -> u64 = || 10_000;
        let notice = small.small_trial_max_timeslice_notice(margin);
        assert_eq!(notice.is_some(), timer, "{notice:?}");
        if let Some(notice) = notice {
            assert!(
                notice.starts_with("NOTICE: --max-timeslice=1000 "),
                "{notice}"
            );
        }
        assert_eq!(
            parse(&["/bin/true"]).small_trial_max_timeslice_notice(margin),
            None
        );
    }

    /// The target's record replays as edited only when `--minimize` edited
    /// it: otherwise it is the target run's recording, whose replay stops
    /// where it diverges.
    #[test]
    fn the_target_record_replays_as_edited_only_after_minimization() {
        let workspace = tempfile::tempdir().unwrap();
        for (minimize, edited) in [(false, false), (true, true)] {
            let mut argv = vec!["analyze", "--", "/bin/true"];
            if minimize {
                argv.insert(1, "--minimize");
            }
            let mut options = AnalyzeOpts::try_parse_from(argv).unwrap();
            options.tmp_dir = Some(workspace.path().to_path_buf());
            let run =
                RunData::new_baseline(&options, "verify_target_endpoint".to_string()).unwrap();
            let run =
                options.replaying_the_target_record(run, workspace.path().join("target.preempts"));
            assert_eq!(
                run.into_runopts()
                    .det_opts
                    .det_config
                    .replay_edited_preemptions,
                edited,
                "--minimize: {minimize}"
            );
        }
    }

    /// A search round whose trial `--max-log-bytes` ended stops the `--search`
    /// loop and returns that error, still a `LogCapExceeded`, so main reports
    /// it as the cap (123). Before, the loop panicked on any round's error.
    #[test]
    fn a_failing_search_round_ends_the_search_with_its_error() {
        let options =
            AnalyzeOpts::try_parse_from(["analyze", "--analyze-seed=7", "--", "/bin/true"])
                .unwrap();
        for failing_round in 1..=4 {
            let mut rounds = 0;
            let result = options.search_rounds(|round, _sched_seed| {
                assert_eq!(round, rounds, "rounds are numbered from 0");
                rounds += 1;
                if rounds == failing_round {
                    return Err(Error::new(LogCapExceeded));
                }
                // An earlier round finished and did not match.
                Ok(None)
            });
            let Err(error) = result else {
                panic!("round {failing_round} failed, yet the search returned a run")
            };
            assert!(
                error.downcast_ref::<LogCapExceeded>().is_some(),
                "round {failing_round}: the error lost its type: {error:#}"
            );
            assert_eq!(
                rounds, failing_round,
                "the search ran more rounds after round {failing_round} failed"
            );
        }
    }

    const RECORDED: &str = "2000-12-31T23:59:59.123456789Z";
    const RECORDED_RFC3339: &str = "2000-12-31T23:59:59.123456789+00:00";
    const OTHER: &str = "2026-01-01T00:00:00Z";

    /// A preemption record written to `dir` under `name`, with the given
    /// recorded epoch.
    fn record_with_epoch(dir: &Path, name: &str, epoch: Option<&str>) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-resources/flaky_cas_sequence_schedules-passing.json");
        let mut record: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(source).unwrap()).unwrap();
        if let Some(epoch) = epoch {
            record["epoch"] = serde_json::Value::from(epoch);
        }
        let path = dir.join(format!("{name}.json"));
        std::fs::write(&path, record.to_string()).unwrap();
        path
    }

    /// Through `prepare`, which `main` runs before phase 0: the trial
    /// configuration `hermit analyze` would use for these records, or its
    /// refusal.
    fn prepared_analysis(
        dir: &Path,
        run1: Option<&str>,
        run2: Option<&str>,
        run_args: &[&str],
    ) -> anyhow::Result<AnalyzeOpts> {
        let run1 = format!(
            "--run1-preemptions={}",
            record_with_epoch(dir, "run1", run1).display()
        );
        let run2 = run2.map(|epoch| {
            format!(
                "--run2-preemptions={}",
                record_with_epoch(dir, "run2", Some(epoch)).display()
            )
        });
        let mut argv = vec!["hermit", "analyze", run1.as_str()];
        argv.extend(run2.as_deref());
        argv.push("--");
        argv.extend(run_args);
        argv.push("/bin/true");
        let args = crate::Args::try_parse_from(&argv).unwrap();
        let crate::Subcommand::Analyze(mut options) = args.command else {
            panic!("{argv:?} is not analyze")
        };
        options.prepare(&args.global)?;
        options.tmp_dir = Some(dir.to_path_buf());
        Ok(*options)
    }

    /// Analyze runs every trial, the baseline it records without `--chaos`
    /// included, under the `--expired-wait-charge` of its target: the run
    /// arguments' own, or else `--run1-preemptions`'s rule, or else `each`
    /// for the chaos target it records itself. The value is put in the run
    /// arguments, every record analyze writes carries it, and a
    /// `--run2-preemptions` record under the other rule is refused.
    #[test]
    fn analyze_runs_every_trial_under_the_targets_expired_wait_charge() {
        use detcore_model::config::ExpiredWaitCharge;
        let dir = tempfile::tempdir().unwrap();
        let record = |name: &str, once: bool| {
            let path = record_with_epoch(dir.path(), name, None);
            let mut value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if once {
                value["expired_wait_runs_charged_once"] = serde_json::Value::from(true);
            }
            std::fs::write(&path, value.to_string()).unwrap();
            path
        };
        let prepare = |run1: Option<&Path>, run2: Option<&Path>, run_args: &[&str]| {
            let run1 = run1.map(|path| format!("--run1-preemptions={}", path.display()));
            let run2 = run2.map(|path| format!("--run2-preemptions={}", path.display()));
            let mut argv = vec!["hermit", "analyze"];
            argv.extend(run1.as_deref());
            argv.extend(run2.as_deref());
            argv.push("--");
            argv.extend(run_args);
            argv.push("/bin/true");
            let args = crate::Args::try_parse_from(&argv).unwrap();
            let crate::Subcommand::Analyze(mut options) = args.command else {
                panic!("{argv:?} is not analyze")
            };
            options.prepare(&args.global).map(|_| options)
        };
        let each = record("each", false);
        let once = record("once", true);
        let written = |options: &AnalyzeOpts| {
            let (failing, passing, trial) = (
                dir.path().join("final-failing.json"),
                dir.path().join("final-passing.json"),
                dir.path().join("trial.json"),
            );
            options.write_final_schedules(Vec::new(), &failing, Vec::new(), &passing, &[]);
            options
                .write_trial_schedule_from(Vec::new(), &[], &trial)
                .unwrap();
            [failing, passing, trial].map(|path| {
                detcore::preemptions::read_recorded_expired_wait_runs_charged_once(&path).unwrap()
            })
        };
        for (run1, run2, run_args, expected) in [
            (None, None, vec![], ExpiredWaitCharge::Each),
            (
                None,
                None,
                vec!["--expired-wait-charge=once"],
                ExpiredWaitCharge::Once,
            ),
            (Some(&each), None, vec![], ExpiredWaitCharge::Each),
            (Some(&once), None, vec![], ExpiredWaitCharge::Once),
            (Some(&once), Some(&once), vec![], ExpiredWaitCharge::Once),
            (Some(&each), Some(&each), vec![], ExpiredWaitCharge::Each),
        ] {
            let case = format!("{run1:?} {run2:?} {run_args:?}");
            let options = prepare(
                run1.map(|p| p.as_path()),
                run2.map(|p| p.as_path()),
                &run_args,
            )
            .unwrap_or_else(|error| panic!("{case}: {error:#}"));
            assert_eq!(options.trial_expired_wait_charge(), expected, "{case}");
            assert_eq!(
                written(&options),
                [expected == ExpiredWaitCharge::Once; 3],
                "{case}"
            );
        }
        // Without --run1-preemptions the trials use `each`, so a plain
        // (`once`) --run2-preemptions baseline is refused.
        assert_eq!(
            prepare(None, Some(&each), &[])
                .unwrap()
                .trial_expired_wait_charge(),
            ExpiredWaitCharge::Each
        );
        assert!(prepare(None, Some(&once), &[]).is_err());
        for (run1, run2, run_args) in [
            (&once, Some(&each), vec![]),
            (&each, Some(&once), vec![]),
            (&once, None, vec!["--expired-wait-charge=each"]),
        ] {
            let case = format!("{run1:?} {run2:?} {run_args:?}");
            let error = prepare(Some(run1), run2.map(|p| p.as_path()), &run_args).expect_err(&case);
            assert!(
                format!("{error:#}").contains("--expired-wait-charge"),
                "{case}: {error:#}"
            );
        }
    }

    /// Analyze runs every trial, the baseline it records without `--chaos`
    /// included, under the `--sleep-registration` of its target: the run
    /// arguments' own, or else `--run1-preemptions`'s rule, or else
    /// `when-chosen` for the chaos target it records itself. The value is put
    /// in the run arguments, every record analyze writes carries it, and a
    /// `--run2-preemptions` record under the other rule is refused.
    #[test]
    fn analyze_runs_every_trial_under_the_targets_sleep_registration() {
        use detcore_model::config::SleepRegistration;
        let dir = tempfile::tempdir().unwrap();
        let record = |name: &str, first_pass: bool| {
            let path = record_with_epoch(dir.path(), name, None);
            let mut value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if first_pass {
                value["queued_sleeps_registered_at_first_pass"] = serde_json::Value::from(true);
            }
            std::fs::write(&path, value.to_string()).unwrap();
            path
        };
        let prepare = |run1: Option<&Path>, run2: Option<&Path>, run_args: &[&str]| {
            let run1 = run1.map(|path| format!("--run1-preemptions={}", path.display()));
            let run2 = run2.map(|path| format!("--run2-preemptions={}", path.display()));
            let mut argv = vec!["hermit", "analyze"];
            argv.extend(run1.as_deref());
            argv.extend(run2.as_deref());
            argv.push("--");
            argv.extend(run_args);
            argv.push("/bin/true");
            let args = crate::Args::try_parse_from(&argv).unwrap();
            let crate::Subcommand::Analyze(mut options) = args.command else {
                panic!("{argv:?} is not analyze")
            };
            options.prepare(&args.global).map(|_| options)
        };
        let chosen = record("when-chosen", false);
        let first = record("first-pass", true);
        let written = |options: &AnalyzeOpts| {
            let (failing, passing, trial) = (
                dir.path().join("final-failing.json"),
                dir.path().join("final-passing.json"),
                dir.path().join("trial.json"),
            );
            options.write_final_schedules(Vec::new(), &failing, Vec::new(), &passing, &[]);
            options
                .write_trial_schedule_from(Vec::new(), &[], &trial)
                .unwrap();
            [failing, passing, trial].map(|path| {
                detcore::preemptions::read_recorded_queued_sleeps_registered_at_first_pass(&path)
                    .unwrap()
            })
        };
        for (run1, run2, run_args, expected) in [
            (None, None, vec![], SleepRegistration::WhenChosen),
            (
                None,
                None,
                vec!["--sleep-registration=first-pass"],
                SleepRegistration::FirstPass,
            ),
            (Some(&chosen), None, vec![], SleepRegistration::WhenChosen),
            (Some(&first), None, vec![], SleepRegistration::FirstPass),
            (
                Some(&first),
                Some(&first),
                vec![],
                SleepRegistration::FirstPass,
            ),
            (
                Some(&chosen),
                Some(&chosen),
                vec![],
                SleepRegistration::WhenChosen,
            ),
        ] {
            let case = format!("{run1:?} {run2:?} {run_args:?}");
            let options = prepare(
                run1.map(|p| p.as_path()),
                run2.map(|p| p.as_path()),
                &run_args,
            )
            .unwrap_or_else(|error| panic!("{case}: {error:#}"));
            assert_eq!(options.trial_sleep_registration(), expected, "{case}");
            assert_eq!(
                written(&options),
                [expected == SleepRegistration::FirstPass; 3],
                "{case}"
            );
        }
        // Without --run1-preemptions the trials use `when-chosen`, so a plain
        // (first-pass) --run2-preemptions baseline is refused.
        assert_eq!(
            prepare(None, Some(&chosen), &[])
                .unwrap()
                .trial_sleep_registration(),
            SleepRegistration::WhenChosen
        );
        assert!(prepare(None, Some(&first), &[]).is_err());
        for (run1, run2, run_args) in [
            (&first, Some(&chosen), vec![]),
            (&chosen, Some(&first), vec![]),
            (&first, None, vec!["--sleep-registration=when-chosen"]),
        ] {
            let case = format!("{run1:?} {run2:?} {run_args:?}");
            let error = prepare(Some(run1), run2.map(|p| p.as_path()), &run_args).expect_err(&case);
            assert!(
                format!("{error:#}").contains("--sleep-registration"),
                "{case}: {error:#}"
            );
        }
    }

    /// Analyze refuses, before any trial, a `--run1-preemptions` record made
    /// under another `--pipe-wake-latency` than the trials' own, and any
    /// record in its run arguments; its final schedules carry the trials'
    /// value (https://github.com/rrnewton/hermit/issues/4380).
    #[test]
    fn analyze_refuses_records_under_another_pipe_wake_latency() {
        let dir = tempfile::tempdir().unwrap();
        let record = |name: &str, latency: Option<u64>| {
            let path = record_with_epoch(dir.path(), name, None);
            let mut value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if let Some(latency) = latency {
                value["pipe_wake_latency"] = serde_json::Value::from(latency);
            }
            std::fs::write(&path, value.to_string()).unwrap();
            path
        };
        let prepare = |run1: &Path, run_args: &[&str]| {
            let run1 = format!("--run1-preemptions={}", run1.display());
            let mut argv = vec!["hermit", "analyze", run1.as_str(), "--"];
            argv.extend(run_args);
            argv.push("/bin/true");
            let args = crate::Args::try_parse_from(&argv).unwrap();
            let crate::Subcommand::Analyze(mut options) = args.command else {
                panic!("{argv:?} is not analyze")
            };
            options.prepare(&args.global).map(|_| options)
        };
        let off = record("off", None);
        let zero = record("zero", Some(0));
        let options = prepare(&zero, &["--pipe-wake-latency=0"]).unwrap();
        assert_eq!(options.trial_pipe_wake_latency(), Some(0));
        // Every trial-produced, minimized, synthetic and final schedule analyze
        // writes carries the trials' latency: the final schedules, each
        // trial's schedule, and minimize's records (a supplied record analyze
        // copies unchanged, and its normalized copy, are not restamped).
        let written = |options: &AnalyzeOpts| {
            let (failing, passing, trial) = (
                dir.path().join("final-failing.json"),
                dir.path().join("final-passing.json"),
                dir.path().join("trial.json"),
            );
            options.write_final_schedules(Vec::new(), &failing, Vec::new(), &passing, &[]);
            options
                .write_trial_schedule_from(Vec::new(), &[], &trial)
                .unwrap();
            [failing, passing, trial]
                .map(|path| detcore::preemptions::read_recorded_pipe_wake_latency(&path).unwrap())
        };
        assert_eq!(written(&options), [Some(0); 3]);
        assert_eq!(
            options
                .stamp_trial_record(PreemptionRecord::from_vecs(&Default::default()))
                .pipe_wake_latency(),
            Some(0)
        );
        let options_off = prepare(&off, &[]).unwrap();
        assert_eq!(written(&options_off), [None; 3]);
        let replay_flag = format!("--replay-preemptions-from={}", zero.display());
        for (run1, run_args, named) in [
            (&zero, vec![], "--run1-preemptions"),
            (&off, vec!["--pipe-wake-latency=0"], "--run1-preemptions"),
        ] {
            let error = prepare(run1, &run_args).unwrap_err();
            assert!(
                error
                    .downcast_ref::<crate::container::PolicyRefusal>()
                    .is_some(),
                "{error:#}"
            );
            let message = format!("{error:#}");
            assert!(
                message.contains(named) && message.contains("cannot reproduce the run"),
                "{run_args:?}: {message}"
            );
        }
        // A record in the run arguments is refused before any recording is
        // read, whatever its latency (`RunOpts::options_trials_refuse`).
        let error = prepare(&off, &[replay_flag.as_str()]).unwrap_err();
        assert!(
            error
                .downcast_ref::<crate::container::PolicyRefusal>()
                .is_some(),
            "{error:#}"
        );
        assert!(
            format!("{error:#}").contains("refuse --replay-preemptions-from in the run arguments"),
            "{error:#}"
        );
    }

    /// A drawn timeslice travels from analyze to bisect through the production
    /// wiring: `prepare` adopts it from the recording (`--run1-preemptions`),
    /// `write_final_schedules` stamps it on both final schedules, and
    /// `BisectOpts::prepare` adopts it from them, so every bisect replay runs
    /// under it. Removing any of the three steps fails this test. A recording
    /// that states none leaves bisect at the default. The recordings carry an
    /// epoch, which the trials start from, both final schedules state, and
    /// bisect adopts in turn.
    #[test]
    fn analyze_final_schedules_carry_a_drawn_timeslice_into_bisect() {
        let Some(arm) =
            epoch_environment_arm("analyze_final_schedules_carry_a_drawn_timeslice_into_bisect")
        else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let resources = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-resources");
        let events = |fixture: &str| {
            let source = resources.join(format!("flaky_cas_sequence_schedules-{fixture}.json"));
            let record: PreemptionRecord =
                serde_json::from_str(&std::fs::read_to_string(source).unwrap()).unwrap();
            record.into_global()
        };
        // The recordings carry an epoch, as real ones do: the trials must
        // start from it whichever way the recording is given.
        let record = |name: &str, timeslice: Option<u64>| {
            let path = record_with_epoch(dir.path(), name, Some(RECORDED));
            let mut value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if let Some(timeslice) = timeslice {
                value["chaos_timeslice"] = serde_json::Value::from(timeslice);
            }
            std::fs::write(&path, value.to_string()).unwrap();
            path
        };
        let analyze = |analyze_args: &[&str], run_args: &[&str]| {
            let mut argv = vec!["hermit", "analyze"];
            argv.extend(analyze_args);
            argv.push("--");
            argv.extend(run_args);
            argv.push("/bin/true");
            let args = crate::Args::try_parse_from(&argv).unwrap();
            let crate::Subcommand::Analyze(mut options) = args.command else {
                panic!("{argv:?} is not analyze")
            };
            options.prepare(&args.global).map(|_| options)
        };
        let bisect = |good: &Path, bad: &Path| {
            let good = format!("--good={}", good.display());
            let bad = format!("--bad={}", bad.display());
            let argv = [
                "hermit",
                "bisect",
                &good,
                &bad,
                "--",
                "--chaos",
                "/bin/true",
            ];
            let args = crate::Args::try_parse_from(argv).unwrap();
            let crate::Subcommand::Bisect(options) = args.command else {
                panic!("{argv:?} is not bisect")
            };
            let (analyzer, _, _) = options
                .prepare(&args.global)
                .unwrap_or_else(|error| panic!("{argv:?}: {error:#}"));
            analyzer
        };
        let marked = record("marked", Some(808_237));
        let plain = record("plain", None);
        let run1 = format!("--run1-preemptions={}", marked.display());
        let plain_run1 = format!("--run1-preemptions={}", plain.display());
        for (label, analyze_args, run_args, expected) in [
            (
                "--run1-preemptions",
                vec![run1.as_str()],
                vec!["--chaos"],
                Some(808_237),
            ),
            (
                "a recording without one",
                vec![plain_run1.as_str()],
                vec!["--chaos"],
                None,
            ),
        ] {
            if arm == "set" {
                // HERMIT_EPOCH is an explicit epoch other than the
                // recording's: refused before any trial, however it is given.
                let error = analyze(&analyze_args, &run_args).unwrap_err();
                assert!(
                    format!("{error:#}")
                        .contains(&format!("differs from the epoch {RECORDED_RFC3339}")),
                    "{label}: {error:#}"
                );
                continue;
            }
            let mut options = analyze(&analyze_args, &run_args)
                .unwrap_or_else(|error| panic!("{label}: {error:#}"));
            options.tmp_dir = Some(dir.path().to_path_buf());
            // The trials start from the recording's epoch (checked on the run
            // arguments: building a trial validates it against this host's
            // PMU, which a drawn timeslice needs).
            assert!(
                options
                    .run_arg
                    .contains(&format!("--epoch={RECORDED_RFC3339}")),
                "{label}: {:?}",
                options.run_arg
            );
            let (good, bad) = (
                dir.path().join(format!("{expected:?}-good.json")),
                dir.path().join(format!("{expected:?}-bad.json")),
            );
            options.write_final_schedules(events("failing"), &bad, events("passing"), &good, &[]);
            for path in [&good, &bad] {
                assert_eq!(
                    detcore::preemptions::read_recorded_chaos_timeslice(path)
                        .unwrap()
                        .map(std::num::NonZeroU64::get),
                    expected,
                    "{label}: {}",
                    path.display()
                );
                // The trials' epoch is stated too, so bisect starts there.
                assert_eq!(
                    detcore::preemptions::read_recorded_epoch(path)
                        .unwrap()
                        .map(|epoch| epoch.to_rfc3339()),
                    Some(RECORDED_RFC3339.to_owned()),
                    "{label}: {}",
                    path.display()
                );
            }
            let trials = bisect(&good, &bad);
            assert_eq!(
                trials.trial_chaos_timeslice.map(std::num::NonZeroU64::get),
                expected,
                "{label}"
            );
            assert!(
                trials
                    .run_arg
                    .contains(&format!("--epoch={RECORDED_RFC3339}")),
                "{label}: {:?}",
                trials.run_arg
            );
            let maximum: Vec<&String> = trials
                .run_arg
                .iter()
                .filter(|arg| arg.starts_with("--max-timeslice"))
                .collect();
            match expected {
                Some(timeslice) => {
                    assert_eq!(
                        maximum,
                        [&format!("--max-timeslice={timeslice}")],
                        "{label}"
                    )
                }
                None => assert!(maximum.is_empty(), "{label}: {maximum:?}"),
            }
        }
    }

    /// Every trial-produced, minimized, synthetic and final schedule analyze
    /// writes states the trials' signal-state copy setting (a supplied record
    /// analyze copies unchanged, and its normalized copy, are not restamped),
    /// and a recording made under the other setting is refused before any
    /// trial; one that states no setting is accepted.
    #[test]
    fn analyze_stamps_and_checks_the_signal_state_copy_setting() {
        let dir = tempfile::tempdir().unwrap();
        let record = |name: &str, copy: Option<bool>| {
            let path = record_with_epoch(dir.path(), name, None);
            let mut value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            if let Some(copy) = copy {
                value["signal_state_copy"] = serde_json::Value::from(copy);
            }
            std::fs::write(&path, value.to_string()).unwrap();
            path
        };
        let prepare = |run1: &Path, run_args: &[&str]| {
            let run1 = format!("--run1-preemptions={}", run1.display());
            let mut argv = vec!["hermit", "analyze", run1.as_str(), "--"];
            argv.extend(run_args);
            argv.push("/bin/true");
            let args = crate::Args::try_parse_from(&argv).unwrap();
            let crate::Subcommand::Analyze(mut options) = args.command else {
                panic!("{argv:?} is not analyze")
            };
            options.prepare(&args.global).map(|_| options)
        };
        let unsaid = record("unsaid", None);
        let on = record("on", Some(true));
        let off = record("off", Some(false));
        let written = |options: &AnalyzeOpts| {
            let trial = dir.path().join("copy-trial.json");
            options
                .write_trial_schedule_from(Vec::new(), &[], &trial)
                .unwrap();
            detcore::preemptions::read_recorded_signal_state_copy(&trial).unwrap()
        };
        let default = prepare(&on, &[]).unwrap();
        assert!(default.trial_signal_state_copy());
        assert_eq!(written(&default), Some(true));
        let copy_off = prepare(&off, &["--no-signal-state-copy"]).unwrap();
        assert_eq!(written(&copy_off), Some(false));
        assert!(prepare(&unsaid, &[]).is_ok());
        assert!(prepare(&unsaid, &["--no-signal-state-copy"]).is_ok());
        for (run1, run_args) in [(&off, vec![]), (&on, vec!["--no-signal-state-copy"])] {
            let error = prepare(run1, &run_args).unwrap_err();
            assert!(
                error
                    .downcast_ref::<crate::container::PolicyRefusal>()
                    .is_some(),
                "{error:#}"
            );
            assert!(
                format!("{error:#}").contains("signal-state copy"),
                "{error:#}"
            );
        }
    }

    /// Runs `test` (this module's test of that name) in two child processes,
    /// once with `HERMIT_EPOCH` unset and once set to [`OTHER`], and returns
    /// `None`. Inside such a child it returns the arm, `"unset"` or `"set"`.
    /// `HERMIT_EPOCH` counts as an explicit epoch, so the validation's
    /// forwarded value cannot decide the checks.
    fn epoch_environment_arm(test: &str) -> Option<String> {
        const CHILD: &str = "HERMIT_ANALYZE_EPOCH_TEST_CHILD";
        if let Some(arm) = std::env::var_os(CHILD) {
            return Some(arm.into_string().unwrap());
        }
        let name = format!("{}::{test}", module_path!().split_once("::").unwrap().1);
        for arm in ["unset", "set"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, arm);
            if arm == "set" {
                child.env("HERMIT_EPOCH", OTHER);
            } else {
                child.env_remove("HERMIT_EPOCH");
            }
            let output = child.output().unwrap();
            assert!(output.status.success(), "{arm}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{arm}: the child ran no test: {output:?}"
            );
        }
        None
    }

    fn refused(error: anyhow::Error, expected: &str) {
        assert!(error.downcast_ref::<PolicyRefusal>().is_some(), "{error:#}");
        assert!(error.to_string().contains(expected), "{error:#}");
    }

    /// The trial that replays `--run1-preemptions` starts from the epoch the
    /// record was made under, as `hermit run` replaying it does
    /// (https://github.com/rrnewton/hermit/issues/3870). Before, it started
    /// from the run arguments' epoch, the default when none was given. The
    /// checks run in a child process whose environment fixes `HERMIT_EPOCH`,
    /// which counts as an explicit epoch: once unset, and once set to an epoch
    /// other than the recorded one.
    #[test]
    fn analyze_replays_a_record_from_the_epoch_it_was_recorded_under() {
        let Some(arm) =
            epoch_environment_arm("analyze_replays_a_record_from_the_epoch_it_was_recorded_under")
        else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        if arm == "set" {
            refused(
                prepared_analysis(dir, Some(RECORDED), None, &[]).unwrap_err(),
                &format!(
                    "the explicit virtual-time epoch 2026-01-01T00:00:00+00:00 (from --epoch or \
                     HERMIT_EPOCH) differs from the epoch {RECORDED_RFC3339} that \
                     --run1-preemptions"
                ),
            );
            return;
        }

        // A record without an epoch keeps the default.
        let analysis = prepared_analysis(dir, None, None, &[]).unwrap();
        // No `--epoch` is added; `--expired-wait-charge` and `--sleep-registration` always are.
        assert_eq!(
            analysis.run_arg,
            [
                "--expired-wait-charge=each",
                "--sleep-registration=when-chosen"
            ]
        );
        assert_eq!(analysis.trial_epoch_for_test(), "2026-01-01T00:00:00+00:00");

        // The recorded epoch reaches the trials, from either record.
        let analysis = prepared_analysis(dir, Some(RECORDED), None, &[]).unwrap();
        assert_eq!(analysis.trial_epoch_for_test(), RECORDED_RFC3339);
        let analysis = prepared_analysis(dir, None, Some(RECORDED), &[]).unwrap();
        assert_eq!(analysis.trial_epoch_for_test(), RECORDED_RFC3339);

        // An explicit epoch equal to the recorded one adds no second --epoch.
        let analysis =
            prepared_analysis(dir, Some(RECORDED), None, &["--epoch", RECORDED]).unwrap();
        // No `--epoch` is added; `--expired-wait-charge` and `--sleep-registration` always are.
        assert_eq!(
            analysis.run_arg,
            [
                "--expired-wait-charge=each",
                "--sleep-registration=when-chosen"
            ]
        );
        assert_eq!(analysis.trial_epoch_for_test(), RECORDED_RFC3339);

        // A different explicit epoch is refused, naming the remedy.
        refused(
            prepared_analysis(dir, Some(RECORDED), None, &["--epoch", OTHER]).unwrap_err(),
            &format!("pass --epoch={RECORDED_RFC3339}"),
        );

        // Two records under different epochs are refused, naming both.
        refused(
            prepared_analysis(dir, Some(RECORDED), Some(OTHER), &[]).unwrap_err(),
            &format!(
                "was recorded under the virtual-time epoch {RECORDED_RFC3339} and \
                 --run2-preemptions"
            ),
        );
    }

    /// A network trace the run arguments replay (`--replay-networking`)
    /// releases its inputs at absolute virtual times measured from its own
    /// epoch, and every trial replays it. The trials start from that epoch,
    /// and a trace that disagrees with a preemption record or an explicit
    /// epoch is refused before any trial, as `hermit run` refuses it
    /// (https://github.com/rrnewton/hermit/issues/3875). Before, the trials
    /// replayed it from the run arguments' epoch.
    #[test]
    fn analyze_replays_a_network_trace_from_the_epoch_it_was_recorded_under() {
        let Some(arm) = epoch_environment_arm(
            "analyze_replays_a_network_trace_from_the_epoch_it_was_recorded_under",
        ) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let trace = |name: &str, epoch: &str| {
            let path = dir.join(format!("{name}.trace"));
            detcore_model::network_engine::NetworkEngine::new_record(epoch.parse().unwrap())
                .finish()
                .unwrap()
                .write_framed(std::fs::File::create(&path).unwrap())
                .unwrap();
            format!("--replay-networking={}", path.display())
        };
        let recorded = trace("recorded", RECORDED);
        if arm == "set" {
            refused(
                prepared_analysis(dir, None, None, &[&recorded]).unwrap_err(),
                &format!(
                    "the explicit virtual-time epoch 2026-01-01T00:00:00+00:00 (from --epoch or \
                     HERMIT_EPOCH) differs from the epoch {RECORDED_RFC3339} that \
                     --replay-networking"
                ),
            );
            return;
        }

        // The trace alone sets the trials' epoch.
        let analysis = prepared_analysis(dir, None, None, &[&recorded]).unwrap();
        assert_eq!(analysis.trial_epoch_for_test(), RECORDED_RFC3339);

        // With a preemption record from the same epoch it is accepted.
        let analysis = prepared_analysis(dir, Some(RECORDED), None, &[&recorded]).unwrap();
        assert_eq!(analysis.trial_epoch_for_test(), RECORDED_RFC3339);

        // A trace from another epoch than the record is refused, naming both.
        let other = trace("other", OTHER);
        refused(
            prepared_analysis(dir, Some(RECORDED), None, &[&other]).unwrap_err(),
            &format!(
                "was recorded under the virtual-time epoch {RECORDED_RFC3339} and \
                 --replay-networking"
            ),
        );

        // An explicit epoch other than the trace's is refused.
        refused(
            prepared_analysis(dir, None, None, &[&recorded, "--epoch", OTHER]).unwrap_err(),
            &format!("pass --epoch={RECORDED_RFC3339}"),
        );
    }

    /// Through `main`: `--run1-schedule` and `--run2-schedule` parse but have
    /// no implementation, so `hermit analyze` refuses them before any
    /// workspace or trial, naming the options that work. Before, `main`
    /// reached `unimplemented!()` and the process panicked (exit 101).
    #[test]
    fn analyze_refuses_the_unimplemented_schedule_inputs_before_any_trial() {
        for (options, named) in [
            (
                &["--run1-schedule=/nonexistent/run1.json"][..],
                "--run1-schedule",
            ),
            (
                &["--run2-schedule=/nonexistent/run2.json"][..],
                "--run2-schedule",
            ),
            (
                &[
                    "--run1-schedule=/nonexistent/run1.json",
                    "--run2-schedule=/nonexistent/run2.json",
                ][..],
                "--run1-schedule or --run2-schedule",
            ),
        ] {
            let mut argv = vec!["hermit", "analyze"];
            argv.extend(options);
            argv.extend(["--", "/bin/true"]);
            let args = crate::Args::try_parse_from(&argv).unwrap();
            let crate::Subcommand::Analyze(mut analyze) = args.command else {
                panic!("{argv:?} is not analyze")
            };
            let error = analyze.main(&args.global).unwrap_err();
            refused(
                error,
                &format!(
                    "hermit analyze does not implement {named}. Identify a run by a preemption \
                     record (--run1-preemptions or --run2-preemptions"
                ),
            );
            assert!(
                analyze.tmp_dir.is_none(),
                "{options:?}: a workspace was created before the refusal"
            );
        }
    }

    /// A prefix search's trials as `RunData::launch` runs them: a trial the
    /// journal holds takes its recorded outcome; any other first asks the
    /// budget, then runs (here: `outcome`) and is journaled. Each trial's end
    /// and run go into `ends` and `runs`, as `phase5_prefix_search` keeps
    /// them for the bracket.
    struct JournaledPrefixTrials {
        journal: BTreeMap<usize, TrialEnd>,
        ends: Ends,
        runs: BTreeMap<(usize, MaybeTimeslice), String>,
    }

    impl JournaledPrefixTrials {
        fn new() -> Self {
            Self {
                journal: BTreeMap::new(),
                ends: Ends::new(),
                runs: BTreeMap::new(),
            }
        }

        fn trial(
            &mut self,
            budget: &Budget,
            prefix: usize,
            outcome: impl Fn(usize) -> TrialEnd,
        ) -> anyhow::Result<Option<TrialEnd>> {
            let end = match self.journal.get(&prefix) {
                Some(&end) => end,
                None => {
                    budget.start_trial()?;
                    let end = outcome(prefix);
                    self.journal.insert(prefix, end);
                    end
                }
            };
            self.ends.insert((prefix, None), (end, None));
            self.runs
                .insert((prefix, None), format!("prefix_round_{prefix}"));
            Ok(Some(end))
        }
    }

    /// A budget that ends a prefix search leaves a bracket whose lower prefix
    /// misses the target and whose upper prefix meets it, with the deciding
    /// event between them. Resumed with the journal of the trials it ran, the
    /// search runs only the trials it had not, and finds the event the
    /// uninterrupted search finds.
    #[test]
    fn a_budget_ends_the_prefix_search_at_a_bracket_and_a_resume_finds_the_same_event() {
        use crate::analyze::budget::TimeBudget;
        use crate::analyze::budget::TrialBudget;
        let (len, decision) = (37_710, 28_055);
        let outcome = |prefix: usize| {
            if prefix > decision {
                TrialEnd::Met
            } else {
                TrialEnd::Missed
            }
        };
        let mut uninterrupted_trials = 0;
        let uninterrupted = search_prefix_boundary(len, TrialEnd::Missed, |prefix, _| {
            uninterrupted_trials += 1;
            Ok(Some(outcome(prefix)))
        })
        .unwrap();

        let allowed = 7;
        let budget = Budget::new(
            TimeBudget::Off,
            TrialBudget::Limit(NonZeroU64::new(allowed).unwrap()),
        );
        let mut trials = JournaledPrefixTrials::new();
        let stopped = search_prefix_boundary(len, TrialEnd::Missed, |prefix, _| {
            trials.trial(&budget, prefix, outcome)
        })
        .unwrap_err();
        let expired = stopped.downcast_ref::<BudgetExpired>().unwrap();
        assert_eq!(expired.kind, BudgetKind::TrialBudget);
        let bracket = prefix_bracket(&trials.ends, &trials.runs, None, len);
        let (misses, meets) = (bracket.misses.unwrap(), bracket.meets.unwrap());
        assert_eq!(outcome(misses), TrialEnd::Missed);
        assert_eq!(outcome(meets), TrialEnd::Met);
        assert!(misses <= decision && decision < meets, "{bracket:?}");
        assert_eq!(bracket.meets_run, Some(format!("prefix_round_{meets}")));
        assert!(bracket.unfinished.is_empty());

        let resumed_budget = Budget::default();
        let resumed = search_prefix_boundary(len, TrialEnd::Missed, |prefix, _| {
            trials.trial(&resumed_budget, prefix, outcome)
        })
        .unwrap();
        assert_eq!(resumed, uninterrupted);
        assert_eq!(
            allowed + resumed_budget.trials_started(),
            uninterrupted_trials as u64
        );
    }

    /// A time budget ends the search the same way: no trial starts once the
    /// time is spent, whatever the trial budget.
    #[test]
    fn a_time_budget_ends_the_prefix_search_once_the_time_is_spent() {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;

        use crate::analyze::budget::TimeBudget;
        use crate::analyze::budget::TrialBudget;
        let seconds = std::sync::Arc::new(AtomicU64::new(0));
        let clock = std::sync::Arc::clone(&seconds);
        let budget = Budget::with_clock(
            TimeBudget::Limit(std::time::Duration::from_secs(600)),
            TrialBudget::Off,
            std::sync::Arc::new(move || {
                std::time::Duration::from_secs(clock.load(Ordering::SeqCst))
            }),
        );
        let mut trials = JournaledPrefixTrials::new();
        let stopped = search_prefix_boundary(1000, TrialEnd::Missed, |prefix, _| {
            // Every trial takes 250 s of the 600.
            let end = trials.trial(&budget, prefix, |prefix| {
                if prefix > 400 {
                    TrialEnd::Met
                } else {
                    TrialEnd::Missed
                }
            });
            seconds.fetch_add(250, Ordering::SeqCst);
            end
        })
        .unwrap_err();
        assert_eq!(
            stopped.downcast_ref::<BudgetExpired>().unwrap().kind,
            BudgetKind::TimeBudget
        );
        assert_eq!(budget.trials_started(), 3);
        let bracket = prefix_bracket(&trials.ends, &trials.runs, None, 1000);
        assert_eq!((bracket.misses, bracket.meets), (Some(375), Some(500)));
    }

    /// Only trials that finished bound the bracket: a stopped one in between
    /// is named as no outcome.
    #[test]
    fn a_bracket_rests_on_finished_trials() {
        let mut ends = Ends::new();
        let mut runs = BTreeMap::new();
        for (prefix, end) in [
            (0, TrialEnd::Missed),
            (10, TrialEnd::Missed),
            (20, TrialEnd::Unfinished(Stop::Bound)),
            (30, TrialEnd::Met),
            (40, TrialEnd::Met),
        ] {
            ends.insert((prefix, None), (end, None));
            runs.insert((prefix, None), format!("prefix_round_{prefix:03}"));
        }
        let bracket = prefix_bracket(&ends, &runs, None, 50);
        assert_eq!(bracket.misses, Some(10));
        assert_eq!(bracket.meets, Some(30));
        assert_eq!(bracket.unfinished, [20]);
        let said = describe_bracket(&bracket);
        assert!(
            said.contains(
                "replaying the first 10 of the target schedule's 50 events misses the target \
                 (prefix_round_010), and replaying the first 30 meets it (prefix_round_030). The \
                 deciding event is one of events #10 to #29 (20 events)"
            ),
            "{said}"
        );
        assert!(
            said.contains("prefixes of 20 events in between did not finish"),
            "{said}"
        );
        // Before any trial met the target there is no upper end.
        ends.retain(|_, (end, _)| *end != TrialEnd::Met);
        let open = prefix_bracket(&ends, &runs, None, 50);
        assert_eq!((open.misses, open.meets), (Some(10), None));
        assert!(
            describe_bracket(&open).contains("had not yet found a prefix"),
            "{}",
            describe_bracket(&open)
        );
    }

    /// The options of an analysis of `/bin/true` in a fresh workspace under
    /// `parent`, with `extra` options.
    fn analysis_in(parent: &Path, extra: &[&str]) -> (AnalyzeOpts, Workspace) {
        let tmp_dir = format!("--tmp-dir={}", parent.display());
        let mut argv = vec!["analyze", tmp_dir.as_str()];
        argv.extend(extra);
        argv.extend(["--", "--chaos", "/bin/true"]);
        let mut options = AnalyzeOpts::try_parse_from(argv).unwrap();
        let workspace = options.phase0_initialize(Retention::Remove).unwrap();
        (options, workspace)
    }

    /// A partial report says that it is partial, why, which phase was
    /// running, its bracket, and the command that resumes the analysis; it
    /// exits 120 and keeps the workspace.
    #[test]
    fn a_partial_report_says_why_where_and_how_to_resume() {
        let parent = tempfile::tempdir().unwrap();
        let report_file = parent.path().join("report.json");
        let report = format!("--report-file={}", report_file.display());
        let (mut options, _workspace) =
            analysis_in(parent.path(), &[report.as_str(), "--trial-budget=1"]);
        options.budget = Budget::new(options.time_budget, options.trial_budget);
        options.budget.start_trial().unwrap();
        let expired = options.budget.start_trial().unwrap_err();
        options.progress.phase(Phase::PrefixSearch);
        let mut ends = Ends::new();
        ends.insert((100, None), (TrialEnd::Missed, None));
        ends.insert((200, None), (TrialEnd::Met, None));
        let runs = BTreeMap::from([
            ((100, None), "prefix_round_004".to_owned()),
            ((200, None), "prefix_round_003".to_owned()),
        ]);
        let bracket = prefix_bracket(&ends, &runs, None, 300);
        options.progress.bracket(bracket.clone());

        let status = options.report_partial(expired).unwrap();
        assert_eq!(
            status,
            ExitStatus::Exited(hermit::HERMIT_ANALYZE_PARTIAL_EXIT)
        );
        assert!(options.partial_report_written);
        let written: Report =
            serde_json::from_str(&std::fs::read_to_string(&report_file).unwrap()).unwrap();
        let partial = written.partial.unwrap();
        assert_eq!(partial.reason, BudgetKind::TrialBudget);
        assert_eq!(partial.phase, Phase::PrefixSearch);
        assert_eq!(partial.bracket, Some(bracket));
        assert_eq!(partial.runs_started, 1);
        assert_eq!(partial.trial_budget, Some(1));
        assert_eq!(&partial.workspace, options.tmp_dir.as_ref().unwrap());
        assert!(
            partial
                .resume_command
                .contains(&format!("--resume={}", partial.workspace.display())),
            "{}",
            partial.resume_command
        );
        for said in [
            "PARTIAL RESULT. hermit analyze reached its --trial-budget (1 runs)",
            "while searching the target schedule's prefixes (--prefix-search)",
            "The deciding event is one of events #100 to #199 (100 events)",
            "The workspace is kept",
        ] {
            assert!(
                written.header.contains(said),
                "{said:?} not in {}",
                written.header
            );
        }
    }

    /// A resumed analysis restarts its search from the interval the earlier
    /// invocation recorded, with its trial count and warnings, when that
    /// interval is of the same endpoints and its two files hold what it
    /// names; otherwise the search starts from its endpoints.
    #[test]
    fn a_resume_restarts_the_search_only_from_a_whole_interval_of_its_endpoints() {
        let parent = tempfile::tempdir().unwrap();
        let (mut options, _workspace) = analysis_in(parent.path(), &[]);
        options.progress.phase(Phase::Bisect);
        let events = |tids: &[i32]| -> Vec<SchedEvent> {
            tids.iter()
                .map(|&tid| SchedEvent::branches(DetTid::from_raw(tid), 1))
                .collect()
        };
        let (baseline, target) = (events(&[3, 3, 5, 5]), events(&[5, 5, 3, 3]));
        let endpoints = events_digest(&[&baseline, &target]);
        let (passing, failing) = (events(&[3, 5, 3, 5]), events(&[3, 5, 5, 3]));
        let mut interval = IntervalFiles::new(options.tmp_dir.as_ref().unwrap());
        interval.record(
            &options,
            Some(3),
            [&passing, &failing],
            Some((2, 1)),
            Some(SearchState {
                endpoints: endpoints.clone(),
                event_level: true,
                trials: 7,
                unfinished: 1,
                refused: 0,
            }),
        );
        options.resumed_progress = Some(options.progress.snapshot());

        let (resume, pass, resumed_passing, resumed_failing) =
            options.resumable_interval(&endpoints).unwrap();
        assert_eq!(pass, 3);
        assert_eq!(
            (resume.trials, resume.unfinished, resume.refused),
            (7, 1, 0)
        );
        assert!(resume.event_level);
        assert_eq!(resumed_passing, passing);
        assert_eq!(resumed_failing, failing);

        // A search between other endpoints starts over.
        assert!(options.resumable_interval("another digest").is_none());
        // So does one whose file no longer holds what the interval names.
        let recorded = options.progress.snapshot().interval.unwrap();
        options
            .write_trial_schedule_from(events(&[5, 3, 3, 5]), &[], &recorded.passing)
            .unwrap();
        assert!(options.resumable_interval(&endpoints).is_none());
        // And one recorded before the search's first pass, which has no state.
        interval.record(&options, None, [&baseline, &target], None, None);
        options.resumed_progress = Some(options.progress.snapshot());
        assert!(options.resumable_interval(&endpoints).is_none());
    }

    /// A budget hit after the search decided, during the stack-trace runs,
    /// still reports the decision in the report's structured fields: the
    /// deciding event for `--prefix-search`, and the critical pair for the
    /// default search, with no stacks, and exits 120. Before, the decision
    /// was only text, and the event indices were 0 on the prefix path.
    #[test]
    fn a_budget_hit_after_the_decision_reports_it() {
        for (decided, events, critical, deciding) in [
            (
                "event #41 of the target schedule decides the outcome (tid 3)",
                DecidedEvents::Deciding(41),
                [41, 41],
                Some(41),
            ),
            (
                "events #6 and #7 of the failing schedule are the critical pair",
                DecidedEvents::CriticalPair(6, 7),
                [6, 7],
                None,
            ),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let report_file = parent.path().join("report.json");
            let report = format!("--report-file={}", report_file.display());
            let (mut options, _workspace) =
                analysis_in(parent.path(), &[report.as_str(), "--time-budget=30m"]);
            options.budget = Budget::new(options.time_budget, options.trial_budget);
            options.progress.phase(Phase::StackTraces);
            options.progress.decided(decided.to_owned(), events);
            let expired = BudgetExpired {
                kind: BudgetKind::TimeBudget,
                cut: Some("final_target_for_stacktraces".to_owned()),
            };

            let status = options.report_partial(expired).unwrap();
            assert_eq!(
                status,
                ExitStatus::Exited(hermit::HERMIT_ANALYZE_PARTIAL_EXIT)
            );
            let written: Report =
                serde_json::from_str(&std::fs::read_to_string(&report_file).unwrap()).unwrap();
            assert_eq!(
                [
                    written.critical_event1.as_ref().unwrap().event_index,
                    written.critical_event2.as_ref().unwrap().event_index
                ],
                critical,
                "{events:?}"
            );
            assert_eq!(
                written
                    .deciding_event
                    .as_ref()
                    .map(|event| event.event_index),
                deciding,
                "{events:?}"
            );
            assert!(written.critical_event1.as_ref().unwrap().stack.is_none());
            assert!(written.critical_event2.as_ref().unwrap().stack.is_none());
            assert!(
                written
                    .deciding_event
                    .as_ref()
                    .is_none_or(|event| event.stack.is_none())
            );
            let partial = written.partial.unwrap();
            assert_eq!(partial.phase, Phase::StackTraces);
            assert_eq!(partial.decided.as_deref(), Some(decided));
            assert_eq!(
                partial.stacks,
                "not taken: the budget ran out during the stack-trace runs; --resume takes them"
            );
            assert!(
                written
                    .header
                    .contains(&format!("The search had finished: {decided}.")),
                "{}",
                written.header
            );
        }
    }

    /// The same, through the real cut path: a prefix search with a trial
    /// runner in place of the guest and `--trial-budget` set to the trials the
    /// search takes, so the budget runs out at the first stack-trace run
    /// (`final_target_for_stacktraces`), and `end_on_budget` reports it as
    /// `analyze` does. The report carries the decision as above. Resumed
    /// through the journal, the analysis answers the search's trials from it
    /// and finishes with the same deciding event.
    #[test]
    fn a_trial_budget_that_ends_at_the_stack_trace_runs_reports_the_decision() {
        use std::sync::Arc;
        use std::sync::Mutex;

        use crate::analyze::rundata::TrialRunner;
        let (len, deciding) = (200, 137);
        let target = PreemptionRecord::from_sched_events(
            (0..len)
                .map(|i| SchedEvent::branches(DetTid::from_raw(3 + (i % 2)), 1))
                .collect(),
        );
        // A trial meets the target when its prefix holds the deciding event.
        let runner = |names: Arc<Mutex<Vec<String>>>| {
            TrialRunner(Some(Arc::new(move |run: &mut RunData| {
                names.lock().unwrap().push(run.name().to_owned());
                let replayed = run
                    .runopts
                    .det_opts
                    .det_config
                    .replay_schedule_from
                    .clone()
                    .unwrap();
                let prefix = PreemptionReader::new(&replayed)
                    .load_all()
                    .schedevents()
                    .len();
                run.finish_for_test(prefix > deciding, std::time::Duration::from_secs(1));
                Ok(())
            })))
        };
        let search = ["--target-stdout=FAILED", "--prefix-search"];

        // How many trials the search takes, uninterrupted.
        let parent = tempfile::tempdir().unwrap();
        let counted = Arc::new(Mutex::new(Vec::new()));
        let (mut uninterrupted, _uninterrupted_workspace) =
            analysis_in(&parent.path().join("uninterrupted"), &search);
        uninterrupted.start_checkpoint().unwrap();
        uninterrupted.trial_runner = runner(counted.clone());
        assert_eq!(
            uninterrupted
                .phase5_prefix_search(&target)
                .unwrap()
                .decision,
            deciding
        );
        let search_trials = counted.lock().unwrap().len();

        let report_file = parent.path().join("report.json");
        let report = format!("--report-file={}", report_file.display());
        let budget = format!("--trial-budget={search_trials}");
        let mut args = search.to_vec();
        args.extend([report.as_str(), budget.as_str()]);
        let (mut options, mut workspace) = analysis_in(&parent.path().join("first"), &args);
        workspace.keep("the resumed analysis owns it");
        options.start_checkpoint().unwrap();
        options.budget = Budget::new(options.time_budget, options.trial_budget);
        let ran = Arc::new(Mutex::new(Vec::new()));
        options.trial_runner = runner(ran.clone());
        let result = options
            .phase5_prefix_search(&target)
            .and_then(|decision| options.phase6_record_prefix_outputs(decision))
            .map(|_| ExitStatus::SUCCESS);
        let status = options.end_on_budget(result).unwrap();
        assert_eq!(
            status,
            ExitStatus::Exited(hermit::HERMIT_ANALYZE_PARTIAL_EXIT)
        );
        // The search ran to its end; the stack-trace run never started.
        assert_eq!(ran.lock().unwrap().len(), search_trials);
        assert!(
            !ran.lock()
                .unwrap()
                .iter()
                .any(|name| name == "final_target_for_stacktraces")
        );
        let written: Report =
            serde_json::from_str(&std::fs::read_to_string(&report_file).unwrap()).unwrap();
        assert_eq!(
            written
                .deciding_event
                .as_ref()
                .map(|event| event.event_index),
            Some(deciding)
        );
        assert_eq!(
            [
                written.critical_event1.as_ref().unwrap().event_index,
                written.critical_event2.as_ref().unwrap().event_index
            ],
            [deciding, deciding]
        );
        assert!(written.critical_event1.as_ref().unwrap().stack.is_none());
        assert!(written.critical_event2.as_ref().unwrap().stack.is_none());
        assert!(
            written
                .deciding_event
                .as_ref()
                .is_some_and(|event| event.stack.is_none())
        );
        let partial = written.partial.unwrap();
        assert_eq!(partial.reason, BudgetKind::TrialBudget);
        assert_eq!(partial.phase, Phase::StackTraces);
        assert!(
            partial.decided.as_deref().is_some_and(|decided| decided
                .starts_with(&format!("event #{deciding} of the target schedule decides"))),
            "{:?}",
            partial.decided
        );
        assert_eq!(
            partial.stacks,
            "not taken: the budget ran out during the stack-trace runs; --resume takes them"
        );

        // Resumed, the search's trials come from the journal and only the
        // stack-trace runs run.
        let path = workspace.path().to_path_buf();
        let resume = format!("--resume={}", path.display());
        let mut argv = vec!["analyze", resume.as_str()];
        argv.extend(search);
        argv.extend(["--", "--chaos", "/bin/true"]);
        let mut resumed = AnalyzeOpts::try_parse_from(argv).unwrap();
        let resumed_workspace = resumed.phase0_resume(&path).unwrap();
        let resumed_ran = Arc::new(Mutex::new(Vec::new()));
        resumed.trial_runner = runner(resumed_ran.clone());
        let decision = resumed.phase5_prefix_search(&target).unwrap();
        assert_eq!(resumed.journal.answered() as usize, search_trials);
        assert!(resumed_ran.lock().unwrap().is_empty());
        let complete = resumed.phase6_record_prefix_outputs(decision).unwrap();
        assert!(complete.partial.is_none());
        assert_eq!(
            complete.critical_event1.as_ref().unwrap().event_index,
            deciding
        );
        assert_eq!(
            resumed_ran.lock().unwrap().first().map(String::as_str),
            Some("final_target_for_stacktraces")
        );
        drop(resumed_workspace);
        drop(workspace);
    }

    /// The default search's partial report names its pair of schedules, the
    /// first event at which they differ and the commands that replay them,
    /// and says when the stack traces did not fit the grace period.
    #[test]
    fn a_partial_bisection_names_its_pair_and_why_it_took_no_stacks() {
        let parent = tempfile::tempdir().unwrap();
        let (mut options, _workspace) = analysis_in(parent.path(), &["--time-budget=30m"]);
        options.budget = Budget::new(options.time_budget, options.trial_budget);
        options
            .endpoints
            .record(std::time::Duration::from_secs(400), None);
        options.progress.phase(Phase::Bisect);
        let events = |tids: &[i32]| -> Vec<SchedEvent> {
            tids.iter()
                .map(|&tid| SchedEvent::branches(DetTid::from_raw(tid), 1))
                .collect()
        };
        let mut interval = IntervalFiles::new(options.tmp_dir.as_ref().unwrap());
        interval.record(
            &options,
            Some(3),
            [&events(&[3, 3, 5, 3]), &events(&[3, 3, 3, 5])],
            Some((2, 1)),
            None,
        );
        let recorded = options.progress.snapshot().interval.unwrap();
        assert_eq!(recorded.common_prefix, 2);
        assert!(recorded.passing.is_file() && recorded.failing.is_file());

        let expired = BudgetExpired {
            kind: BudgetKind::TimeBudget,
            cut: Some("bisect_round_009".to_owned()),
        };
        assert_eq!(
            options.report_partial(expired).unwrap(),
            ExitStatus::Exited(hermit::HERMIT_ANALYZE_PARTIAL_EXIT)
        );
        let progress = options.progress.snapshot();
        assert_eq!(progress.interval, Some(recorded));
        // Two replays of a 400 s endpoint do not fit min(120 s, 5% of 30 min).
        let partial_stacks = options
            .partial_stacks(progress.interval.as_ref().unwrap())
            .1;
        assert!(
            partial_stacks.starts_with(
                "not taken: two replays as slow as the slowest endpoint run (400 s) do not fit \
                 the grace period of 90 s"
            ),
            "{partial_stacks}"
        );
    }

    /// A resume refuses an analysis of something else, names what differs,
    /// and says how to start over; the same analysis resumes, with the seed
    /// the first invocation drew.
    #[test]
    fn a_resume_refuses_another_analysis_and_says_how_to_start_over() {
        let parent = tempfile::tempdir().unwrap();
        let (mut first, mut workspace) = analysis_in(
            parent.path(),
            &["--target-stdout=FAILED", "--prefix-search"],
        );
        workspace.keep("the resumed analysis owns it");
        first.start_checkpoint().unwrap();
        let drawn = first.analyze_seed.unwrap();
        let path = workspace.path().to_path_buf();
        let resume = format!("--resume={}", path.display());

        for (options, differs) in [
            (
                vec!["--target-stdout=PASSED", "--prefix-search"],
                "the target --target-stdout: recorded FAILED, now PASSED",
            ),
            (
                vec!["--target-stdout=FAILED"],
                "the search option --prefix-search: recorded true, now false",
            ),
        ] {
            let mut argv = vec!["analyze", resume.as_str()];
            argv.extend(options);
            argv.extend(["--", "--chaos", "/bin/true"]);
            let mut again = AnalyzeOpts::try_parse_from(argv).unwrap();
            let error = again.phase0_resume(&path).unwrap_err();
            assert!(error.downcast_ref::<PolicyRefusal>().is_some(), "{error:#}");
            let message = format!("{error:#}");
            assert!(message.contains(differs), "{message}");
            assert!(
                message.contains("To continue anyway, run the same command without --resume"),
                "{message}"
            );
        }
        let mut argv = vec!["analyze", resume.as_str()];
        argv.extend(["--target-stdout=FAILED", "--prefix-search"]);
        argv.extend(["--", "--chaos", "/bin/true"]);
        let mut same = AnalyzeOpts::try_parse_from(argv).unwrap();
        let resumed = same.phase0_resume(&path).unwrap();
        assert_eq!(same.analyze_seed, Some(drawn));
        assert_eq!(same.tmp_dir.as_deref(), Some(path.as_path()));
        assert!(same.journal.is_on());
        drop(resumed);
        drop(workspace);
    }

    /// A resumed analysis that errors or is stopped keeps the workspace it
    /// adopted, with the journal of the runs before it; one that finishes
    /// leaves it to its retention, like a new analysis.
    #[test]
    fn a_resumed_analysis_keeps_its_workspace_unless_it_finishes() {
        let parent = tempfile::tempdir().unwrap();
        let (mut options, _workspace) = analysis_in(parent.path(), &[]);
        let failed: anyhow::Result<ExitStatus> = Err(anyhow::anyhow!("interrupted"));
        let finished: anyhow::Result<ExitStatus> = Ok(ExitStatus::SUCCESS);
        assert_eq!(options.keep_workspace_because(&failed), None);
        options.resume = Some(parent.path().to_path_buf());
        assert!(
            options
                .keep_workspace_because(&failed)
                .unwrap()
                .contains("a resumed analysis that does not finish keeps its workspace")
        );
        assert_eq!(options.keep_workspace_because(&finished), None);
        options.partial_report_written = true;
        assert!(
            options
                .keep_workspace_because(&finished)
                .unwrap()
                .contains("a budget ended the analysis")
        );
    }

    /// A prefix search that a trial budget ends, resumed through
    /// `phase0_resume`, `RunData::launch` and the journal, with a trial runner
    /// in place of the guest: the resumed search answers the trials the first
    /// invocation ran from the journal, runs only the others, and decides
    /// what an uninterrupted search decides.
    #[test]
    fn a_prefix_search_resumed_through_the_journal_decides_as_an_uninterrupted_one() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        use crate::analyze::rundata::TrialRunner;
        let (len, deciding) = (600, 437);
        let target = PreemptionRecord::from_sched_events(
            (0..len)
                .map(|i| SchedEvent::branches(DetTid::from_raw(3 + (i % 2)), 1))
                .collect(),
        );
        // A trial meets the target when its prefix holds the deciding event.
        let runner = |count: Arc<AtomicUsize>| {
            TrialRunner(Some(Arc::new(move |run: &mut RunData| {
                count.fetch_add(1, Ordering::SeqCst);
                let replayed = run
                    .runopts
                    .det_opts
                    .det_config
                    .replay_schedule_from
                    .clone()
                    .unwrap();
                let prefix = PreemptionReader::new(&replayed)
                    .load_all()
                    .schedevents()
                    .len();
                run.finish_for_test(prefix > deciding, std::time::Duration::from_secs(1));
                Ok(())
            })))
        };
        let search = ["--target-stdout=FAILED", "--prefix-search"];

        let parent = tempfile::tempdir().unwrap();
        let uninterrupted_runs = Arc::new(AtomicUsize::new(0));
        let (mut uninterrupted, _uninterrupted_workspace) =
            analysis_in(&parent.path().join("uninterrupted"), &search);
        uninterrupted.start_checkpoint().unwrap();
        uninterrupted.trial_runner = runner(uninterrupted_runs.clone());
        let expected = uninterrupted.phase5_prefix_search(&target).unwrap();
        let all = uninterrupted_runs.load(Ordering::SeqCst);
        assert!(all > 4, "{all} trials");

        let stopped_runs = Arc::new(AtomicUsize::new(0));
        let mut first_args = search.to_vec();
        first_args.push("--trial-budget=4");
        let (mut first, mut workspace) = analysis_in(&parent.path().join("first"), &first_args);
        workspace.keep("the resumed analysis owns it");
        first.start_checkpoint().unwrap();
        first.budget = Budget::new(first.time_budget, first.trial_budget);
        first.trial_runner = runner(stopped_runs.clone());
        let Err(error) = first.phase5_prefix_search(&target) else {
            panic!("the trial budget did not end the search");
        };
        assert!(error.downcast_ref::<BudgetExpired>().is_some(), "{error:#}");
        assert_eq!(stopped_runs.load(Ordering::SeqCst), 4);

        let path = workspace.path().to_path_buf();
        let resume = format!("--resume={}", path.display());
        let mut argv = vec!["analyze", resume.as_str()];
        argv.extend(search);
        argv.extend(["--", "--chaos", "/bin/true"]);
        let mut resumed = AnalyzeOpts::try_parse_from(argv).unwrap();
        let resumed_workspace = resumed.phase0_resume(&path).unwrap();
        let resumed_runs = Arc::new(AtomicUsize::new(0));
        resumed.trial_runner = runner(resumed_runs.clone());
        let decided = resumed.phase5_prefix_search(&target).unwrap();
        assert_eq!(decided.decision, expected.decision);
        assert_eq!(decided.decision, deciding);
        assert_eq!(resumed.journal.answered(), 4);
        assert_eq!(resumed_runs.load(Ordering::SeqCst), all - 4);
        drop(resumed_workspace);
        drop(workspace);
    }
}
