/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Integration coverage for `hermit analyze`, the root-cause search that locates
//! the racing instructions behind a nondeterministic failure.
//!
//! These mirror the Buck `analyze_*` targets from `tests/BUCK`, which drive
//! `tests/util/hermit_analyze_test.sh`: each scenario runs `hermit analyze
//! --search` over a chaotic schedule and asserts that a guest stack trace is
//! printed, optionally blaming a specific source line.
//!
//! The search bisects over chaos schedules and relies on PMU branch counters
//! plus working user/mount namespaces, so the tests are `#[ignore]`d by default
//! (like the `chaos_buck_*` cases in `hermit_modes.rs`) and are exercised
//! explicitly by `scripts/validate.rs`. Run them with:
//!
//! ```text
//! cargo test -p hermit-run --test analyze -- --ignored
//! ```

#[path = "common/hermit_binary.rs"]
mod hermit_test;

use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

static ANALYZE_LOCK: Mutex<()> = Mutex::new(());
static WORKLOADS: OnceLock<AnalyzeWorkloads> = OnceLock::new();
const ANALYZE_SKID_MARGIN_ENV: &str = "HERMIT_ANALYZE_SKID_MARGIN";

/// Guest binaries whose races `hermit analyze` is expected to pinpoint.
///
/// They are compiled beneath `CARGO_TARGET_TMPDIR` (inside the repository's
/// `target/` directory) rather than `/tmp`, because `hermit analyze` bind-mounts
/// its own workspace over `/tmp` in the guest and would otherwise shadow the
/// binary.
struct AnalyzeWorkloads {
    hello_race: PathBuf,
    racewrite_nostdlib: PathBuf,
    nanosleep_nocrash: PathBuf,
    fd_reuse_close_race: PathBuf,
    race_then: PathBuf,
    rpc_shutdown_removes_client: PathBuf,
}

fn command_output(mut command: Command, label: &str) -> Output {
    let rendered = format!("{command:?}");
    let output = hermit_test::hermit_output(&rendered, &mut command);
    assert!(
        output.status.success(),
        "{label} failed: {rendered}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn analyze_lock() -> MutexGuard<'static, ()> {
    ANALYZE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn add_calibrated_skid_margin(command: &mut Command, label: &str) {
    let Some(value) = std::env::var_os(ANALYZE_SKID_MARGIN_ENV) else {
        return;
    };
    let value = value.to_string_lossy();
    let margin = value.parse::<u64>().unwrap_or_else(|error| {
        panic!(
            "{label}: {ANALYZE_SKID_MARGIN_ENV} must be a positive integer, got {value:?}: {error}"
        )
    });
    assert!(
        margin > 0,
        "{label}: {ANALYZE_SKID_MARGIN_ENV} must be greater than zero"
    );
    eprintln!("{label}: using calibrated PMU skid margin {margin} RCB");
    command.arg(format!("--run-arg=--skid-margin={margin}"));
}

fn repository() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("hermit-cli should be inside the repository")
}

/// The `--tmp-dir` a test's analysis creates its workspace in, beside its
/// report. Analyze removes the workspace when it exits, unless `--keep-tmp`.
fn tmp_dir_in(report_dir: &Path) -> PathBuf {
    report_dir.join("workspaces")
}

/// What an analysis left in its `--tmp-dir` (or any directory).
fn left_in(dir: &Path) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("cannot list {}: {error}", dir.display()),
    }
}

/// An analysis that has exited left no workspace in `tmp_dir`, whatever its
/// outcome.
fn assert_no_workspace_left(label: &str, tmp_dir: &Path, combined: &str) {
    let left = left_in(tmp_dir);
    assert!(
        left.is_empty(),
        "{label}: analyze left {left:?} in its --tmp-dir\n{combined}"
    );
}

fn compile_c_pthread(source: &Path, output: &Path) {
    let mut command = Command::new("cc");
    command
        .args(["-O0", "-g", "-pthread", "-D_GNU_SOURCE"])
        .arg(source)
        .arg("-o")
        .arg(output);
    command_output(command, "C workload compilation");
}

fn compile_c_without_libc(source: &Path, output: &Path) {
    let mut command = Command::new("cc");
    command
        .args(["-g", "-nostdlib"])
        .arg(source)
        .arg("-o")
        .arg(output);
    command_output(command, "C workload compilation without libc");
}

fn compile_rust(source: &Path, output: &Path) {
    let mut command = Command::new("rustc");
    command
        .args(["--edition=2024", "-C", "debuginfo=1"])
        .arg(source)
        .arg("-o")
        .arg(output);
    command_output(command, "Rust workload compilation");
}

fn workloads() -> &'static AnalyzeWorkloads {
    WORKLOADS.get_or_init(|| {
        let repository = repository();
        let build_root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hermit-analyze-workloads");
        fs::create_dir_all(&build_root).expect("failed to create analyze workload directory");

        let hello_race = build_root.join("hello_race");
        compile_rust(&repository.join("flaky-tests/hello_race.rs"), &hello_race);

        let racewrite_nostdlib = build_root.join("racewrite_nostdlib");
        compile_c_without_libc(
            &repository.join("tests/c/simple/racewrite_nostdlib.c"),
            &racewrite_nostdlib,
        );

        let nanosleep_nocrash = build_root.join("nanosleep_nocrash");
        compile_c_pthread(
            &repository.join("tests/c/simple/nanosleep-threads-nocrash.c"),
            &nanosleep_nocrash,
        );

        let fd_reuse_close_race = build_root.join("fd_reuse_close_race");
        compile_c_pthread(
            &repository.join("tests/c/fd_reuse_close_race.c"),
            &fd_reuse_close_race,
        );

        let race_then = build_root.join("analyze_race_then");
        compile_c_pthread(
            &repository.join("hermit-cli/tests/fixtures/analyze_race_then.c"),
            &race_then,
        );

        let rpc_shutdown_removes_client = build_root.join("rpc_shutdown_removes_client");
        compile_c_pthread(
            &repository.join("tests/c/rpc_shutdown_removes_client.c"),
            &rpc_shutdown_removes_client,
        );

        AnalyzeWorkloads {
            hello_race,
            racewrite_nostdlib,
            nanosleep_nocrash,
            fd_reuse_close_race,
            race_then,
            rpc_shutdown_removes_client,
        }
    })
}

/// Runs `hermit analyze --search` over `guest` and returns its report file,
/// asserting a successful exit and that at least one guest stack trace was
/// printed. `expected_output`, when non-empty, must also appear in the
/// combined stdout+stderr (used to pin the blamed source line).
///
/// Mirrors `tests/util/hermit_analyze_test.sh`: `--analyze-seed=0 --search`,
/// then a chaotic run with a tight preemption timeout so the search has enough
/// scheduling change points to expose the race.
fn run_analyze(
    label: &str,
    guest: &Path,
    analyze_opts: &[&str],
    expected_output: &str,
) -> serde_json::Value {
    let _guard = analyze_lock();
    let report_dir = tempfile::tempdir().expect("failed to create analyze report directory");
    let report_file = report_dir.path().join("report.json");
    let tmp_dir = tmp_dir_in(report_dir.path());

    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command.arg("analyze");
    command.args(analyze_opts);
    add_calibrated_skid_margin(&mut command, label);
    command
        .arg(format!("--report-file={}", report_file.display()))
        .arg(format!("--tmp-dir={}", tmp_dir.display()))
        .args(["--analyze-seed=0", "--search", "--"])
        // Arguments forwarded to the underlying `hermit run` invocations:
        .args(["--chaos", "--summary", "--max-timeslice=400000", "--"])
        .arg(guest);

    let output = command_output(command, label);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        combined.contains("Stack trace for thread"),
        "{label}: hermit analyze did not print a guest stack trace\n{combined}"
    );
    // The report is the user's; the workspace is analyze's.
    assert!(report_file.is_file(), "{label}: no report\n{combined}");
    assert_no_workspace_left(label, &tmp_dir, &combined);
    // The runs after the target run are bounded in virtual time
    // (--trial-virtual-timeout, by default 10 times the longest endpoint run
    // and at least 60 s of virtual time) and, as a backstop, in wall-clock
    // time (--trial-timeout=auto: 4 times the larger of 60 s and 10 times the
    // slowest endpoint run).
    let bound = |unit: &str| {
        regex::Regex::new(&format!(r"Runs from here on are bounded at (\d+) {unit}"))
            .unwrap()
            .captures(&combined)
            .and_then(|found| found[1].parse::<u64>().ok())
    };
    assert!(
        bound("ns of virtual time").is_some_and(|nanos| nanos >= 60_000_000_000),
        "{label}: no virtual-time trial bound of at least 60 s\n{combined}"
    );
    assert!(
        bound("s of wall-clock time").is_some_and(|seconds| seconds >= 240),
        "{label}: no wall-clock backstop of at least 240 s\n{combined}"
    );
    if !expected_output.is_empty() {
        assert!(
            combined.contains(expected_output),
            "{label}: expected {expected_output:?} in hermit analyze output\n{combined}"
        );
    }

    // Analyze writes the branch-counter warning to stderr at most once, before
    // its first trial, and the report repeats exactly that line, without its
    // newline; it carries none where analyze wrote none.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let warnings: Vec<&str> = stderr
        .lines()
        .filter(|line| line.starts_with("WARNING: this host's retired-branch counter"))
        .collect();
    assert!(warnings.len() <= 1, "{label}: {warnings:?}\n{combined}");
    let report = fs::read_to_string(&report_file)
        .unwrap_or_else(|error| panic!("{label}: no report file: {error}\n{combined}"));
    let report: serde_json::Value = serde_json::from_str(&report)
        .unwrap_or_else(|error| panic!("{label}: unreadable report file: {error}\n{report}"));
    assert_eq!(
        report
            .get("branch_counter_warning")
            .map(|value| value.as_str().expect("branch_counter_warning is a string")),
        warnings.first().copied(),
        "{label}: {report}\n{combined}"
    );
    report
}

/// Exercises analyze's fail-closed endpoint check for a workload whose target
/// outcome now also occurs under the non-chaos baseline schedule.
fn run_analyze_expect_baseline_collision(label: &str, guest: &Path, analyze_opts: &[&str]) {
    let _guard = analyze_lock();
    let report_dir = tempfile::tempdir().expect("failed to create analyze report directory");
    let report_file = report_dir.path().join("report.json");
    let tmp_dir = tmp_dir_in(report_dir.path());

    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command.arg("analyze");
    command.args(analyze_opts);
    add_calibrated_skid_margin(&mut command, label);
    command
        .arg(format!("--report-file={}", report_file.display()))
        .arg(format!("--tmp-dir={}", tmp_dir.display()))
        .args(["--analyze-seed=0", "--search", "--"])
        .args(["--chaos", "--summary", "--preemption-timeout=400000", "--"])
        .arg(guest);

    let rendered = format!("{command:?}");
    let output = hermit_test::hermit_output(&rendered, &mut command);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    assert!(
        !output.status.success(),
        "{label} unexpectedly found distinct target and baseline schedules\n{combined}"
    );
    assert!(
        combined.contains("baseline run matched target criteria when it should not"),
        "{label}: analyze did not reject indistinguishable endpoints\n{combined}"
    );
    // A baseline that meets the target is an input analyze cannot use, not a
    // failure of Hermit.
    assert_precondition(label, &output, "baseline-not-reproduced");
    assert_no_workspace_left(label, &tmp_dir, &combined);
}

#[test]
#[ignore = "slow: bisecting chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_hello_race() {
    run_analyze(
        "analyze hello_race",
        &workloads().hello_race,
        &["--run-arg=--base-env=host"],
        "flaky-tests/hello_race.rs:37",
    );
}

#[test]
#[ignore = "slow: bisecting chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_racewrite_nostdlib() {
    run_analyze(
        "analyze racewrite_nostdlib",
        &workloads().racewrite_nostdlib,
        &[
            "--selfcheck",
            "--run-arg=--base-env=empty",
            "--target-exit-code=0",
            // The current non-chaos baseline is barfoo; analyze the opposite
            // write order so the endpoints remain behaviorally distinct.
            "--target-stdout=foobar",
        ],
        // The racing `write` syscall lives at this line in the guest source.
        "racewrite_nostdlib.c:35",
    );
}

/// `--prefix-search` finds the same race from the target schedule alone: the
/// deciding event is the parent's return from fork, and the thread the
/// scheduler would run there instead is the child at its racing write. The
/// parent's slice ends right after that return in the target schedule, and a
/// trial that stops there leaves that slice end to the scheduler; one that
/// replayed it would name the parent's next event, one too late.
#[test]
#[ignore = "slow: bisecting chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_racewrite_nostdlib_prefix_search() {
    let report = run_analyze(
        "analyze racewrite_nostdlib --prefix-search",
        &workloads().racewrite_nostdlib,
        &[
            "--prefix-search",
            "--run-arg=--base-env=empty",
            "--target-exit-code=0",
            "--target-stdout=foobar",
        ],
        "racewrite_nostdlib.c:35",
    );
    let header = report["header"].as_str().unwrap_or_default();
    assert!(header.contains("Syscall(fork, Posthook)"), "{report}");
    let thread = |event: &str| report[event]["stack"]["thread_id"].as_i64();
    assert!(thread("critical_event1").is_some(), "{report}");
    assert!(thread("critical_event2").is_some(), "{report}");
    assert_ne!(
        thread("critical_event1"),
        thread("critical_event2"),
        "{report}"
    );
}

/// A shutdown that removes a client before the server looks it up
/// (tests/c/rpc_shutdown_removes_client.c): the race is in memory, so the
/// finder can only rank candidates, first the server's change of course
/// against the deciding event. The report checks each candidate by
/// intervention. Moving the server's turn before the shutdown's crosses the
/// client and the poller, and the check says how many events of each; the
/// server then cannot run as edited (it needs the request that now comes
/// after it), so the check is not realized rather than a verdict. No
/// poller nap decides.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_checks_the_race_candidates_and_says_what_each_edit_moved() {
    let report = run_analyze(
        "analyze rpc_shutdown_removes_client --prefix-search",
        &workloads().rpc_shutdown_removes_client,
        &[
            "--prefix-search",
            "--run-arg=--base-env=empty",
            "--target-stdout=call failed",
        ],
        "call failed",
    );
    let racing = &report["racing_accesses"];
    assert_eq!(racing["status"], "candidates", "{report}");
    let candidates = racing["candidates"].as_array().cloned().unwrap_or_default();
    let calls = |c: &serde_json::Value| -> Vec<String> {
        (0..2)
            .map(|i| c["accesses"][i]["call"].as_str().unwrap_or("").to_owned())
            .collect()
    };
    let change = candidates
        .iter()
        .find(|c| calls(c).iter().any(|call| call.contains("not found")))
        .unwrap_or_else(|| panic!("no candidate names the server's change: {report}"));
    let check = &change["check"];
    assert_eq!(check["verdict"], "not_realized", "{report}");
    assert!(
        check["edit"].as_str().unwrap_or("").starts_with("moving ")
            && check["moved"]["events"].as_u64().unwrap_or(0) > 0
            && !check["moved"]["crossed"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .is_empty(),
        "{report}"
    );
    for candidate in &candidates {
        assert!(candidate["check"].is_object(), "{report}");
        if calls(candidate)
            .iter()
            .any(|call| call.starts_with("nanosleep("))
        {
            assert_ne!(candidate["check"]["verdict"], "decides", "{report}");
        }
    }
}

/// A deferred second close of a descriptor number another thread reopened
/// (tests/c/fd_reuse_close_race.c, the fdsan pattern): the report's
/// "Racing accesses" section names the closer's close and the writer's lseek
/// that fails with EBADF, on two threads, and no edge Hermit observes orders
/// them.
#[test]
#[ignore = "slow: bisecting chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_names_the_close_racing_the_reused_descriptor() {
    let report = run_analyze(
        "analyze fd_reuse_close_race --prefix-search",
        &workloads().fd_reuse_close_race,
        &[
            "--prefix-search",
            "--run-arg=--base-env=empty",
            "--target-stderr=failed with EBADF",
        ],
        "unordered by the edges Hermit observes",
    );
    let racing = &report["racing_accesses"];
    assert_eq!(racing["status"], "found", "{report}");
    let access = |i: usize, field: &str| racing["accesses"][i][field].clone();
    let call = |i: usize| access(i, "call").as_str().unwrap_or_default().to_owned();
    assert!(call(0).starts_with("close("), "{report}");
    assert!(call(1).starts_with("lseek("), "{report}");
    assert_eq!(access(1, "result"), "-EBADF", "{report}");
    assert_ne!(access(0, "thread"), access(1, "thread"), "{report}");
    assert_eq!(
        racing["happens_before"]["target"]["ordered"], false,
        "{report}"
    );
}

#[test]
#[ignore = "slow: bisecting chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_nanosleep_threads_rejects_indistinguishable_baseline() {
    run_analyze_expect_baseline_collision(
        "analyze nanosleep-threads baseline collision",
        &workloads().nanosleep_nocrash,
        &["--run-arg=--base-env=empty", "--target-exit-code=0"],
    );
}

/// The first chaos seed under which `analyze_race_then THEN`, run with
/// `run_args`, takes the order that finishes ("b-first", exit 0). A run in
/// the other order may not end by itself, so each is bounded at 5 s.
fn race_then_target_seed(then: &str, run_args: &[&str]) -> u64 {
    let guest = &workloads().race_then;
    (0..40)
        .find(|seed| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
            command
                .args(["run", "--chaos", "--timeout=5"])
                .args(run_args)
                .arg(format!("--seed={seed}"))
                .arg("--")
                .arg(guest)
                .arg(then);
            let output = hermit_test::hermit_output(&format!("{command:?}"), &mut command);
            output.status.success() && output.stdout == b"b-first\n"
        })
        .expect("no chaos seed in 0..40 lets thread b win the race")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

/// Analyze (or bisect) ended because its inputs do not give it what it
/// needs: exit 2, the precondition's class line on stderr, and no internal
/// failure (125 and `HERMIT_INTERNAL_FAILURE class=cli-error` before).
fn assert_precondition(label: &str, output: &Output, class: &str) {
    let combined = combined_output(output);
    assert_eq!(
        output.status.code(),
        Some(hermit::HERMIT_ANALYZE_PRECONDITION_EXIT),
        "{label}\n{combined}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = format!("HERMIT_ANALYZE_PRECONDITION class={class}");
    assert!(
        stderr.lines().any(|candidate| candidate == line)
            && !stderr.contains("HERMIT_INTERNAL_FAILURE"),
        "{label}: no {line:?}\n{combined}"
    );
}

/// `hermit bisect` verifies its endpoints as analyze does: a --good schedule
/// that meets the target is an input it cannot use, so it ends with exit 2
/// and `HERMIT_ANALYZE_PRECONDITION class=baseline-not-reproduced`, as
/// analyze would. Before, it exited 125 with `HERMIT_INTERNAL_FAILURE
/// class=cli-error`.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn bisect_exits_2_when_its_good_schedule_meets_the_target() {
    let label = "bisect analyze_race_then, --good meets the target";
    let guest = &workloads().race_then;
    let then = "exit";
    let target_seed = race_then_target_seed(then, &[]);
    // Not in /tmp: the schedule is written where the guest's /tmp is not.
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("failed to create bisect directory");
    let record = |seed: u64| -> (PathBuf, Vec<u8>) {
        let schedule = dir.path().join(format!("seed-{seed}.json"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
        command
            // One epoch for both schedules, which bisect requires.
            .args([
                "run",
                "--chaos",
                "--timeout=5",
                "--epoch=2026-01-01T00:00:00Z",
            ])
            .arg(format!("--seed={seed}"))
            .arg(format!("--record-preemptions-to={}", schedule.display()))
            .arg("--")
            .arg(guest)
            .arg(then);
        let output = hermit_test::hermit_output(&format!("{command:?}"), &mut command);
        (schedule, output.stdout)
    };
    let (target, stdout) = record(target_seed);
    assert_eq!(stdout, b"b-first\n", "{label}: target seed {target_seed}");
    let (passing, _) = (0..40)
        .filter(|&seed| seed != target_seed)
        .map(record)
        .find(|(_, stdout)| stdout == b"a-first\n")
        .expect("no chaos seed in 0..40 lets thread a win the race");
    let _guard = analyze_lock();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command
        .arg("bisect")
        // Swapped: the schedule called good is the one that meets the target.
        .arg(format!("--good={}", target.display()))
        .arg(format!("--bad={}", passing.display()))
        .args(["--target-stdout=b-first", "--target-exit-code=0"])
        .args(["--", "--timeout=30", "--"])
        .arg(guest)
        .arg(then);
    let output = hermit_test::hermit_output(label, &mut command);
    assert!(
        combined_output(&output)
            .contains("the passing schedule endpoint did not reproduce a passing outcome"),
        "{label}\n{}",
        combined_output(&output)
    );
    assert_precondition(label, &output, "baseline-not-reproduced");
}

/// `hermit analyze` over `analyze_race_then THEN` from a target seed, with
/// more analyze options and run arguments: its output and report, if it
/// wrote one.
fn analyze_race_then_with(
    then: &str,
    analyze_opts: &[&str],
    run_args: &[&str],
) -> (Output, Option<serde_json::Value>) {
    let seed = race_then_target_seed(then, run_args);
    let _guard = analyze_lock();
    let report_dir = tempfile::tempdir().expect("failed to create analyze report directory");
    let report_file = report_dir.path().join("report.json");
    let tmp_dir = tmp_dir_in(report_dir.path());
    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command
        .arg("analyze")
        .args(["--target-stdout=b-first", "--target-exit-code=0"])
        .args(analyze_opts)
        .arg(format!("--run1-seed={seed}"))
        .arg(format!("--report-file={}", report_file.display()))
        .arg(format!("--tmp-dir={}", tmp_dir.display()))
        .args(["--", "--chaos"])
        .args(run_args)
        .arg("--")
        .arg(&workloads().race_then)
        .arg(then);
    let output = hermit_test::hermit_output(&format!("{command:?}"), &mut command);
    assert_no_workspace_left(&format!("{command:?}"), &tmp_dir, &combined_output(&output));
    let report = fs::read_to_string(&report_file).ok().map(|text| {
        serde_json::from_str(&text).unwrap_or_else(|error| {
            panic!("unreadable report: {error}\n{}", combined_output(&output))
        })
    });
    (output, report)
}

/// [`analyze_race_then_with`], asserting that analyze succeeded and wrote a
/// report naming a critical event: the combined output and the report.
fn analyze_race_then(
    label: &str,
    then: &str,
    analyze_opts: &[&str],
) -> (String, serde_json::Value) {
    let (output, report) = analyze_race_then_with(then, analyze_opts, &[]);
    let combined = combined_output(&output);
    assert!(
        output.status.success(),
        "{label} failed: {}\n{combined}",
        output.status
    );
    let report = report.unwrap_or_else(|| panic!("{label}: no report\n{combined}"));
    assert!(
        report["critical_event1"]["event_index"].is_u64(),
        "{label}: {report}"
    );
    (combined, report)
}

/// A wall-clock bound short enough that a trial that never ends reaches it
/// long before the virtual-time bound.
const TRIAL_TIMEOUT_3: &str = "--trial-timeout=3";

const BOUND_REACHED: &str = "reached hermit analyze's bound of 3 s for this run \
                             (--trial-timeout=SECONDS raises it, --trial-timeout=off lifts it)); \
                             counted as not meeting the target";

/// Every prefix trial in which thread a wins the race spins for ever, the
/// run without chaos (the prefix search's baseline) among them. Each is
/// bounded by `--trial-timeout` and counts as not meeting the target, so
/// the search still finds the deciding event. Before the bound, the first
/// such trial never ended. The trial on the boundary's baseline side runs
/// once more with 4 times the bound, does not finish then either, and the
/// report says the boundary rests on that bound rather than on an outcome.
/// The virtual-time bound is off: a confirmation of 12 s could otherwise
/// reach it first on a fast host.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_bounds_trials_that_never_end() {
    let label = "analyze --prefix-search analyze_race_then spin";
    let (combined, report) = analyze_race_then(
        label,
        "spin",
        &[
            "--prefix-search",
            TRIAL_TIMEOUT_3,
            "--trial-virtual-timeout=off",
        ],
    );
    assert!(
        combined.contains(BOUND_REACHED),
        "{label}: no trial reached the bound\n{combined}"
    );
    assert!(
        combined.contains("running it again with a bound of 12 s, so that a finished trial"),
        "{label}: the boundary was not confirmed\n{combined}"
    );
    let header = report["header"].as_str().unwrap();
    assert!(
        header.contains("does not finish, which the search counts as not meeting")
            && header.contains("this boundary rests on a wall-clock bound, not on an outcome"),
        "{label}: {report}"
    );
}

/// The same spinning trials under the default virtual-time bound: each
/// reaches it (60 s of virtual time) at the same scheduler turn on every
/// host. Such a trial counts as not meeting the target, and the one on the
/// boundary's baseline side is not confirmed with a longer bound, since a
/// rerun at the same bound stops at the same turn: the report calls it a
/// hang that the boundary rests on a virtual-time bound for. A stopped trial
/// keeps its recorded schedule, so the report also shows the thread the
/// scheduler runs instead (stack2). A debug build took 87 to 121 s of host
/// time to reach the bound in this spin, so the wall-clock bound is raised
/// from the 240 s backstop to 600 s, for the virtual-time bound to stop every
/// trial on a slower or busier host too.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_bounds_trials_that_never_end_in_virtual_time() {
    let label = "analyze --prefix-search analyze_race_then spin, virtual-time bound";
    let (combined, report) =
        analyze_race_then(label, "spin", &["--prefix-search", "--trial-timeout=600"]);
    assert!(
        combined.contains("reached hermit analyze's virtual-time bound of"),
        "{label}: no trial reached the virtual-time bound\n{combined}"
    );
    assert!(
        combined.contains("Stopped in virtual time"),
        "{label}: no trial was stopped in virtual time\n{combined}"
    );
    assert!(
        !combined.contains("running it again with a bound"),
        "{label}: a trial the virtual-time bound stopped was confirmed\n{combined}"
    );
    // The final recheck runs the boundary's trials once more; the one the
    // virtual-time bound stopped stops at the same turn again.
    assert!(
        !combined.contains("gave other outcomes"),
        "{label}: a recheck of the boundary did not repeat\n{combined}"
    );
    let header = report["header"].as_str().unwrap();
    assert!(
        header.contains("this boundary rests on a virtual-time bound, not on an outcome"),
        "{label}: {report}"
    );
    assert!(
        report["critical_event2"]["stack"].is_object(),
        "{label}: no stack2\n{report}"
    );
}

/// The default search's baseline is the run without chaos, which here spins
/// for ever. The bound ends it too, and with no baseline schedule analyze
/// searches within the target schedule instead. Before, the baseline run
/// never ended, whatever --trial-timeout said.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_searches_the_target_schedule_when_the_baseline_never_ends() {
    let label = "analyze analyze_race_then spin";
    let (combined, _) = analyze_race_then(label, "spin", &[TRIAL_TIMEOUT_3]);
    assert!(
        combined.contains(
            "the baseline run (non-chaos (0 extra preemptions) run) did not finish, so it \
             recorded no schedule to bisect against"
        ) && combined.contains("Searching within the target schedule instead"),
        "{label}: no fallback\n{combined}"
    );
}

/// Every prefix trial in which thread a wins the race asks for something
/// Hermit refuses at run time (exit 122), the run without chaos (the prefix
/// search's baseline) among them. Each counts as not meeting the target, with
/// a warning, and the report says how many were refused. Before, the first
/// refused trial ended the whole analysis with exit 122. The refusal is
/// Detcore's for a process-directed signal while several threads live
/// (https://github.com/rrnewton/hermit/issues/4034); once that is supported,
/// the fixture needs another refused operation.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_counts_a_refused_trial_as_the_baseline() {
    let label = "analyze --prefix-search analyze_race_then refuse";
    let (combined, report) =
        analyze_race_then(label, "refuse", &["--prefix-search", TRIAL_TIMEOUT_3]);
    assert!(
        combined.contains(
            "Hermit refused this trial when the guest reached an operation it does not support"
        ),
        "{label}: no trial was refused\n{combined}"
    );
    assert!(
        report["header"]
            .as_str()
            .unwrap()
            .contains("trial(s) were refused by Hermit (exit 122) and counted as not reaching"),
        "{label}: {report}"
    );
}

/// The target run itself is refused: it cannot be studied, so analyze ends
/// with Hermit's refusal (exit 122) rather than counting it.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_ends_with_a_refused_target_run() {
    let label = "analyze analyze_race_then refuse, target refused";
    let guest = &workloads().race_then;
    // The run without chaos takes the order Hermit refuses.
    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command
        .args(["analyze", "--prefix-search", "--target-stdout=a-first"])
        .args(["--", "--timeout=30", "--"])
        .arg(guest)
        .arg("refuse");
    let output = hermit_test::hermit_output(label, &mut command);
    let combined = combined_output(&output);
    assert_eq!(output.status.code(), Some(122), "{label}\n{combined}");
    assert!(
        combined.contains("HERMIT_POLICY_REFUSAL"),
        "{label}\n{combined}"
    );
}

/// A race found only at a short timeslice: at the run's own 100 us, thread a
/// is preempted before it claims even without chaos, so the scheduler alone
/// meets the target and gives the prefix search nothing to bisect against.
/// The search says so and continues at hermit's default 200 ms, where it
/// does not. Before, the analysis ended there with exit 125.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_continues_prefixes_at_a_coarser_timeslice() {
    let label = "analyze --prefix-search analyze_race_then late-a --max-timeslice=100000";
    let (output, report) = analyze_race_then_with(
        "late-a",
        &["--prefix-search", TRIAL_TIMEOUT_3],
        &["--max-timeslice=100000"],
    );
    let combined = combined_output(&output);
    assert!(
        output.status.success(),
        "{label}: {}\n{combined}",
        output.status
    );
    assert!(
        combined.contains(
            "Continuing without chaos at a 100000 ns timeslice, the scheduler alone, replaying \
             none of the target schedule, meets the target"
        ),
        "{label}\n{combined}"
    );
    let report = report.unwrap_or_else(|| panic!("{label}: no report\n{combined}"));
    assert!(
        report["header"]
            .as_str()
            .unwrap()
            .contains("scheduling without chaos at a 200000000 ns timeslice does not meet"),
        "{label}: {report}"
    );
}

/// The same race with `--continuation-timeslice=100000`: there is no other
/// continuation to try, so analyze concludes that the outcome does not
/// depend on a chaos decision, and says what to run or pass instead. That is
/// a completed analysis: exit 0, `HERMIT_ANALYZE_VERDICT
/// class=no-deciding-event`, and a report whose verdict says so. Before, it
/// exited 125 with `HERMIT_INTERNAL_FAILURE class=cli-error`.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_explains_a_target_the_scheduler_meets_alone() {
    let label = "analyze --prefix-search analyze_race_then late-a --continuation-timeslice=100000";
    let (output, report) = analyze_race_then_with(
        "late-a",
        &[
            "--prefix-search",
            "--continuation-timeslice=100000",
            TRIAL_TIMEOUT_3,
        ],
        &["--max-timeslice=100000"],
    );
    let combined = combined_output(&output);
    assert_eq!(output.status.code(), Some(0), "{label}\n{combined}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .lines()
            .any(|line| line == "HERMIT_ANALYZE_VERDICT class=no-deciding-event")
            && !stderr.contains("HERMIT_INTERNAL_FAILURE"),
        "{label}\n{combined}"
    );
    let report = report.unwrap_or_else(|| panic!("{label}: no report\n{combined}"));
    assert_eq!(report["verdict"], "no_deciding_event", "{label}: {report}");
    assert!(
        report["header"].as_str().is_some_and(
            |header| header.starts_with("no event of the target schedule decides the outcome")
        ),
        "{label}: {report}"
    );
    for expected in [
        "no event of the target schedule decides the outcome: without chaos, the scheduler alone \
         already meets the target criteria at a 100000 ns timeslice",
        "prefix_round_001.repro",
        "pass --continuation-timeslice",
        "--run2-seed",
    ] {
        assert!(
            combined.contains(expected),
            "{label}: no {expected:?}\n{combined}"
        );
    }
}

/// `--run1-preemptions` replays the record as the target run, measured for
/// the trial bound and logged like a seed's run. Before, analyze did not run
/// it at all, and the next phase unwrapped the log of a run that never ran
/// (exit 101). The record is read from the host's /tmp, which the guest's
/// container does not see, so analyze replays a copy in its workspace. A
/// replay that misses the target ends the analysis with an error that says
/// why.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_starts_from_a_recorded_target_run() {
    let label = "analyze --prefix-search --run1-preemptions analyze_race_then plain";
    let guest = &workloads().race_then;
    let seed = race_then_target_seed("plain", &[]);
    // Recorded outside /tmp: the run's guest has a private one, and the
    // record is written from inside the container.
    let workspace =
        tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("failed to create a workspace");
    let recorded = workspace.path().join("target.preempts");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command
        .args(["run", "--chaos"])
        .arg(format!("--seed={seed}"))
        .arg(format!("--record-preemptions-to={}", recorded.display()))
        .arg("--")
        .arg(guest)
        .arg("plain");
    let output = hermit_test::hermit_output(label, &mut command);
    assert!(
        output.status.success() && output.stdout == b"b-first\n",
        "{label}: the recorded run missed the target\n{}",
        combined_output(&output)
    );
    let host_tmp = tempfile::tempdir_in("/tmp").expect("failed to create a directory under /tmp");
    let record = host_tmp.path().join("target.preempts");
    fs::copy(&recorded, &record).unwrap();

    let _guard = analyze_lock();
    let analyze = |target_stdout: &str, report_file: &Path| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
        command
            .args(["analyze", "--prefix-search", "--target-exit-code=0", "-v"])
            .arg(format!("--target-stdout={target_stdout}"))
            .arg(format!("--run1-preemptions={}", record.display()))
            .arg(format!("--report-file={}", report_file.display()))
            .args(["--", "--chaos"])
            .arg(format!("--seed={seed}"))
            .arg("--")
            .arg(guest)
            .arg("plain");
        hermit_test::hermit_output(label, &mut command)
    };
    let report_file = workspace.path().join("report.json");
    let output = analyze("b-first", &report_file);
    let combined = combined_output(&output);
    assert!(
        output.status.success(),
        "{label}: {}\n{combined}",
        output.status
    );
    assert!(
        combined.contains("First run matched target criteria")
            && combined.contains("Runs from here on are bounded at"),
        "{label}: the record was not run as the target\n{combined}"
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report_file).unwrap()).unwrap();
    assert!(
        report["critical_event1"]["event_index"].is_u64(),
        "{label}: {report}"
    );

    // The record's replay prints b-first, so a-first is a miss.
    let output = analyze("a-first", &workspace.path().join("miss.json"));
    let combined = combined_output(&output);
    assert!(
        !output.status.success()
            && output.status.code() != Some(101)
            && combined.contains("did not meet the target criteria")
            && combined.contains("--seed included"),
        "{label}: a missed replay: {}\n{combined}",
        output.status
    );
    // A record that does not give a target run is an input analyze cannot
    // use: exit 2, not a failure of Hermit.
    assert_precondition(label, &output, "target-not-reproduced");
}

/// `--target-exit-code` names the exit code as a shell reports it: the
/// guest's own (121 here; with the guest-deadlock outcome, also the code of
/// a run Hermit ends as a deadlock), or 128 plus the signal number when a
/// signal killed the guest (143 for SIGTERM, which dumps no core). Before,
/// analyze compared the raw wait status, so neither matched and analyze
/// said the target run missed the target.
#[test]
#[ignore = "slow: runs hermit analyze; requires PMU branch counters and working mount namespaces"]
fn analyze_targets_the_exit_code_hermit_run_reports() {
    for (code, script) in [
        ("121", "echo TARGET; exit 121"),
        ("143", "echo TARGET; kill -TERM $$"),
    ] {
        let label = format!("analyze --target-exit-code={code} /bin/sh -c {script:?}");
        let _guard = analyze_lock();
        let workspace = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("failed to create a workspace");
        let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
        command
            .args([
                "analyze",
                "--prefix-search",
                "--target-stdout=TARGET",
                "--run1-seed=1",
            ])
            .arg(format!("--target-exit-code={code}"))
            .arg(format!("--tmp-dir={}", workspace.path().display()))
            .args(["--", "--", "/bin/sh", "-c", script]);
        let output = hermit_test::hermit_output(&label, &mut command);
        let combined = combined_output(&output);
        assert!(
            combined.contains("First run matched target criteria"),
            "{label}: the target run did not match\n{combined}"
        );
    }
}

/// A target the scheduler meets without chaos at every timeslice (thread a
/// winning the race, which it does unless chaos or a tiny timeslice lets b
/// in): the prefix search concludes that no event decides the outcome, a
/// completed analysis that exits 0 with `HERMIT_ANALYZE_VERDICT
/// class=no-deciding-event` and a report whose verdict says so. Unlike
/// `analyze_explains_a_target_the_scheduler_meets_alone`, it needs no short
/// timeslice, so it does not depend on preemption repeating on the host.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_concludes_no_event_decides_a_target_met_without_chaos() {
    let label = "analyze --prefix-search analyze_race_then exit, target a-first";
    let guest = &workloads().race_then;
    let _guard = analyze_lock();
    let dir = tempfile::tempdir().expect("failed to create analyze report directory");
    let report_file = dir.path().join("report.json");
    let tmp_dir = tmp_dir_in(dir.path());
    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command
        .args(["analyze", "--prefix-search", "--target-stdout=a-first"])
        .args(["--target-exit-code=nonzero", "--run1-seed=0"])
        .arg(format!("--report-file={}", report_file.display()))
        .arg(format!("--tmp-dir={}", tmp_dir.display()))
        .args(["--", "--chaos", "--timeout=30", "--"])
        .arg(guest)
        .arg("exit");
    let output = hermit_test::hermit_output(label, &mut command);
    let combined = combined_output(&output);
    assert_eq!(output.status.code(), Some(0), "{label}\n{combined}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr
            .lines()
            .any(|line| line == "HERMIT_ANALYZE_VERDICT class=no-deciding-event")
            && !stderr.contains("HERMIT_INTERNAL_FAILURE"),
        "{label}\n{combined}"
    );
    let report: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&report_file)
            .unwrap_or_else(|error| panic!("{label}: no report: {error}\n{combined}")),
    )
    .unwrap();
    assert_eq!(report["verdict"], "no_deciding_event", "{label}: {report}");
    assert!(
        report["header"]
            .as_str()
            .is_some_and(|header| header.starts_with(
                "no event of the target schedule decides the outcome: without chaos, the scheduler \
             alone already meets the target criteria"
            )),
        "{label}: {report}"
    );
    assert!(report.get("critical_event1").is_none(), "{label}: {report}");
    assert_no_workspace_left(label, &tmp_dir, &combined);
}

/// An analysis that ends with an error removes its workspace too, and with
/// `--keep-tmp` keeps it: the target run here misses a target nothing prints,
/// and without `--search` analyze ends there.
#[test]
#[ignore = "slow: runs a chaos trial; requires PMU branch counters and working mount namespaces"]
fn analyze_removes_its_workspace_unless_kept() {
    for keep in [false, true] {
        let label = format!("analyze hello_race, target never met, keep: {keep}");
        let _guard = analyze_lock();
        let dir = tempfile::tempdir().expect("failed to create analyze directory");
        let tmp_dir = tmp_dir_in(dir.path());
        let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
        command
            .arg("analyze")
            .arg(format!("--tmp-dir={}", tmp_dir.display()))
            .args(["--run-arg=--base-env=host", "--target-stdout=never printed"]);
        if keep {
            command.arg("--keep-tmp");
        }
        command
            .args(["--", "--chaos", "--max-timeslice=400000", "--"])
            .arg(&workloads().hello_race);
        let output = hermit_test::hermit_output(&label, &mut command);
        let combined = combined_output(&output);
        assert!(
            !output.status.success()
                && combined.contains("The run did not match the target criteria"),
            "{label}: {}\n{combined}",
            output.status
        );
        assert_precondition(&label, &output, "target-not-reproduced");
        let left = left_in(&tmp_dir);
        if keep {
            assert!(
                left.len() == 1 && left[0].join("run1_target.repro").is_file(),
                "{label}: {left:?}\n{combined}"
            );
            assert!(
                combined.contains("Kept the workspace"),
                "{label}\n{combined}"
            );
        } else {
            assert_no_workspace_left(&label, &tmp_dir, &combined);
            assert!(
                combined.contains("Removed the workspace"),
                "{label}\n{combined}"
            );
        }
    }
}

/// Makes a container init wait before it arms its own stop handlers, under
/// the thread name [`ARMING_STALL_COMM`]; both are copied from
/// `stall_container_init_before_arming_if_asked` in `bin/hermit/container.rs`.
const ARMING_STALL_ENV: &str = "HERMIT_INTERNAL_STALL_CONTAINER_INIT_BEFORE_ARMING";
const ARMING_STALL_COMM: &str = "unarmed-init";

/// The children of process `parent`, by the parent field of each
/// `/proc/<pid>/stat`.
fn children_of(parent: u32) -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
                    == Some(parent)
            })
        })
        .collect()
}

/// Run `hermit analyze` over a target run that spins for ever, with `env`,
/// send SIGTERM to analyze alone once `ready` says so, and check that it ends
/// that run and the analysis: analyze removes its workspace and the run's own
/// temporary directories (its private /tmp, in TMPDIR), leaves no process,
/// and dies of the signal, as a shell reports with 143.
fn analyze_stopped_by_sigterm(label: &str, env: &[(&str, &str)], ready: impl Fn(u32) -> bool) {
    let _guard = analyze_lock();
    let dir = tempfile::tempdir().expect("failed to create analyze directory");
    let tmp_dir = tmp_dir_in(dir.path());
    let run_tmp = dir.path().join("TMPDIR");
    fs::create_dir(&run_tmp).unwrap();
    let stderr = dir.path().join("stderr");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    hermit_test::pin_canonical_epoch(&mut command);
    command
        .arg("analyze")
        .arg(format!("--tmp-dir={}", tmp_dir.display()))
        .args(["--", "--chaos", "--max-timeslice=400000", "--"])
        .args(["/bin/sh", "-c", "while :; do :; done"])
        .env("TMPDIR", &run_tmp)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(fs::File::create(&stderr).unwrap());
    let mut analyze = command.spawn().expect("failed to start hermit analyze");
    let said = || fs::read_to_string(&stderr).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(120);
    while !ready(analyze.id()) {
        assert!(
            analyze.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "{label}: analyze did not get as far as the signal\n{}",
            said()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let inits = children_of(analyze.id());
    // SAFETY: kill(2) on this test's own child.
    assert_eq!(
        unsafe { libc::kill(analyze.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = analyze.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = analyze.kill();
            let _ = analyze.wait();
            panic!("{label}: analyze did not stop\n{}", said());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let said = said();
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "{label}: {status}\n{said}"
    );
    assert!(
        said.contains("hermit analyze stopped on SIGTERM")
            && said.contains("Removed the workspace"),
        "{label}\n{said}"
    );
    assert_no_workspace_left(label, &tmp_dir, &said);
    let run_left = left_in(&run_tmp);
    assert!(
        run_left.is_empty(),
        "{label}: the run left {run_left:?} in TMPDIR\n{said}"
    );
    // Analyze reaped the run's container init before it exited.
    let survivors: Vec<_> = inits
        .iter()
        .filter(|init| Path::new(&format!("/proc/{init}")).exists())
        .collect();
    assert!(
        survivors.is_empty(),
        "{label}: the run's init {survivors:?} outlived analyze\n{said}"
    );
}

/// SIGTERM sent to analyze alone, 2 s into a target run that spins for ever,
/// ends that run and the analysis, and analyze cleans up. Before, the
/// workspace stayed behind whatever ended analyze, and a SIGTERM also left
/// the run's directories.
#[test]
#[ignore = "slow: runs a chaos trial; requires PMU branch counters and working mount namespaces"]
fn analyze_cleans_up_when_a_signal_stops_it() {
    let started = std::cell::Cell::new(None);
    analyze_stopped_by_sigterm("analyze of a guest that spins, SIGTERM", &[], |analyze| {
        // The target run's container init is analyze's only child.
        let at = started
            .get()
            .or((!children_of(analyze).is_empty()).then(Instant::now));
        started.set(at);
        at.is_some_and(|at| at.elapsed() >= Duration::from_secs(2))
    });
}

/// SIGTERM sent to analyze while its run's container init is held before
/// it arms its own stop handlers (Hermit's internal stall) reaches that init
/// all the same: the handler it inherited from analyze ends it as its own
/// would, and analyze cleans up.
#[test]
#[ignore = "slow: runs a chaos trial; requires PMU branch counters and working mount namespaces"]
fn analyze_stops_a_run_whose_init_has_not_armed() {
    analyze_stopped_by_sigterm(
        "analyze, SIGTERM before the run's init arms",
        &[(ARMING_STALL_ENV, "1")],
        |analyze| {
            children_of(analyze).iter().any(|init| {
                fs::read_to_string(format!("/proc/{init}/comm"))
                    .is_ok_and(|comm| comm.trim() == ARMING_STALL_COMM)
            })
        },
    );
}

/// `--trial-budget` ends a prefix search with a partial report and exit 120,
/// naming a bracket that holds the deciding event, and keeps the workspace
/// even without --keep-tmp. `--resume` with that workspace answers the runs
/// the first invocation journaled instead of running them, finishes the
/// search, and finds the deciding event an uninterrupted analysis finds.
#[test]
#[ignore = "slow: replays chaos schedules; requires PMU branch counters and working mount namespaces"]
fn a_budget_ends_analyze_with_a_partial_report_that_resume_finishes() {
    let label = "analyze --prefix-search --trial-budget=4 analyze_race_then exit";
    let (combined, uninterrupted) = analyze_race_then(label, "exit", &["--prefix-search"]);
    // The deciding event; a timing decision's critical events are positions
    // in its continuations instead.
    let decision = uninterrupted["deciding_event"]["event_index"]
        .as_u64()
        .or(uninterrupted["critical_event1"]["event_index"].as_u64())
        .unwrap_or_else(|| panic!("{label}: {uninterrupted}\n{combined}"));

    let seed = race_then_target_seed("exit", &[]);
    let _guard = analyze_lock();
    let report_dir = tempfile::tempdir().expect("failed to create analyze report directory");
    let report_file = report_dir.path().join("report.json");
    let tmp_dir = tmp_dir_in(report_dir.path());
    let analyze = |extra: &[String]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
        command
            .arg("analyze")
            .args([
                "--target-stdout=b-first",
                "--target-exit-code=0",
                "--trial-timeout=3",
                "--prefix-search",
            ])
            .args(extra)
            .arg(format!("--run1-seed={seed}"))
            .arg(format!("--report-file={}", report_file.display()))
            .arg(format!("--tmp-dir={}", tmp_dir.display()))
            .args(["--", "--chaos", "--"])
            .arg(&workloads().race_then)
            .arg("exit");
        let output = hermit_test::hermit_output(&format!("{command:?}"), &mut command);
        let report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&report_file).unwrap_or_else(|error| {
                panic!("{label}: no report ({error})\n{}", combined_output(&output))
            }))
            .unwrap();
        (output, report)
    };

    let (output, partial) = analyze(&["--trial-budget=4".to_owned()]);
    let said = combined_output(&output);
    assert_eq!(output.status.code(), Some(120), "{label}\n{said}");
    assert!(
        said.contains("HERMIT_ANALYZE_PARTIAL class=trial-budget phase=prefix-search"),
        "{label}: no class line\n{said}"
    );
    let details = &partial["partial"];
    assert_eq!(details["reason"], "trial-budget", "{partial}");
    assert_eq!(details["runs_started"], 4, "{partial}");
    let bracket = &details["bracket"];
    let (misses, meets) = (
        bracket["misses"].as_u64().unwrap(),
        bracket["meets"].as_u64().unwrap(),
    );
    assert!(
        misses <= decision && decision < meets,
        "{label}: event {decision} is not in the bracket {bracket}"
    );
    assert!(
        partial["header"]
            .as_str()
            .unwrap()
            .starts_with("PARTIAL RESULT."),
        "{partial}"
    );
    let workspace = PathBuf::from(details["workspace"].as_str().unwrap());
    assert!(
        workspace.join("analyze-journal.jsonl").is_file(),
        "{label}: the workspace was not kept\n{said}"
    );
    assert!(
        details["resume_command"]
            .as_str()
            .unwrap()
            .contains(&format!("--resume={}", workspace.display())),
        "{partial}"
    );

    let (output, resumed) = analyze(&[format!("--resume={}", workspace.display())]);
    let said = combined_output(&output);
    assert!(output.status.success(), "{label}: resume failed\n{said}");
    assert_eq!(
        said.matches("answered from the journal of an earlier invocation")
            .count(),
        4,
        "{label}\n{said}"
    );
    assert!(resumed.get("partial").is_none(), "{resumed}");
    for field in ["deciding_event", "critical_event1", "critical_event2"] {
        assert_eq!(
            resumed[field]["event_index"], uninterrupted[field]["event_index"],
            "{label}: the resumed analysis found another {field} than the uninterrupted one\n{said}"
        );
    }
    assert_no_workspace_left(label, &tmp_dir, &said);
}

/// An analyze run's `.repro` line reproduces its run from any directory
/// (https://github.com/rrnewton/hermit/issues/4812). The guest is named by a
/// path relative to analyze's working directory, so a reproducer that does
/// not start in that directory cannot even find its program. The test reads
/// the baseline run's reproducer, which analyze writes before its search, so
/// it does not depend on how the search ends.
#[test]
#[ignore = "slow: bisecting chaos schedules; requires PMU branch counters and working mount namespaces"]
fn analyze_reproducer_runs_from_another_directory() {
    let label = "analyze reproducer from another directory";
    let _guard = analyze_lock();
    let guest = &workloads().hello_race;
    let guest_dir = guest.parent().unwrap();
    let guest_name = Path::new(".").join(guest.file_name().unwrap());

    let mut command = Command::new(env!("CARGO_BIN_EXE_hermit"));
    command.current_dir(guest_dir).arg("analyze");
    add_calibrated_skid_margin(&mut command, label);
    command
        .args([
            "--analyze-seed=0",
            "--search",
            "--run-arg=--base-env=host",
            "--",
        ])
        .args(["--chaos", "--summary", "--max-timeslice=400000", "--"])
        .arg(&guest_name);
    let output = command.output().expect("failed to run hermit analyze");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let workspace = stderr
        .lines()
        .find_map(|line| line.strip_prefix(":: Temp workspace: "))
        .unwrap_or_else(|| panic!("{label}: no workspace in analyze's output\n{stderr}"));
    let repro = Path::new(workspace).join("run2_baseline.repro");
    let line = fs::read_to_string(&repro)
        .unwrap_or_else(|error| panic!("{label}: {}: {error}\n{stderr}", repro.display()));

    // The line names `hermit` as a command; run it with this build, from the
    // guest's directory and from another one, and compare the two runs.
    let bin_dir = Path::new(env!("CARGO_BIN_EXE_hermit")).parent().unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let elsewhere = tempfile::tempdir().unwrap();
    let run_from = |dir: &Path| {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(line.trim())
            .current_dir(dir)
            .env("PATH", &path);
        command.output().unwrap()
    };
    let here = run_from(guest_dir);
    let there = run_from(elsewhere.path());
    assert!(
        here.status.success(),
        "{label}: {} failed from the guest's directory\n{}",
        repro.display(),
        String::from_utf8_lossy(&here.stderr),
    );
    assert_eq!(
        (there.status.code(), &there.stdout),
        (here.status.code(), &here.stdout),
        "{label}: {} reproduced its run from the guest's directory but not from {}\n{}",
        repro.display(),
        elsewhere.path().display(),
        String::from_utf8_lossy(&there.stderr),
    );
}
