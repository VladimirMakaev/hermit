# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""GDB's own breakpoints against the timer of `hermit run --strict --gdbserver`.

For as long as it is attached, gdb keeps breakpoints of its own in the dynamic
loader (its shared-library event breakpoint, or the loader's probes), so a
session that stops at nothing still stops the guest there at every library
load and unload. Under `--strict`, Hermit ends each timeslice at an exact
retired-branch count, with a precise timer event. When the guest reached one
of gdb's breakpoints while such an event was scheduled or being stepped to its
target, the breakpoint ended the event: the guest ran past the target, Hermit
reported a skid overshoot (HERMIT_SKID_OVERSHOOT) and refused the strict run,
although the same run without gdb is clean. A failing strict seed could be
inspected under gdb, but the session could not stand for the strict run.

The test runs guests/dlopen_threads.c, whose two threads each load and unload
a library ten times, with small timeslices, so that timer events are often
near gdb's breakpoints. A session that only continues must give the strict
run's own result: no refusal, and the exit status and output of the run
without gdb. The output prints the order of the two threads' loads, so it
also shows that the threads were scheduled as without gdb.
"""

import subprocess
import unittest

from harness import (
    compile_guest,
    DebuggerTestBase,
    exact_branch_counter,
    gdb_batch,
    GUESTS_DIR,
    HermitGdbserver,
    pick_free_port,
)

# Small timeslices put a timer event near many of gdb's breakpoints; chaos
# scheduling makes the order of the threads' loads depend on where they end.
STRICT_SMALL_TIMESLICES = [
    "--strict",
    "--base-env=minimal",
    "--epoch=2026-01-01T00:00:00Z",
    "--chaos",
    "--seed=1",
    "--max-timeslice=1000",
]
# A session that stops at nothing; a loaded host can answer slower than gdb's
# default 2 s.
CONTINUE_ONLY = [
    "set remotetimeout 30",
    "handle all nostop noprint pass",
]
# How long a run, or the gdb session, may take.
RUN_TIMEOUT = 300


class GdbStrictTimer(DebuggerTestBase):
    require_gdb = True

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        present, evidence = exact_branch_counter(cls.hermit)
        if not present:
            raise unittest.SkipTest(
                "hermit run --strict refuses on this host (no exact retired-branch "
                "counter): " + evidence
            )
        try:
            cls.dlopen_threads = compile_guest(
                GUESTS_DIR / "dlopen_threads.c", "dlopen_threads", ["-pthread"]
            )
        except Exception as e:  # noqa: BLE001
            raise unittest.SkipTest(f"could not compile dlopen_threads guest ({e})")

    def _run(self, run_args):
        """The run without gdb: (status, stdout, stderr)."""
        r = subprocess.run(
            [str(self.hermit), "run", *run_args, "--", str(self.dlopen_threads)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            timeout=RUN_TIMEOUT,
        )
        return (
            r.returncode,
            r.stdout.decode(errors="replace"),
            r.stderr.decode(errors="replace"),
        )

    def _continue_only(self, run_args):
        """The run under a gdb session that stops at nothing and only
        continues: (gdb output, status, stdout, hermit stderr)."""
        port = pick_free_port()
        with HermitGdbserver(
            self.hermit,
            self.dlopen_threads,
            port,
            run_args=run_args,
            separate_stdout=True,
        ) as srv:
            out = gdb_batch(
                self.dlopen_threads,
                CONTINUE_ONLY
                + [
                    f"target remote 127.0.0.1:{port}",
                    # gdb's own breakpoints, listed before the guest runs.
                    "maint info breakpoints",
                    "continue",
                ],
                timeout=RUN_TIMEOUT,
            )
            status = srv.wait(RUN_TIMEOUT)
            return out, status, srv.stdout.read_text(), srv.read_log()

    def test_gdbs_own_breakpoints_leave_a_strict_run_as_without_gdb(self):
        status, stdout, stderr = self._run(STRICT_SMALL_TIMESLICES)
        self.assertEqual(status, 0, stderr)
        self.assertNotIn("HERMIT_SKID_OVERSHOOT", stderr)

        out, gdb_status, gdb_stdout, log = self._continue_only(STRICT_SMALL_TIMESLICES)
        msg = f"gdb:\n{out}\nhermit:\n{log}"
        self.assertIn("shlib events", out, msg)
        self.assertIn("exited normally", out, msg)
        self.assertNotIn("HERMIT_SKID_OVERSHOOT", log, msg)
        self.assertNotIn("HERMIT_POLICY_REFUSAL", log, msg)
        self.assertEqual((gdb_status, gdb_stdout), (status, stdout), msg)


if __name__ == "__main__":
    unittest.main()
