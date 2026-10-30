# aarch64 generic-timer reads

On aarch64 a guest can read the generic timer's virtual counter straight from
EL0 (`MRS Xt, CNTVCT_EL0`, and `CNTVCTSS_EL0` on cores with FEAT_ECV) and its
frequency (`MRS Xt, CNTFRQ_EL0`). Linux enables that access for every task and
has no per-process switch to turn it off: this is the architecture's `RDTSC`,
with no `PR_SET_TSC`. The read makes no stop a tracer sees, so before this
change host time reached guest control flow: a guest that branches on the
counter diverged between the two runs of `--verify`, and a recorded schedule
did not replay. Hermit's own scan finds such reads in real images, for example
in the ART runtime's method tracing and in a hash seed of the Android dynamic
linker.

## What Hermit does

Each such `MRS` is replaced, in place, by a permanently undefined instruction,
`UDF #imm16`, with `imm16 = 0xC700 | register << 5 | Rt` (register 0 =
`CNTVCT_EL0`, 1 = `CNTVCTSS_EL0`, 2 = `CNTFRQ_EL0`; `0xC760..0xC77F` reserved).
Executing it raises SIGILL at its own address. Detcore answers a SIGILL only at
an address this run registered as a trap whose word is still in memory: it
writes the value into `Rt` (nothing for `XZR`), steps the PC by 4, puts back
what forcing SIGILL changed, and suppresses the signal. Every other SIGILL
reaches the guest as before.

The answer is the one x86's trapped `RDTSC` gets (`handle_rdtsc_event`): an
instruction trap for the scheduler, one virtual-instruction charge, an `rdtsc`
event in a traced schedule, and the guest clock read before the event is
traced. `CNTVCT_EL0` and `CNTVCTSS_EL0` return that clock in nanoseconds, the
value `clock_gettime` returns, so successive reads strictly increase.
`CNTFRQ_EL0` returns 1 GHz, so a guest converting ticks to seconds gets
virtual seconds on every host. It must be virtualized: hosts report 1 GHz
(Neoverse V2), 62.5 MHz (older QEMU `virt`), 19.2 or 24 MHz (phones and
boards), and leaving it to the host would scale guest time by that ratio and
make guest-visible values host-dependent. A guest reads it about once, so it
costs one trap.

Where the replacement is written:

- In memory, on by default whenever time is virtual, threads are
  sequentialized and the backend is ptrace: as each executable file is mapped,
  Detcore writes the traps into the guest's private pages through
  `/proc/<pid>/mem`, beside `--rewrite-exclusives`' in-memory loop rewrite. A
  single instruction cannot be half-executed, so unlike a loop it is written
  in text that may already have run.
- In files: `--rewrite-exclusives` overlays (the main executable and
  `--rewrite-exclusives-also`) carry the traps too.
- `hermit rewrite-exclusives` reports them and writes them with
  `--output-dir` (`--no-counter-traps` leaves them).

`--no-virtualize-time` turns the traps off. The run summary lists the reads
answered by traps and the reads left to the host, per file.

## Options measured

Measured on a Neoverse V2 host (72 cores, Linux 6.16, 64 KiB pages):

| | per read |
| --- | --- |
| native `MRS CNTVCT_EL0` | 12.9 ns (19.3 ns after `ISB`) |
| (b) in-guest stub: branch out, load a page Detcore keeps, branch back | 0.6 ns, plus a `/proc/<pid>/mem` write of 0.39-0.48 us at each Detcore stop |
| (a) bare trap: SIGILL stop, register read and write, resume, in a 30-line tracer | 2.93 us (a `PTRACE_SYSCALL` syscall round trip: 4.27 us) |
| (a) under Hermit, ptrace backend, `--strict` | 48 us; a `clock_gettime` under the same Hermit: 52 us |

Both are deterministic. The stub was rejected: its value is frozen between
Detcore stops, so two reads around a computation can show no time passing and
a spin on the counter waits for the next preemption (coarser time than every
other clock Hermit gives); it needs a stub within 128 MB of each site, mapped
into the guest (a visible layout change) or added to the ELF as a new segment
in the overlay; and it adds a page write to every stop. Its speed only matters
for a program that reads the counter in a hot loop. The trap costs what a
`clock_gettime` costs under Hermit, adds no mapping, and changes nothing but
the one instruction.

## Soundness

- One instruction becomes one instruction of the same length, so no branch
  can enter it part-way and nothing moves. The trap changes `Rt` and the PC
  and nothing else; a harness that loads every register and the flags with
  patterns, executes each of the 64 forms (`CNTVCT_EL0` and `CNTFRQ_EL0` into
  `X0..X30` and `XZR`), and dumps them, gives identical output original
  against rewritten under `qemu-aarch64 -cpu max` and natively, except the
  destination, which holds the trap handler's value.
- `UDF` is permanently undefined, so the trap is taken on every core and in
  later architecture versions.
- Linux forces the SIGILL (`force_sig_info_to_task`): if the guest had it
  ignored or blocked, the kernel resets its action and unblocks it before the
  stop. Detcore writes the guest's action and mask back from its signal-state
  copy; with the copy unknown it warns once.
- Left as they are: `CNTVCTSS_EL0` on a host without FEAT_ECV (the original
  is undefined there and faults); a word a relocation covers; text in a
  writable segment; every read of an image whose code already holds a
  reserved immediate, so that a reserved immediate in a rewritten image is
  always a trap Hermit wrote; code outside executable file mappings (JIT).
- Residual: an image Hermit never rewrote whose executable sections contain a
  reserved immediate it executes gets a counter value instead of SIGILL. No
  compiler emits those immediates (GCC and LLVM trap with `BRK`, and use
  `UDF #0`).

## Limits

The in-memory rewrite writes only into a file it can prove is the mapped one:
through `/proc/<pid>/map_files` (which needs `CAP_CHECKPOINT_RESTORE`), or by
name on a filesystem whose device numbers identify files. On btrfs and
overlayfs without that capability the reads stay with the host, counted as not
written, with a warning (as for `--rewrite-exclusives-mode=memory`); the
overlay mode still covers the files it names there.
