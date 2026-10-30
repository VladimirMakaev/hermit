/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Trapping the guest's direct reads of the aarch64 generic timer.
//!
//! Linux lets every task read the virtual counter from EL0 (`MRS Xt,
//! CNTVCT_EL0`, and `CNTVCTSS_EL0` on cores with FEAT_ECV) and its frequency
//! (`MRS Xt, CNTFRQ_EL0`), with no stop a tracer sees: this architecture's
//! `RDTSC`, with no `PR_SET_TSC` to trap it. Each such instruction is
//! replaced, in place and at the same length, by a permanently undefined
//! instruction (`UDF #imm16`) whose immediate names the register and the
//! destination. Executing it raises SIGILL at its own address, where Detcore
//! writes its virtual value into the destination and steps past it (see
//! `Detcore::emulate_counter_trap`).
//!
//! A single instruction replaced by a single instruction needs none of the
//! exclusive-loop rewriter's reasoning about sequences: no branch can enter
//! it part-way, no register but the destination changes, and the flags,
//! memory and every other register are the original's. What the guest sees
//! differ is the value (Detcore's, not the host's) and nothing else.
//!
//! Left alone: `CNTVCTSS_EL0` on a host without FEAT_ECV, where the original
//! instruction is itself undefined and raises SIGILL (a guest that reads it
//! there must keep doing so); `CNTPCT_EL0`, `CNTPCTSS_EL0` and the timer
//! registers, whose EL0 access Linux disables, so a read already faults
//! visibly and deterministically; and every image that already holds one of
//! the reserved immediates in its code, so that each reserved immediate a
//! rewritten image holds is one this rewrite wrote.

/// A counter register the guest reads from EL0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CounterRegister {
    /// `CNTVCT_EL0`, the virtual count.
    Cntvct,
    /// `CNTVCTSS_EL0`, the self-synchronized virtual count (FEAT_ECV): the
    /// same value, read without a preceding `ISB`.
    Cntvctss,
    /// `CNTFRQ_EL0`, the count's frequency in Hz.
    Cntfrq,
}

impl CounterRegister {
    /// Every register, in immediate order.
    pub const ALL: [CounterRegister; 3] = [
        CounterRegister::Cntvct,
        CounterRegister::Cntvctss,
        CounterRegister::Cntfrq,
    ];

    /// The `MRS Xt, <register>` encoding with `Rt` = 0: `op0` 3, `op1` 3,
    /// `CRn` 14, `CRm` 0 and `op2` 2, 6 and 0 (Arm ARM DDI 0487 L.a, D24.11).
    pub const fn mrs_base(self) -> u32 {
        match self {
            CounterRegister::Cntvct => 0xD53B_E040,
            CounterRegister::Cntvctss => 0xD53B_E0C0,
            CounterRegister::Cntfrq => 0xD53B_E000,
        }
    }

    /// The register's architectural name.
    pub const fn name(self) -> &'static str {
        match self {
            CounterRegister::Cntvct => "CNTVCT_EL0",
            CounterRegister::Cntvctss => "CNTVCTSS_EL0",
            CounterRegister::Cntfrq => "CNTFRQ_EL0",
        }
    }

    const fn index(self) -> u32 {
        match self {
            CounterRegister::Cntvct => 0,
            CounterRegister::Cntvctss => 1,
            CounterRegister::Cntfrq => 2,
        }
    }
}

/// The frequency Detcore reports in `CNTFRQ_EL0`: one tick per virtual
/// nanosecond, so the count it reports is Hermit's virtual time in
/// nanoseconds, what x86 reports for `RDTSC`, and the same on every host.
pub const VIRTUAL_COUNTER_FREQUENCY: u64 = 1_000_000_000;

/// What a trapped read of `register` returns at virtual time `nanos` (in
/// nanoseconds): the time itself for the count, one tick per nanosecond, and
/// that frequency for `CNTFRQ_EL0`.
pub fn virtual_value(register: CounterRegister, nanos: u64) -> u64 {
    match register {
        CounterRegister::Cntvct | CounterRegister::Cntvctss => nanos,
        CounterRegister::Cntfrq => VIRTUAL_COUNTER_FREQUENCY,
    }
}

/// `Rt`, bits 4:0 of an `MRS`.
const RT_MASK: u32 = 0x1F;

/// The reserved `UDF` immediates are `0xC700 | register << 5 | Rt`, all of
/// `0xC700..=0xC77F` (the fourth register slot, `0xC760..=0xC77F`, is
/// reserved and never written). `UDF #imm16` is `0x0000_0000 | imm16`
/// (Arm ARM C6.2.387): permanently undefined, so it raises SIGILL at EL0 on
/// every core, now and in later architecture versions. No compiler emits
/// these immediates: GCC and LLVM use `BRK` for traps and `UDF #0` where they
/// emit `UDF` at all.
pub const TRAP_BASE: u32 = 0x0000_C700;

/// The bits a trap word shares with every other one.
const TRAP_MASK: u32 = !0x7F;

/// The register and destination of `MRS Xt, <counter register>`, or `None`
/// for any other instruction. `Rt` 31 is `XZR`: the read is discarded.
pub fn decode_read(word: u32) -> Option<(CounterRegister, u8)> {
    CounterRegister::ALL
        .into_iter()
        .find(|register| word & !RT_MASK == register.mrs_base())
        .map(|register| (register, (word & RT_MASK) as u8))
}

/// The `UDF` that replaces `MRS X<rt>, <register>`.
pub fn trap_word(register: CounterRegister, rt: u8) -> u32 {
    debug_assert!(rt <= 31);
    TRAP_BASE | register.index() << 5 | (u32::from(rt) & RT_MASK)
}

/// The register and destination a trap word stands for, or `None` for any
/// other word, the reserved fourth slot included.
pub fn decode_trap(word: u32) -> Option<(CounterRegister, u8)> {
    if word & TRAP_MASK != TRAP_BASE {
        return None;
    }
    let register = match (word >> 5) & 0x3 {
        0 => CounterRegister::Cntvct,
        1 => CounterRegister::Cntvctss,
        2 => CounterRegister::Cntfrq,
        _ => return None,
    };
    Some((register, (word & RT_MASK) as u8))
}

/// Whether `word` is one of the reserved immediates, whether or not it
/// decodes to a trap.
pub fn is_reserved(word: u32) -> bool {
    word & TRAP_MASK == TRAP_BASE
}

/// What the host executes, which decides what may be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterHost {
    /// FEAT_ECV (`HWCAP2_ECV`): `CNTVCTSS_EL0` is readable. Without it the
    /// original instruction is undefined, and stays so.
    pub self_synchronized: bool,
}

/// One counter read to replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterSite {
    /// Virtual address of the `MRS`.
    pub addr: u64,
    /// The register it reads.
    pub register: CounterRegister,
    /// Its destination; 31 is `XZR`.
    pub rt: u8,
    /// The replacement, [`trap_word`] of the two.
    pub word: u32,
}

/// Why a counter read is left as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CounterLeft {
    /// `CNTVCTSS_EL0` on a host without FEAT_ECV: the original is undefined.
    NoSelfSynchronizedCounter,
    /// The code already holds a reserved immediate, so a trap at one could
    /// not be told from the guest's own `UDF`.
    ReservedWordPresent,
    /// A relocation covers the word: the loader writes it.
    Relocated,
    /// The section is in a writable segment, which the program may rewrite.
    WritableText,
}

impl CounterLeft {
    /// A short name for reports.
    pub const fn name(self) -> &'static str {
        match self {
            CounterLeft::NoSelfSynchronizedCounter => "cntvctss-without-ecv",
            CounterLeft::ReservedWordPresent => "reserved-udf-present",
            CounterLeft::Relocated => "relocation-on-the-word",
            CounterLeft::WritableText => "writable-text",
        }
    }
}

/// What planning one run of instruction words found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CounterPlan {
    /// The reads to replace.
    pub sites: Vec<CounterSite>,
    /// The reads left, with the reason.
    pub left: Vec<(u64, CounterRegister, CounterLeft)>,
    /// Reserved immediates already in the words.
    pub reserved: usize,
}

impl CounterPlan {
    /// Every counter read in the words.
    pub fn reads(&self) -> usize {
        self.sites.len() + self.left.len()
    }
}

/// Plan the counter reads of `words`, the instructions at `base`. A range
/// that holds any reserved immediate keeps all of its reads (see
/// [`CounterLeft::ReservedWordPresent`]); the caller extends that to the
/// whole image.
pub fn plan(words: &[u32], base: u64, host: CounterHost) -> CounterPlan {
    let mut plan = CounterPlan {
        reserved: words.iter().filter(|word| is_reserved(**word)).count(),
        ..CounterPlan::default()
    };
    for (index, word) in words.iter().enumerate() {
        let Some((register, rt)) = decode_read(*word) else {
            continue;
        };
        let addr = base + 4 * index as u64;
        if plan.reserved != 0 {
            plan.left
                .push((addr, register, CounterLeft::ReservedWordPresent));
        } else if register == CounterRegister::Cntvctss && !host.self_synchronized {
            plan.left
                .push((addr, register, CounterLeft::NoSelfSynchronizedCounter));
        } else {
            plan.sites.push(CounterSite {
                addr,
                register,
                rt,
                word: trap_word(register, rt),
            });
        }
    }
    plan
}

/// Whether this host executes `CNTVCTSS_EL0` (FEAT_ECV, `HWCAP2_ECV`).
pub fn host() -> CounterHost {
    #[cfg(target_arch = "aarch64")]
    {
        // HWCAP2_ECV, Linux Documentation/arch/arm64/elf_hwcaps.rst and
        // arch/arm64/include/uapi/asm/hwcap.h.
        const HWCAP2_ECV: libc::c_ulong = 1 << 19;
        // SAFETY: getauxval reads the process's own auxiliary vector.
        let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
        CounterHost {
            self_synchronized: hwcap2 & HWCAP2_ECV != 0,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        CounterHost::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECV: CounterHost = CounterHost {
        self_synchronized: true,
    };

    // The assembler's encodings (llvm-mc --triple=aarch64 -mattr=+ecv
    // --show-encoding): mrs x0, cntvct_el0; mrs x17, cntvct_el0;
    // mrs xzr, cntvct_el0; mrs x3, cntvctss_el0; mrs x30, cntfrq_el0.
    const READS: &[(u32, CounterRegister, u8)] = &[
        (0xd53b_e040, CounterRegister::Cntvct, 0),
        (0xd53b_e051, CounterRegister::Cntvct, 17),
        (0xd53b_e05f, CounterRegister::Cntvct, 31),
        (0xd53b_e0c3, CounterRegister::Cntvctss, 3),
        (0xd53b_e01e, CounterRegister::Cntfrq, 30),
    ];

    /// Neighbours of the counter reads that must not be taken for them:
    /// mrs x0, cntpct_el0 (op2 1); mrs x0, cntpctss_el0 (op2 5);
    /// mrs x0, cntv_tval_el0 (CRm 3); msr cntv_tval_el0, x0 (L 0);
    /// mrs x0, cntkctl_el1 (op1 0); mrs x0, ctr_el0; udf #0.
    const OTHERS: &[u32] = &[
        0xd53b_e020,
        0xd53b_e0a0,
        0xd53b_e300,
        0xd51b_e300,
        0xd538_e100,
        0xd53b_0020,
        0x0000_0000,
    ];

    #[test]
    fn each_counter_read_decodes_with_its_destination() {
        for (word, register, rt) in READS {
            assert_eq!(decode_read(*word), Some((*register, *rt)), "{word:#010x}");
        }
        for word in OTHERS {
            assert_eq!(decode_read(*word), None, "{word:#010x}");
        }
    }

    #[test]
    fn every_trap_word_names_its_read_and_nothing_else_does() {
        let mut seen = std::collections::HashSet::new();
        for register in CounterRegister::ALL {
            for rt in 0..=31u8 {
                let word = trap_word(register, rt);
                // UDF #imm16: the top halfword is zero.
                assert_eq!(word >> 16, 0, "{word:#010x}");
                assert!(is_reserved(word));
                assert_eq!(decode_trap(word), Some((register, rt)), "{word:#010x}");
                assert!(seen.insert(word), "{word:#010x} is used twice");
                // The MRS it replaces decodes back to the same pair.
                assert_eq!(
                    decode_read(register.mrs_base() | u32::from(rt)),
                    Some((register, rt))
                );
            }
        }
        // The fourth slot is reserved but stands for no read.
        for word in [0x0000_c760, 0x0000_c77f] {
            assert!(is_reserved(word));
            assert_eq!(decode_trap(word), None, "{word:#010x}");
        }
        for word in [
            0x0000_0000,
            0x0000_c6ff,
            0x0000_c780,
            0x0001_c700,
            0xd53b_e040,
        ] {
            assert!(!is_reserved(word), "{word:#010x}");
            assert_eq!(decode_trap(word), None, "{word:#010x}");
        }
    }

    #[test]
    fn the_count_is_virtual_nanoseconds_at_one_gigahertz() {
        let at = 1_767_225_600_001_288_230;
        assert_eq!(virtual_value(CounterRegister::Cntvct, at), at);
        assert_eq!(virtual_value(CounterRegister::Cntvctss, at), at);
        assert_eq!(virtual_value(CounterRegister::Cntfrq, at), 1_000_000_000);
        // A guest converting ticks to seconds gets the virtual seconds.
        assert_eq!(
            virtual_value(CounterRegister::Cntvct, at) / virtual_value(CounterRegister::Cntfrq, at),
            at / 1_000_000_000
        );
    }

    #[test]
    fn a_plan_replaces_each_read_in_place() {
        // nop; mrs x9, cntvct_el0; isb; mrs x1, cntfrq_el0; mrs x2, cntvctss_el0; ret
        let words = [
            0xd503_201f,
            0xd53b_e049,
            0xd503_3fdf,
            0xd53b_e001,
            0xd53b_e0c2,
            0xd65f_03c0,
        ];
        let plan = plan(&words, 0x1000, ECV);
        assert_eq!(plan.left, vec![]);
        assert_eq!(plan.reserved, 0);
        assert_eq!(
            plan.sites,
            vec![
                CounterSite {
                    addr: 0x1004,
                    register: CounterRegister::Cntvct,
                    rt: 9,
                    word: 0x0000_c709,
                },
                CounterSite {
                    addr: 0x100c,
                    register: CounterRegister::Cntfrq,
                    rt: 1,
                    word: 0x0000_c741,
                },
                CounterSite {
                    addr: 0x1010,
                    register: CounterRegister::Cntvctss,
                    rt: 2,
                    word: 0x0000_c722,
                },
            ]
        );
    }

    #[test]
    fn a_self_synchronized_read_stays_where_the_host_lacks_it() {
        let words = [0xd53b_e0c2, 0xd53b_e042];
        let plan = plan(&words, 0, CounterHost::default());
        assert_eq!(
            plan.left,
            vec![(
                0,
                CounterRegister::Cntvctss,
                CounterLeft::NoSelfSynchronizedCounter
            )]
        );
        assert_eq!(plan.sites.len(), 1);
        assert_eq!(plan.sites[0].register, CounterRegister::Cntvct);
    }

    #[test]
    fn code_holding_a_reserved_immediate_keeps_every_read() {
        // mrs x0, cntvct_el0; udf #0xc705 (the code's own); mrs x1, cntfrq_el0
        let words = [0xd53b_e040, 0x0000_c705, 0xd53b_e001];
        let plan = plan(&words, 0, ECV);
        assert_eq!(plan.sites, vec![]);
        assert_eq!(plan.reserved, 1);
        assert_eq!(
            plan.left.iter().map(|(_, _, why)| *why).collect::<Vec<_>>(),
            vec![CounterLeft::ReservedWordPresent; 2]
        );
    }
}
