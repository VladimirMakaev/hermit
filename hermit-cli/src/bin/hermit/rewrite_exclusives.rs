/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `hermit rewrite-exclusives`: report, and optionally write, the LSE rewrite
//! of an aarch64 ELF file's exclusive retry loops, and the traps that replace
//! its EL0 generic-timer reads.
//!
//! The same code `hermit run --rewrite-exclusives` uses, exposed on its own so
//! a binary can be inspected before anyone runs it: which loops the rewriter
//! recognises, which it leaves alone and why.

use std::path::PathBuf;

use clap::Parser;
use hermit::Error;
use hermit::ExitStatus;
use hermit::aarch64_lse::elf;

#[derive(Debug, Parser)]
pub struct RewriteExclusivesOpts {
    /// ELF files to inspect.
    #[clap(value_name = "FILE", required = true)]
    files: Vec<PathBuf>,

    /// Write each rewritten file into this directory, under its own name,
    /// instead of only reporting what the rewrite would do.
    #[clap(long, value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// List every loop left alone, not just the first few per file.
    #[clap(long)]
    list_refusals: bool,

    /// Leave the EL0 generic-timer reads (`MRS` of `CNTVCT_EL0`,
    /// `CNTVCTSS_EL0`, `CNTFRQ_EL0`) as they are. By default each becomes the
    /// trap a `hermit run` with virtual time answers, as on this host
    /// (`CNTVCTSS_EL0` only where it has FEAT_ECV).
    #[clap(long)]
    no_counter_traps: bool,
}

impl RewriteExclusivesOpts {
    pub fn main(&self) -> Result<ExitStatus, Error> {
        if let Some(dir) = &self.output_dir {
            let mut names = std::collections::HashSet::new();
            for file in &self.files {
                let name = file
                    .file_name()
                    .ok_or_else(|| Error::msg(format!("{} has no file name", file.display())))?;
                anyhow::ensure!(
                    names.insert(name.to_owned()),
                    "two inputs are named {}, so one would overwrite the other in {}",
                    name.to_string_lossy(),
                    dir.display()
                );
            }
            std::fs::create_dir_all(dir)?;
        }
        let mut incomplete = false;
        let options = elf::PlanOptions {
            loops: true,
            counters: (!self.no_counter_traps).then(hermit::aarch64_lse::counter::host),
        };
        for file in &self.files {
            let report = match &self.output_dir {
                Some(dir) => {
                    let name = file.file_name().ok_or_else(|| {
                        Error::msg(format!("{} has no file name", file.display()))
                    })?;
                    elf::rewrite_file(file, dir.join(name), options)?
                }
                None => elf::rewrite_bytes_with(&mut std::fs::read(file)?, options)?,
            };
            let Some(report) = report else {
                println!("{}: not an aarch64 ELF image", file.display());
                incomplete = true;
                continue;
            };
            println!(
                "{}: exclusive_instructions={} rewritten={} left_alone={}",
                file.display(),
                report.exclusive_instructions,
                report.patched_total(),
                report.refused_total(),
            );
            for (idiom, count) in &report.patched {
                println!("  rewritten {idiom}: {count}");
            }
            for (reason, count) in &report.refused {
                println!("  left alone {reason}: {count}");
            }
            for segment in &report.skipped_segments {
                println!("  skipped {segment}");
            }
            if report.counter_reads != 0 {
                println!(
                    "  counter_reads={} trapped={} left={}",
                    report.counter_reads,
                    report.counter_patched_total(),
                    report.counter_left.values().sum::<usize>()
                );
                for (register, count) in &report.counter_patched {
                    println!("  trapped {register}: {count}");
                }
                for (reason, count) in &report.counter_left {
                    println!("  counter read left {reason}: {count}");
                }
            }
            if self.list_refusals {
                for (addr, why) in &report.refused_examples {
                    println!("  at {addr:#x}: {why}");
                }
            }
            incomplete |= !report.complete();
        }
        // A nonzero status says a file still holds a loop the rewriter
        // refused, or a section it did not read, so a build check can ask for
        // the property directly instead of parsing the report.
        Ok(ExitStatus::Exited(if incomplete { 1 } else { 0 }))
    }
}
