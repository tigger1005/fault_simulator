//! # Injection Point Filtering
//!
//! Restricts where the faults of a multi-fault sequence may be placed.
//!
//! ## Why this exists
//!
//! For a sequence of N faults the simulator places fault 1, re-traces the program,
//! and enumerates fault 2 over *that* trace. The cost of a campaign is therefore the
//! sum of the trace lengths behind every placement of the preceding fault, not the
//! length of the unfaulted program.
//!
//! Some faults derail the control flow instead of merely changing a value. A command
//! bit flip that hits bit 11 of the first halfword of a 32 bit Thumb-2 instruction,
//! for example, rewrites it into a 16 bit branch: the second halfword then decodes as
//! an instruction of its own, execution desynchronizes, and the core walks through
//! `.rodata` and unmapped memory until the instruction budget runs out. The resulting
//! trace is hundreds of times longer than the program, and nearly every record in it
//! is an address that holds data, not code.
//!
//! Enumerating fault 2 over those addresses costs the bulk of such a campaign while
//! describing something no attacker can target: a fault placed on a "instruction" that
//! only exists because the decoder lost sync.
//!
//! ## What is filtered
//!
//! Only injection points *outside every executable segment* of the image are dropped.
//! A derailed run that stays inside executable memory keeps all of its injection
//! points, so a second fault can still rescue a first one that crashed the program —
//! those are genuine multi-fault attacks and must not be lost.

use crate::elf_file::ElfFile;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Decides which injection points of a re-traced run are worth enumerating.
///
/// Shared by all fault attack worker threads, so all state is either immutable or
/// atomic.
#[derive(Debug, Default)]
pub struct InjectionFilter {
    /// Executable address ranges of the image, empty when filtering is off.
    executable_ranges: Vec<(u64, u64)>,
    /// Injection points dropped so far, for the campaign report.
    skipped: AtomicUsize,
}

impl InjectionFilter {
    /// Builds a filter from the executable segments of `file_data`.
    ///
    /// Filtering is disabled when `enabled` is false, and also when the image declares
    /// no executable segment at all — in that case every address would be filtered out
    /// and the campaign would silently test nothing.
    pub fn new(file_data: &ElfFile, enabled: bool) -> Self {
        let executable_ranges = if enabled {
            file_data.executable_ranges()
        } else {
            Vec::new()
        };
        if enabled && executable_ranges.is_empty() {
            log::warn!(
                "No executable segment found in the image, injection point filtering is disabled"
            );
        }
        Self {
            executable_ranges,
            skipped: AtomicUsize::new(0),
        }
    }

    /// A filter that keeps every injection point.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// True when injection points are actually being filtered.
    pub fn is_active(&self) -> bool {
        !self.executable_ranges.is_empty()
    }

    /// True when `address` lies in an executable segment of the image.
    fn is_executable(&self, address: u64) -> bool {
        self.executable_ranges
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    /// Drops injection points that lie outside the executable image.
    ///
    /// Does nothing when the filter is inactive, so callers can apply it
    /// unconditionally.
    pub fn retain_valid_injection_points(&self, records: &mut Vec<crate::simulation::TraceRecord>) {
        if !self.is_active() {
            return;
        }
        let before = records.len();
        records.retain(|record| self.is_executable(record.address()));
        self.skipped
            .fetch_add(before - records.len(), Ordering::Relaxed);
    }

    /// Number of injection points dropped so far.
    pub fn skipped(&self) -> usize {
        self.skipped.load(Ordering::Relaxed)
    }

    /// Clears the skip counter.
    pub fn reset(&self) {
        self.skipped.store(0, Ordering::Relaxed);
    }

    /// Human readable note for the campaign summary, or `None` when nothing was skipped.
    pub fn report(&self) -> Option<String> {
        let skipped = self.skipped();
        if skipped == 0 {
            return None;
        }
        Some(format!(
            "Skipped {skipped} injection points outside the executable image\n  \
             -> A preceding fault desynchronized the instruction decoder, so the program \
             walked through data. Use --no-injection-filter to enumerate them anyway."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulation::record::AsmInstruction;
    use crate::simulation::TraceRecord;

    fn filter_with(ranges: &[(u64, u64)]) -> InjectionFilter {
        InjectionFilter {
            executable_ranges: ranges.to_vec(),
            skipped: AtomicUsize::new(0),
        }
    }

    fn instruction(address: u64) -> TraceRecord {
        TraceRecord::Instruction {
            address,
            index: 0,
            asm_instruction: AsmInstruction::default(),
            registers: None,
        }
    }

    #[test]
    /// Addresses inside an executable segment survive, addresses behind its end do not.
    fn keeps_only_addresses_inside_executable_segments() {
        let filter = filter_with(&[(0x8000000, 0x8000700)]);
        let mut records = vec![
            instruction(0x8000000),
            instruction(0x80006FE),
            instruction(0x8000700),
            instruction(0x20000000),
        ];
        filter.retain_valid_injection_points(&mut records);

        assert_eq!(2, records.len());
        assert_eq!(0x8000000, records[0].address());
        assert_eq!(0x80006FE, records[1].address());
        assert_eq!(2, filter.skipped());
    }

    #[test]
    /// An image can have several executable segments, all of them are valid targets.
    fn keeps_addresses_of_every_executable_segment() {
        let filter = filter_with(&[(0x8000000, 0x8000100), (0x9000000, 0x9000100)]);
        let mut records = vec![
            instruction(0x8000010),
            instruction(0x9000010),
            instruction(0x8500000),
        ];
        filter.retain_valid_injection_points(&mut records);

        assert_eq!(2, records.len());
        assert_eq!(1, filter.skipped());
    }

    #[test]
    /// Without known executable ranges nothing may be dropped, otherwise a campaign
    /// would silently test nothing.
    fn inactive_filter_keeps_everything() {
        let filter = InjectionFilter::disabled();
        let mut records = vec![instruction(0x8000000), instruction(0x20000000)];
        filter.retain_valid_injection_points(&mut records);

        assert!(!filter.is_active());
        assert_eq!(2, records.len());
        assert_eq!(0, filter.skipped());
        assert_eq!(None, filter.report());
    }

    #[test]
    /// The skip counter accumulates over runs and is reported once something was dropped.
    fn report_appears_only_after_a_skip() {
        let filter = filter_with(&[(0x8000000, 0x8000700)]);
        assert_eq!(None, filter.report());

        let mut records = vec![instruction(0x20000000)];
        filter.retain_valid_injection_points(&mut records);
        let mut records = vec![instruction(0x20000004)];
        filter.retain_valid_injection_points(&mut records);

        assert_eq!(2, filter.skipped());
        assert!(filter
            .report()
            .unwrap()
            .contains("Skipped 2 injection points"));

        filter.reset();
        assert_eq!(0, filter.skipped());
    }
}
