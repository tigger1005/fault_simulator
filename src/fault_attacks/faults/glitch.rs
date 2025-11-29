//! # Clock/Voltage Glitch Fault Injection
//!
//! This module implements clock and voltage glitching attacks that cause
//! the processor to skip instructions or execute incorrectly. Glitching
//! is one of the most common fault injection techniques used in practice.
//!
//! ## Attack Mechanism
//!
//! Glitch attacks work by:
//! * Temporarily disrupting the processor's clock signal
//! * Causing voltage fluctuations during instruction execution
//! * Forcing the CPU to skip or misexecute instructions
//! * Bypassing security checks and conditional branches
//!
//! ## Implementation
//!
//! The simulator models glitch effects by advancing the program counter
//! past one or more instructions, simulating the effect of instruction
//! skipping that commonly occurs during real glitch attacks.

use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::Cpu,
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    TraceElement,
};
use std::fmt::Debug;
use std::sync::Arc;

/// ARM Thumb-2 NOP instruction sequence for instruction padding.
///
/// Used to replace skipped instructions with NOPs to maintain
/// proper instruction alignment and prevent execution corruption.
const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

/// Clock/voltage glitch fault that causes instruction skipping.
///
/// This fault type simulates the effects of clock or voltage glitching
/// attacks by advancing the program counter past a specified number of
/// instructions. This models the most common outcome of real glitch
/// attacks where the processor skips over security checks or conditional
/// branches.
///
/// # Attack Effectiveness
///
/// Glitch attacks are particularly effective against:
/// * Conditional branches (if statements, loops)
/// * Security checks and validation routines
/// * Critical state machine transitions
/// * Authentication and authorization logic
///
/// # Parameters
///
/// * `number` - Number of instructions to skip (typically 1-10)
///
/// # Real-World Correlation
///
/// This simulation correlates with physical attacks where glitches
/// cause instruction fetch failures, pipeline stalls, or decode errors
/// that result in effective instruction skipping.
#[derive(Clone, Copy)]
pub struct Glitch {
    /// Number of instructions to skip when the glitch is applied.
    ///
    /// Common values:
    /// * 1: Skip single instruction (most common)
    /// * 2-3: Skip short instruction sequences
    /// * 4+: Skip larger code blocks (less realistic)
    pub number: usize,
}

impl Debug for Glitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Glitch (glitch_{})", self.number)
    }
}

/// Implementation for Glitch fault
impl Glitch {
    /// Creates a new glitch fault instance with specified instruction skip count.
    ///
    /// The instruction skip count determines how many instructions will be
    /// bypassed when the glitch is applied. Higher counts simulate more
    /// severe glitch effects but may be less realistic for actual attacks.
    ///
    /// # Arguments
    ///
    /// * `number` - Number of instructions to skip (1-10 recommended for realism)
    ///
    /// # Returns
    ///
    /// Thread-safe Arc reference to the glitch fault instance, suitable
    /// for use in multi-threaded fault injection campaigns.
    ///
    /// # Typical Usage
    ///
    /// ```rust,no_run
    /// let single_skip = Glitch::new(1);  // Most common glitch effect
    /// let double_skip = Glitch::new(2);  // More severe glitch
    /// ```
    pub fn new(number: usize) -> Arc<Self> {
        Arc::new(Self { number })
    }
}

impl FaultFunctions for Glitch {
    /// Execute a glitch skipping `n` instructions.
    ///
    /// This method advances the program counter by the number of instructions specified in the fault.
    /// It records the original and modified instructions, as well as the fault details, for analysis.
    ///
    /// # Arguments
    ///
    /// * `cpu` - The CPU instance where the fault is injected.
    /// * `fault` - The fault record containing details of the fault.
    ///
    /// # Returns
    ///
    /// * `bool` - Always returns `false` as no cleanup is required after the fault injection.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        let address = cpu.get_program_counter();
        let mut offset = 0;
        let mut modified_instructions = Vec::new();

        for _count in 0..self.number {
            let instruction_size = cpu.get_asm_cmd_size(address + offset).unwrap();
            modified_instructions.extend_from_slice(&T1_NOP[..instruction_size]);
            offset += instruction_size as u64;
        }
        cpu.set_program_counter(address + offset);

        // Set to same size as data
        let mut original_instructions = modified_instructions.clone();
        // Read original instructions
        cpu.memory_read(address, &mut original_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!("Glitch ({} assembler instruction)", self.number,),
            data: original_instructions.clone(),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instruction: original_instructions,
            modified_instruction: modified_instructions,
            record,
            fault: fault.clone(),
        });

        // No cleanup required
        false
    }

    /// Filtering of traces to reduce the number of traces to analyze.
    ///
    /// # Arguments
    ///
    /// * `records` - The trace records to filter.
    /// * `cs` - The disassembly context.
    fn filter(&self, _records: &mut TraceElement, _cs: &Disassembly) {}

    /// Try to parse a Glitch fault from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string.
    ///
    /// # Returns
    ///
    /// * `Option<FaultType>` - Returns the fault type if successful, otherwise `None`.
    fn try_from(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute = collect.get(1).copied()?;
        // check if fault type is glitch
        if fault_type == "glitch" {
            // check if attribute is a number
            if let Ok(num) = attribute.parse::<usize>() {
                // return Glitch struct
                return Some(Self::new(num));
            }
        }
        None
    }

    /// Get the list of possible/good faults.
    ///
    /// # Returns
    ///
    /// * `Vec<String>` - Returns a vector of fault names.
    fn get_list(&self) -> Vec<String> {
        let list: Vec<String> = (1..=8).map(|index| format!("glitch_{}", index)).collect();
        list
    }
}
