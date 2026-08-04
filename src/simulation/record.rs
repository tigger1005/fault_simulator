//! # Simulation Recording and Trace Analysis
//!
//! This module provides data structures for recording and analyzing program
//! execution during fault injection simulation. It captures both the intended
//! fault injections and the actual execution trace for comprehensive analysis.
//!
//! ## Key Concepts
//!
//! * **FaultRecord**: Specifies when and how a fault should be injected
//! * **TraceRecord**: Captures actual execution events (instructions, faults)
//! * **Execution Tracking**: Links fault specifications to execution outcomes

use crate::fault_attacks::faults::FaultType;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

/// Raw bytes of a single ARM Thumb/Thumb-2 instruction, stored inline.
///
/// Instructions are at most four bytes wide, so keeping them inline avoids one
/// heap allocation per recorded instruction. Traces routinely contain hundreds of
/// thousands of records, which makes this the difference between a `memcpy` and a
/// `malloc`/`free` pair per record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AsmInstruction {
    bytes: [u8; 4],
    len: u8,
}

impl AsmInstruction {
    /// Maximum encoded width of an ARM Thumb-2 instruction.
    pub const MAX_LEN: usize = 4;

    /// Creates an instruction buffer from raw bytes, truncating beyond `MAX_LEN`.
    pub fn new(bytes: &[u8]) -> Self {
        let len = bytes.len().min(Self::MAX_LEN);
        let mut buffer = [0u8; Self::MAX_LEN];
        buffer[..len].copy_from_slice(&bytes[..len]);
        Self {
            bytes: buffer,
            len: len as u8,
        }
    }

    /// Creates a zeroed buffer of `len` bytes, ready to be filled in place.
    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: [0u8; Self::MAX_LEN],
            len: len.min(Self::MAX_LEN) as u8,
        }
    }

    /// Mutable view of the used part of the buffer.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len as usize]
    }
}

impl Deref for AsmInstruction {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl From<&[u8]> for AsmInstruction {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

/// Specification for a fault injection to be executed at a specific simulation step.
///
/// This structure defines a planned fault injection, specifying both the timing
/// (execution step index) and the type of fault to inject. It serves as input
/// to the simulation engine to control when and how faults are applied.
///
/// # Usage in Simulation
///
/// FaultRecords are processed in order during simulation execution:
/// 1. Simulation runs until the specified step index
/// 2. The fault_type is applied to modify execution
/// 3. Simulation continues with the injected fault active
///
/// # Fields
///
/// * `index` - Execution step at which to inject the fault (0-based)
/// * `fault_type` - Type and parameters of the fault to inject
#[derive(Clone, Debug)]
pub struct FaultRecord {
    /// Zero-based execution step index when this fault should be injected.
    pub index: usize,
    /// Type of fault to inject (glitch, register modification, etc.).
    pub fault_type: FaultType,
}

/// Records actual execution events during simulation for analysis and replay.
///
/// This enum captures different types of events that occur during program
/// execution, providing a complete trace for fault injection analysis.
/// Each record type contains relevant information for understanding
/// the program's behavior and the impact of fault injections.
///
/// # Record Types
///
/// * **Instruction**: Normal program instruction execution
/// * **Fault**: Fault injection event and its effects
///
/// # Analysis Usage
///
/// TraceRecords enable:
/// * Fault impact analysis by comparing before/after states
/// * Execution flow reconstruction for debugging
/// * Statistical analysis of fault injection effectiveness
#[derive(Clone, Debug, Eq)]
pub enum TraceRecord {
    /// Record of a normal instruction execution.
    ///
    /// Captures the execution of a single program instruction including
    /// its location, timing, and optionally the full processor state.
    Instruction {
        /// Memory address where the instruction is located.
        address: u64,
        /// Execution step index (0-based) when this instruction was executed.
        index: usize,
        /// Raw instruction bytes as they appear in memory.
        asm_instruction: AsmInstruction,
        /// Complete processor register state (R0-R15, plus CPSR) if captured.
        registers: Option<[u32; 17]>,
    },
    /// Record of a fault injection event.
    ///
    /// Documents when and how a fault was injected during execution,
    /// including the fault's effects on the program state.
    Fault {
        /// Memory address where the fault injection occurred.
        address: u64,
        /// Human-readable description of the fault type and parameters.
        fault_type: String,
        /// Additional fault-specific data (modified bytes, register values, etc.).
        data: Vec<u8>,
    },
}

impl PartialEq for TraceRecord {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                TraceRecord::Instruction {
                    address: address1,
                    index: _,
                    asm_instruction: _,
                    registers: _,
                },
                TraceRecord::Instruction {
                    address: address2,
                    index: _,
                    asm_instruction: _,
                    registers: _,
                },
            ) => address1 == address2,
            _ => false,
        }
    }
}

impl Hash for TraceRecord {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        if let TraceRecord::Instruction { address, .. } = self {
            address.hash(hasher);
        }
    }
}

impl TraceRecord {
    /// Extracts the memory address associated with this trace record.
    ///
    /// This method provides a uniform way to access the memory address
    /// for any type of trace record, which is useful for address-based
    /// analysis and correlation of execution events.
    ///
    /// # Returns
    ///
    /// The memory address where this trace event occurred, regardless
    /// of whether it's an instruction execution or fault injection.
    pub fn address(&self) -> u64 {
        match self {
            TraceRecord::Instruction { address, .. } => *address,
            TraceRecord::Fault { address, .. } => *address,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn instruction_records_equal_by_address() {
        let rec1 = TraceRecord::Instruction {
            address: 0x1000,
            index: 0,
            asm_instruction: AsmInstruction::new(&[0x00, 0xBF]),
            registers: None,
        };
        let rec2 = TraceRecord::Instruction {
            address: 0x1000,
            index: 5,
            asm_instruction: AsmInstruction::new(&[0xFF]),
            registers: Some([0; 17]),
        };
        assert_eq!(rec1, rec2);
    }

    #[test]
    fn instruction_records_not_equal_different_address() {
        let rec1 = TraceRecord::Instruction {
            address: 0x1000,
            index: 0,
            asm_instruction: AsmInstruction::default(),
            registers: None,
        };
        let rec2 = TraceRecord::Instruction {
            address: 0x2000,
            index: 0,
            asm_instruction: AsmInstruction::default(),
            registers: None,
        };
        assert_ne!(rec1, rec2);
    }

    #[test]
    fn fault_records_not_equal() {
        let rec1 = TraceRecord::Fault {
            address: 0x1000,
            fault_type: "glitch".to_string(),
            data: vec![],
        };
        let rec2 = TraceRecord::Instruction {
            address: 0x1000,
            index: 0,
            asm_instruction: AsmInstruction::default(),
            registers: None,
        };
        // Fault and Instruction are never equal
        assert_ne!(rec1, rec2);
    }

    #[test]
    fn hash_deduplicates_by_address() {
        let rec1 = TraceRecord::Instruction {
            address: 0x1000,
            index: 0,
            asm_instruction: AsmInstruction::new(&[0x00]),
            registers: None,
        };
        let rec2 = TraceRecord::Instruction {
            address: 0x1000,
            index: 1,
            asm_instruction: AsmInstruction::new(&[0xFF]),
            registers: None,
        };
        let mut set = HashSet::new();
        set.insert(rec1);
        set.insert(rec2);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn address_method_instruction() {
        let rec = TraceRecord::Instruction {
            address: 0xABCD,
            index: 0,
            asm_instruction: AsmInstruction::default(),
            registers: None,
        };
        assert_eq!(rec.address(), 0xABCD);
    }

    #[test]
    fn address_method_fault() {
        let rec = TraceRecord::Fault {
            address: 0x1234,
            fault_type: "test".to_string(),
            data: vec![],
        };
        assert_eq!(rec.address(), 0x1234);
    }
}
