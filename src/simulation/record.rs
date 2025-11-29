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
        asm_instruction: Vec<u8>,
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
