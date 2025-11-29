//! # Fault Injection Data Structures
//!
//! This module provides data structures for representing successful fault
//! injection results. It captures the complete context of a fault injection
//! including the original vs. modified execution and the execution trace.

use crate::simulation::record::{FaultRecord, TraceRecord};

/// Complete record of a successful fault injection during simulation.
///
/// This structure represents the outcome of a fault injection that resulted
/// in a successful attack (reached success criteria). It captures both the
/// intended fault specification and the actual execution results, enabling
/// detailed analysis of fault injection effectiveness.
///
/// # Fault Injection Context
///
/// * **Original State**: What would have executed without the fault
/// * **Modified State**: What actually executed due to the fault injection
/// * **Execution Trace**: Complete record of the execution with fault applied
/// * **Fault Specification**: The original fault injection parameters
///
/// # Analysis Applications
///
/// * **Impact Assessment**: Compare original vs. modified instruction effects
/// * **Pattern Recognition**: Identify common successful fault characteristics
/// * **Reproducibility**: Replay successful attacks for further analysis
/// * **Report Generation**: Document successful attack vectors
#[derive(Clone, Debug)]
pub struct FaultData {
    /// Original instruction bytes that would have executed without fault injection.
    ///
    /// Represents the intended program behavior, serving as a baseline
    /// for understanding the fault's impact on execution.
    pub original_instruction: Vec<u8>,
    /// Modified instruction bytes that actually executed due to fault injection.
    ///
    /// May be identical to original_instruction for faults that don't modify
    /// the instruction stream directly (e.g., register modifications).
    pub modified_instruction: Vec<u8>,
    /// Complete execution trace record capturing the fault injection event.
    ///
    /// Contains detailed information about where and how the fault manifested
    /// during program execution, including timing and state information.
    pub record: TraceRecord,
    /// Original fault specification that led to this successful injection.
    ///
    /// Links the successful result back to the fault injection parameters,
    /// enabling reconstruction of the attack conditions.
    pub fault: FaultRecord,
}

impl FaultData {
    /// Creates a new FaultData instance representing a successful fault injection.
    ///
    /// This constructor assembles the complete context of a successful fault
    /// injection, linking the intended fault specification with the actual
    /// execution results for comprehensive analysis.
    ///
    /// # Arguments
    ///
    /// * `original_instruction` - Instruction bytes that would have executed normally
    /// * `modified_instruction` - Actual instruction bytes executed due to fault
    /// * `record` - Execution trace record capturing the fault injection event
    /// * `fault` - Original fault specification that caused this result
    ///
    /// # Returns
    ///
    /// A FaultData instance containing the complete fault injection context,
    /// suitable for analysis, reporting, and potential replay operations.
    ///
    /// # Usage
    ///
    /// Typically called by the simulation engine when a fault injection
    /// results in reaching the success criteria, to document the successful
    /// attack vector for later analysis.
    pub fn new(
        original_instruction: Vec<u8>,
        modified_instruction: Vec<u8>,
        record: TraceRecord,
        fault: FaultRecord,
    ) -> Self {
        Self {
            original_instruction,
            modified_instruction,
            record,
            fault,
        }
    }

    /// Returns the simulation fault records for the given fault data.
    ///
    /// # Arguments
    ///
    /// * `fault_data` - A slice of fault data.
    ///
    /// # Returns
    ///
    /// * `Vec<FaultRecord>` - Returns a vector of fault records.
    pub fn get_simulation_fault_records(fault_data: &[FaultData]) -> Vec<FaultRecord> {
        fault_data.iter().map(|data| data.fault.clone()).collect()
    }
}
