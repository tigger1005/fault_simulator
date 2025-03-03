use crate::simulation::record::{FaultRecord, TraceRecord};

/// Struct representing fault data.
#[derive(Clone, Debug)]
/// Representation of an fault which was executed in a simulation.
pub struct FaultData {
    /// The original instructions which would have been performed without the fault.
    pub original_instruction: Vec<u8>,
    /// The modified instructions if it was changed which is performed with the fault.
    pub modified_instruction: Vec<u8>,
    /// The recorded execution trace of this fault.
    pub record: TraceRecord,
    /// FaultRecord which caused this FaultData to be simulated.
    pub fault: FaultRecord,
}

impl FaultData {
    /// Creates a new `FaultData` instance.
    ///
    /// # Arguments
    ///
    /// * `original_instruction` - The original instruction bytes.
    /// * `modified_instruction` - The modified instruction bytes.
    /// * `record` - The trace record.
    /// * `fault` - The fault record.
    ///
    /// # Returns
    ///
    /// * `Self` - Returns a `FaultData` instance.
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
