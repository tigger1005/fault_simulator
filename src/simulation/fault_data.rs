use crate::simulation::record::{FaultRecord, TraceRecord};

#[derive(Clone, Debug)]
/// Representation of an fault which was executed in a simulation.
pub struct FaultData {
    /// The original instructions which would have been performed without the fault.
    pub original_instructions: Vec<u8>,
    /// The recorded execution trace of this fault.
    pub record: TraceRecord,
    /// FaultRecord which caused this FaultData to be simulated.
    pub fault: FaultRecord,
}

impl FaultData {
    /// Generate out of a FaultData array a FaultRecord array
    pub fn get_simulation_fault_records(fault_data_records: &[FaultData]) -> Vec<FaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault.clone())
            .collect()
    }
}
