use super::{FaultRecord, TraceRecord};
use crate::simulation::cpu::Cpu;
use std::{fmt::Debug, sync::Arc};

pub mod glitch;
pub use glitch::Glitch;

/// List of all possible faults
const FAULTS: [&dyn FaultFunctions; 1] = [&Glitch { number: 1 }];

/// Trait for fault injection functions
pub trait FaultFunctions: Send + Sync + Debug {
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord);
    fn filter(&self, records: &mut Vec<TraceRecord>);
    fn try_from(&self, input: &str) -> Option<FaultType>;
    fn get_list<'a>(&'a self) -> Vec<&'a str>;
}

/// Type definition of fault injection data type
pub type FaultType = Arc<dyn FaultFunctions>;

/// Get the fault type from a string
pub fn get_fault_type(input: &str) -> Result<FaultType, String> {
    // Parse the fault types
    let result = FAULTS.iter().find_map(|fault| fault.try_from(input));
    match result {
        Some(output) => Ok(output),
        None => Err(format!("Unknown fault type: {:?}", input)),
    }
}

/// Get lists of all suggested faults
pub fn get_fault_lists<'a>() -> Vec<Vec<&'a str>> {
    // Parse all fault types
    FAULTS.iter().map(|fault| fault.get_list()).collect()
}

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
