use super::{FaultRecord, TraceRecord};
use crate::simulation::cpu::Cpu;
use std::{fmt::Debug, sync::Arc};

pub mod bitflip;
pub mod glitch;
pub use bitflip::BitFlip;
pub use glitch::Glitch;

/// List of all possible faults
const FAULTS: [&dyn FaultFunctions; 2] = [&Glitch { number: 1 }, &BitFlip {}];

/// Trait for fault injection functions
pub trait FaultFunctions: Send + Sync + Debug {
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord);
    fn filter(&self, records: &mut Vec<TraceRecord>);
    fn try_from(&self, input: &str) -> Option<FaultType>;
    fn get_list(&self) -> Vec<&str>;
}

/// Type definition of fault injection data type
pub type FaultType = Arc<dyn FaultFunctions>;

/// Get the fault type from a string
pub fn get_fault_from(input: &str) -> Result<FaultType, String> {
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
