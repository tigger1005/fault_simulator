use super::{FaultRecord, TraceRecord};
use crate::{disassembly::Disassembly, simulation::cpu::Cpu};
use std::{fmt::Debug, sync::Arc};

pub mod glitch;
pub mod register_bitflip;

pub use glitch::Glitch;
pub use register_bitflip::RegisterBitFlip;
use unicorn_engine::RegisterARM;

/// List of all possible faults
const FAULTS: [&dyn FaultFunctions; 2] = [
    &Glitch { number: 1 },
    &RegisterBitFlip {
        register: RegisterARM::R0,
        xor_value: 0x01,
    },
];

/// Trait for fault injection functions
pub trait FaultFunctions: Send + Sync + Debug {
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord);
    fn filter(&self, records: &mut Vec<TraceRecord>, cs: &Disassembly);
    fn try_from(&self, input: &str) -> Option<FaultType>;
    fn get_list(&self) -> Vec<String>;
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
pub fn get_fault_lists() -> Vec<Vec<String>> {
    // Parse all fault types
    FAULTS.iter().map(|fault| fault.get_list()).collect()
}
