use super::{FaultRecord, TraceRecord};
use crate::{disassembly::Disassembly, simulation::cpu::Cpu};
use std::{fmt::Debug, slice::Iter, sync::Arc};

pub mod cmd_bitflip;
pub mod glitch;
pub mod register_bitflip;
pub mod register_flood;

pub use cmd_bitflip::CmdBitFlip;
pub use glitch::Glitch;
use itertools::Itertools;
pub use register_bitflip::RegisterBitFlip;
pub use register_flood::RegisterFlood;

use unicorn_engine::RegisterARM;

/// List of all possible faults
const FAULTS: [&dyn FaultFunctions; 3] = [
    &Glitch { number: 1 },
    &RegisterBitFlip {
        register: RegisterARM::R0,
        xor_value: 0x01,
    },
    &RegisterFlood {
        register: RegisterARM::R0,
        value: 0x00,
    },
    //    &CmdBitFlip { xor_value: 0x01 },
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
pub fn get_fault_lists(groups: &mut Iter<String>) -> Vec<Vec<String>> {
    let fault_types: String = groups.join(" ");
    if !fault_types.is_empty() {
        // Parse all fault types
        FAULTS
            .iter()
            .filter(|fault| {
                // Get the first item of the list, get the attack name and check if it is in the list
                let list = fault.get_list();
                let item = list[0].split('_').collect::<Vec<&str>>();
                fault_types.contains(item[0])
            })
            .map(|fault| fault.get_list())
            .collect()
    } else {
        // Parse all fault types
        FAULTS.iter().map(|fault| fault.get_list()).collect()
    }
}
