use std::hash::{Hash, Hasher};

use crate::simulation::faults::FaultType;

#[derive(Clone, Copy, Debug, PartialEq)]
/// Representation for a fault which shall be executed at step `index` of a simulation.
pub struct SimulationFaultRecord {
    pub index: usize,
    pub fault_type: FaultType,
}

#[derive(Clone, Debug, Eq)]
/// One recorded step of a simulation
pub enum TraceRecord {
    Instruction {
        address: u64,
        index: usize,
        asm_instruction: Vec<u8>,
        registers: Option<[u32; 17]>,
    },
    Fault {
        address: u64,
        fault_type: FaultType,
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
    pub fn address(&self) -> u64 {
        match self {
            TraceRecord::Instruction { address, .. } => *address,
            TraceRecord::Fault { address, .. } => *address,
        }
    }
}
