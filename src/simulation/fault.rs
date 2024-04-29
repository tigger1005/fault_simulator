use clap::{builder::PossibleValue, ValueEnum};
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
/// Types of faults which can be simulated.
pub enum FaultType {
    /// A fault which skips `n` consecutive instructions.
    Glitch(usize),
}

impl ValueEnum for FaultType {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            FaultType::Glitch(1),
            FaultType::Glitch(2),
            FaultType::Glitch(3),
            FaultType::Glitch(4),
            FaultType::Glitch(5),
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            FaultType::Glitch(1) => PossibleValue::new("Glitch"),
            FaultType::Glitch(2) => PossibleValue::new("Glitch2"),
            FaultType::Glitch(3) => PossibleValue::new("Glitch3"),
            FaultType::Glitch(4) => PossibleValue::new("Glitch4"),
            FaultType::Glitch(5) => PossibleValue::new("Glitch5"),
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Debug)]
/// Representation of an fault which was executed in a simulation.
pub struct FaultData {
    /// The original instructions which would have been performed without the fault.
    pub original_instructions: Vec<u8>,
    /// The recorded execution trace of this fault.
    pub record: TraceRecord,
    /// SimulationFaultRecord which caused this FaultData to be simulated.
    pub fault: SimulationFaultRecord,
}

impl FaultData {
    pub fn get_simulation_fault_records(
        fault_data_records: &[FaultData],
    ) -> Vec<SimulationFaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault)
            .collect()
    }
}
