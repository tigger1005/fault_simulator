use super::{SimulationFaultRecord, TraceRecord};
use clap::{builder::PossibleValue, ValueEnum};

mod glitch;
pub use glitch::execute_glitch;

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

#[derive(Clone, Debug, PartialEq)]
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
