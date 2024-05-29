use super::{FaultRecord, TraceRecord};
use crate::simulation::cpu::Cpu;
use clap::ValueEnum;
use std::fmt::Debug;

pub mod glitch;
pub use glitch::Glitch;

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

/// Trait for fault injection functions
pub trait FaultFunctions: Send + Sync + Debug {
    //    pub trait FaultFunctions: Debug + Send + Sync + PartialEq + Clone {
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord);
    fn filter(&self, records: &mut Vec<TraceRecord>);
    fn get_possible_value(&self) -> Option<clap::builder::PossibleValue>;
    fn clone_new(&self) -> FaultType;
}

/// Type definition of fault injection data type
pub type FaultType = Box<dyn FaultFunctions>;

/// Implementation of clone for Boxed type
impl Clone for FaultType {
    fn clone(&self) -> Self {
        self.clone_new()
    }
}

/// Implementation for command line fault attack parsing
impl ValueEnum for FaultType {
    fn value_variants<'a>() -> &'a [Self] {
        &[]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        self.get_possible_value()
    }
}
