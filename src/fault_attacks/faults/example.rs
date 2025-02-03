use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::Cpu,
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
};
use std::fmt::Debug;
use std::sync::Arc;

/// BitFlip fault structure
///
#[derive(Clone, Copy)]
pub struct BitFlip {}

impl Debug for Example {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Example()")
    }
}

/// Implementation for Example fault
impl Example {
    /// Create a new Example fault
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}

impl FaultFunctions for Example {
    /// Execute a Example skipping `n` instructions.
    fn execute(&self, _cpu: &mut Cpu, _fault: &FaultRecord) -> bool {
        // No cleanup required
        false
    }

    /// Filtering of traces to reduce the number of traces to analyze
    fn filter(&self, records: &mut Vec<TraceRecord>, cs: &Disassembly) {}

    /// Try to parse a Example fault from a string
    fn try_from(&self, _input: &str) -> Option<FaultType> {
        None
    }
    /// Get the list of possible/good faults
    fn get_list(&self) -> Vec<String> {
        vec![]
    }
}
