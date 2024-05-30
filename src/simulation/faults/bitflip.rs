use super::{FaultFunctions, FaultType};
use crate::simulation::cpu::Cpu;
use crate::simulation::record::{FaultRecord, TraceRecord};
use std::sync::Arc;

/// BitFlip fault structure
///
#[derive(Clone, Copy, Debug)]
pub struct BitFlip {}

/// Implementation for Glitch fault
impl BitFlip {
    /// Create a new Glitch fault
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }

    /// Get the label of the fault
    pub fn get_label(&self) -> String {
        "BitFlip".to_string()
    }
}

impl FaultFunctions for BitFlip {
    /// Execute a glitch skipping `n` instructions.
    fn execute(&self, _cpu: &mut Cpu, _fault: &FaultRecord) {}

    /// Filtering of traces
    fn filter(&self, _records: &mut Vec<TraceRecord>) {}

    /// Try to parse a Glitch fault from a string
    fn try_from(&self, _input: &str) -> Option<FaultType> {
        None
    }
    /// Get the list of possible/good faults
    fn get_list(&self) -> Vec<&str> {
        vec![]
    }
}
