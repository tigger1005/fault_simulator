use super::{FaultFunctions, FaultType};
use crate::simulation::cpu::Cpu;
use crate::simulation::record::{FaultRecord, TraceRecord};
use std::fmt::Debug;
use std::sync::Arc;

/// BitFlip fault structure
///
#[derive(Clone, Copy)]
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

impl Debug for BitFlip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BitFlip()")
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
