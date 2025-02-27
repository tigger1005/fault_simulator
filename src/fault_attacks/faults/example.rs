use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::Cpu,
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
};
use std::fmt::Debug;
use std::sync::Arc;

/// Example fault structure
///
#[derive(Clone, Copy)]
pub struct Example {}

impl Debug for Example {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Example()")
    }
}

/// Implementation for Example fault
impl Example {
    /// Create a new Example fault
    ///
    /// # Returns
    ///
    /// * `Arc<Self>` - Returns an `Arc` containing the `Example` instance.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}

impl FaultFunctions for Example {
    /// Execute an Example fault.
    ///
    /// # Arguments
    ///
    /// * `_cpu` - The CPU instance.
    /// * `_fault` - The fault record.
    ///
    /// # Returns
    ///
    /// * `bool` - Returns `false` as no cleanup is required.
    fn execute(&self, _cpu: &mut Cpu, _fault: &FaultRecord) -> bool {
        // No cleanup required
        false
    }

    /// Filtering of traces to reduce the number of traces to analyze.
    ///
    /// # Arguments
    ///
    /// * `records` - The trace records to filter.
    /// * `cs` - The disassembly context.
    fn filter(&self, records: &mut Vec<TraceRecord>, cs: &Disassembly) {}

    /// Try to parse an Example fault from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string.
    ///
    /// # Returns
    ///
    /// * `Option<FaultType>` - Returns the fault type if successful, otherwise `None`.
    fn try_from(&self, _input: &str) -> Option<FaultType> {
        None
    }

    /// Get the list of possible/good faults.
    ///
    /// # Returns
    ///
    /// * `Vec<String>` - Returns a vector of fault names.
    fn get_list(&self) -> Vec<String> {
        vec![]
    }
}
