use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::Cpu,
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
};
use std::fmt::Debug;
use std::sync::Arc;

/// Command bit flip fault structure
///
#[derive(Clone, Copy)]
pub struct CmdBitFlip {
    pub xor_value: u32,
}

impl Debug for CmdBitFlip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Command BitFlip (cmdbf_{:08x})", self.xor_value)
    }
}

/// Implementation for Example fault
impl CmdBitFlip {
    /// Create a new Example fault
    pub fn new(xor_value: u32) -> Arc<Self> {
        Arc::new(Self { xor_value })
    }
}

impl FaultFunctions for CmdBitFlip {
    /// Execute a Example skipping `n` instructions.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) {
        let address = cpu.get_program_counter();
        let mut manipulated_instructions = Vec::with_capacity(4);

        // Read and write changed command to memory (Draft: Change is currently constant for simulation loop)
        let instruction_size = cpu.get_asm_cmd_size(address).unwrap();

        // Read original instructions
        manipulated_instructions.resize(instruction_size, 0);
        cpu.memory_read(address, &mut manipulated_instructions)
            .unwrap();

        // Set original instructions to same as the original read instructions
        let original_instructions = manipulated_instructions.clone();

        // Manipulate the read command with the xor value
        for (i, byte) in &mut manipulated_instructions.iter_mut().enumerate() {
            *byte ^= self.xor_value.to_le_bytes()[i];
        }
        cpu.memory_write(address, &manipulated_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!("Command BitFlip (cmdbf_{:08x})", self.xor_value,),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instructions,
            record,
            fault: fault.clone(),
        });
    }

    /// Filtering of traces to reduce the number of traces to analyze
    fn filter(&self, _records: &mut Vec<TraceRecord>, _cs: &Disassembly) {}

    /// Try to parse a Example fault from a string
    fn try_from(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute_1 = collect.get(1).copied()?;
        // check if fault type is glitch
        if fault_type == "cmdbf" {
            // check if attribute is a valid value
            if let Ok(xor_value) = u32::from_str_radix(attribute_1, 16) {
                // return Glitch struct
                return Some(Self::new(xor_value));
            }
        }
        None
    }
    /// Get the list of possible/good faults
    fn get_list(&self) -> Vec<String> {
        let mut list = Vec::new();
        // Generate a list of all possible cmd bitflips
        // Values will look like: cmdbf_00000001, cmdbf_00000002, ...
        for index in 0..=31 {
            list.push(format!("cmdbf_{:08x}", 1 << index));
        }
        list
    }
}
