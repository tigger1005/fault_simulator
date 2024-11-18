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
#[derive(Clone)]
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
    /// Do bit flips to command code before execution
    /// Return
    ///     false:  No code repair needed
    ///     true:   Code repair after fault injection is required
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        // Get current assembler instruction
        let (address, original_instruction) = cpu.asm_cmd_read();

        // Set original instructions to same as the original read instructions
        let mut manipulated_instruction = original_instruction.clone();

        // Manipulate the read command with the xor value
        for (i, byte) in &mut manipulated_instruction.iter_mut().enumerate() {
            *byte ^= self.xor_value.to_le_bytes()[i];
        }
        cpu.memory_write(address, &manipulated_instruction).unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!("Command BitFlip (cmdbf_{:08x})", self.xor_value,),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instruction: original_instruction.clone(),
            record,
            fault: fault.clone(),
        });

        // Trigger code repair after fault injection
        true
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
