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

/// Implementation for CmdBitFlip fault
impl CmdBitFlip {
    /// Create a new CmdBitFlip fault
    ///
    /// # Arguments
    ///
    /// * `xor_value` - The XOR value to apply to the command.
    ///
    /// # Returns
    ///
    /// * `Arc<Self>` - Returns an `Arc` containing the `CmdBitFlip` instance.
    pub fn new(xor_value: u32) -> Arc<Self> {
        Arc::new(Self { xor_value })
    }
}

impl FaultFunctions for CmdBitFlip {
    /// Executes a command bit flip fault injection.
    ///
    /// This method modifies the command code by applying an XOR operation with the specified value.
    /// It records the original and modified instructions, as well as the fault details, for analysis.
    ///
    /// # Arguments
    ///
    /// * `cpu` - The CPU instance where the fault is injected.
    /// * `fault` - The fault record containing details of the fault.
    ///
    /// # Returns
    ///
    /// * `bool` - Always returns `true` to indicate that code repair is required after the fault injection.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        // Get current assembler instruction
        let (address, original_instruction) = cpu.asm_cmd_read();

        // Set original instructions to same as the original read instructions
        let mut modified_instruction = original_instruction.clone();

        // Manipulate the read command with the xor value
        for (i, byte) in &mut modified_instruction.iter_mut().enumerate() {
            *byte ^= self.xor_value.to_le_bytes()[i];
        }
        cpu.asm_cmd_write(address, &modified_instruction).unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!(
                "Command BitFlip (cmdbf_{:08x}) 0x{:x} -> 0x{:x}",
                self.xor_value,
                original_instruction
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (*b as u32) << (i * 8) as u32)
                    .sum::<u32>(),
                modified_instruction
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (*b as u32) << (i * 8) as u32)
                    .sum::<u32>()
            ),
            data: original_instruction.clone(),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instruction,
            modified_instruction,
            record,
            fault: fault.clone(),
        });

        // Trigger code repair after fault injection
        true
    }

    /// Filtering of traces to reduce the number of traces to analyze.
    ///
    /// # Arguments
    ///
    /// * `records` - The trace records to filter.
    /// * `cs` - The disassembly context.
    fn filter(&self, _records: &mut Vec<TraceRecord>, _cs: &Disassembly) {}

    /// Try to parse a CmdBitFlip fault from a string.
    ///
    /// # Arguments
    ///
    /// * `input` - The input string.
    ///
    /// # Returns
    ///
    /// * `Option<FaultType>` - Returns the fault type if successful, otherwise `None`.
    fn try_from(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute_1 = collect.get(1).copied()?;
        // check if fault type is cmd bit flip
        if fault_type == "cmdbf" {
            // check if attribute is a valid value
            if let Ok(xor_value) = u32::from_str_radix(attribute_1, 16) {
                // return CmdBitFlip struct
                return Some(Self::new(xor_value));
            }
        }
        None
    }

    /// Get the list of possible/good faults.
    ///
    /// # Returns
    ///
    /// * `Vec<String>` - Returns a vector of fault names.
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
