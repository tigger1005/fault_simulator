use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::Cpu,
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
};
use std::fmt::Debug;
use std::sync::Arc;

const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

/// Glitch fault structure
/// number  Number of assembler instructions to advance program counter to simulate
///         glitching on internal cpu state machine
///
#[derive(Clone, Copy)]
pub struct Glitch {
    pub number: usize,
}

impl Debug for Glitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Glitch (glitch_{})", self.number)
    }
}

/// Implementation for Glitch fault
impl Glitch {
    /// Create a new Glitch fault
    pub fn new(number: usize) -> Arc<Self> {
        Arc::new(Self { number })
    }
}

impl FaultFunctions for Glitch {
    /// Execute a glitch skipping `n` instructions.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        let address = cpu.get_program_counter();
        let mut offset = 0;
        let mut modified_instructions = Vec::new();

        for _count in 0..self.number {
            let instruction_size = cpu.get_asm_cmd_size(address + offset).unwrap();
            modified_instructions.extend_from_slice(&T1_NOP[..instruction_size]);
            offset += instruction_size as u64;
        }
        cpu.set_program_counter(address + offset);

        // Set to same size as data
        let mut original_instructions = modified_instructions.clone();
        // Read original instructions
        cpu.memory_read(address, &mut original_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!("Glitch ({} assembler instruction)", self.number,),
            data: original_instructions.clone(),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instruction: original_instructions,
            modified_instruction: modified_instructions,
            record,
            fault: fault.clone(),
        });

        // No cleanup required
        false
    }

    /// Filtering of traces to reduce the number of traces to analyze
    fn filter(&self, _records: &mut Vec<TraceRecord>, _cs: &Disassembly) {}

    /// Try to parse a Glitch fault from a string
    fn try_from(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute = collect.get(1).copied()?;
        // check if fault type is glitch
        if fault_type == "glitch" {
            // check if attribute is a number
            if let Ok(num) = attribute.parse::<usize>() {
                // return Glitch struct
                return Some(Self::new(num));
            }
        }
        None
    }
    /// Get the list of possible/good faults
    fn get_list(&self) -> Vec<String> {
        let list: Vec<String> = (1..=8).map(|index| format!("glitch_{}", index)).collect();
        list
    }
}
