use super::{FaultData, FaultFunctions, FaultType};
use crate::simulation::cpu::{Cpu, ARM_REG};
use crate::simulation::record::{FaultRecord, TraceRecord};
use std::sync::Arc;

const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

/// Glitch fault structure
/// number  Number of assembler instructions to advance program counter to simulate
///         glitching on internal cpu state machine
///
#[derive(Clone, Copy, Debug)]
pub struct Glitch {
    pub number: usize,
}

/// Implementation for Glitch fault
impl Glitch {
    /// Create a new Glitch fault
    pub fn new(number: usize) -> Arc<Glitch> {
        Arc::new(Glitch { number })
    }

    /// Get the label of the fault
    pub fn get_label(&self) -> String {
        format!("Glitch[{}]", self.number)
    }
}

impl FaultFunctions for Glitch {
    /// Execute a glitch skipping `n` instructions.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) {
        let address = cpu.get_program_counter();
        let mut offset = 0;
        let mut manipulated_instructions = Vec::new();

        for _count in 0..self.number {
            let instruction_size = cpu.get_asm_cmd_size(address + offset).unwrap();
            manipulated_instructions.extend_from_slice(&T1_NOP[..instruction_size]);
            offset += instruction_size as u64;
        }
        cpu.set_program_counter(address + offset);

        // Set to same size as data_changed
        let mut original_instructions = manipulated_instructions.clone();
        // Read original instructions
        cpu.memory_read(address, &mut original_instructions)
            .unwrap();

        // Read registers
        let mut registers: [u32; 17] = [0; 17];
        ARM_REG.iter().enumerate().for_each(|(index, register)| {
            registers[index] = cpu.register_read(*register).unwrap() as u32;
        });
        let record = TraceRecord::Fault {
            address,
            fault_type: self.get_label(),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instructions,
            record,
            fault: fault.clone(),
        });
    }

    /// Filtering of traces
    /// Currently no filtering. All positions are attacked
    ///
    fn filter(&self, _records: &mut Vec<TraceRecord>) {}

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
    fn get_list<'a>(&'a self) -> Vec<&'a str> {
        vec![
            "glitch_1",
            "glitch_2",
            "glitch_3",
            "glitch_4",
            "glitch_5",
            "glitch_6",
            "glitch_7",
            "glitch_8",
            "glitch_9",
            "glitch_10",
        ]
    }
}
