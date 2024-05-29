use super::{FaultData, FaultFunctions};
use crate::simulation::cpu::{Cpu, ARM_REG};
use crate::simulation::record::{FaultRecord, TraceRecord};
use clap::builder::PossibleValue;

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
    pub fn new(number: usize) -> Box<Glitch> {
        Box::new(Glitch { number })
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
            fault_type: format!("{:?}", fault.fault_type),
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instructions,
            record,
            fault: fault.clone(),
        });
    }

    /// Clone function for Boxed type
    fn clone_new(&self) -> crate::prelude::FaultType {
        Glitch::new(self.number)
    }

    /// Filtering of traces
    /// Currently no filtering. All positions are attacked
    ///
    fn filter(&self, _records: &mut Vec<TraceRecord>) {}

    /// Value parsing for command line parameters
    fn get_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self.number {
            1 => Some(PossibleValue::new("Glitch")),
            2 => Some(PossibleValue::new("Glitch2")),
            3 => Some(PossibleValue::new("Glitch3")),
            4 => Some(PossibleValue::new("Glitch4")),
            5 => Some(PossibleValue::new("Glitch5")),
            _ => None,
        }
    }
}
