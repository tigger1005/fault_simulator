use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::{Cpu, ARM_REG},
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
};
use std::fmt::Debug;
use std::sync::Arc;
use unicorn_engine::RegisterARM;

/// Register BitFlip fault structure
///
#[derive(Clone, Copy)]
pub struct RegisterBitFlip {
    pub register: RegisterARM,
    pub xor_value: u32,
}

impl Debug for RegisterBitFlip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Register BitFlip (regbf_r{}_{:08x})",
            self.register as u32 - RegisterARM::R0 as u32,
            self.xor_value
        )
    }
}

/// Implementation for Glitch fault
impl RegisterBitFlip {
    /// Create a new Glitch fault
    pub fn new(register: RegisterARM, xor_value: u32) -> Arc<Self> {
        Arc::new(Self {
            register,
            xor_value,
        })
    }
}

impl FaultFunctions for RegisterBitFlip {
    /// Execute a bit flip in the given register.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        let address = cpu.get_program_counter();

        // Read and write changed register
        let reg_val = cpu.register_read(self.register).unwrap();
        cpu.register_write(self.register, reg_val ^ self.xor_value as u64)
            .unwrap();

        // Read assembler line
        let mut original_instructions = vec![0; cpu.get_asm_cmd_size(address).unwrap()];
        // Read original instructions
        cpu.memory_read(address, &mut original_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!(
                "Register BitFlip (Reg: R{}, Value: {:08x}) 0x{:08x} -> 0x{:08x}",
                self.register as u32 - RegisterARM::R0 as u32,
                self.xor_value,
                reg_val,
                reg_val ^ self.xor_value as u64
            ),
            data: vec![],
        };
        cpu.get_trace_data().push(record.clone());

        // Push to fault data vector
        cpu.get_fault_data().push(FaultData {
            original_instruction: original_instructions,
            modified_instruction: vec![],
            record,
            fault: fault.clone(),
        });

        // No cleanup required
        false
    }

    /// Filtering of traces to reduce the number of traces to analyze
    fn filter(&self, records: &mut Vec<TraceRecord>, cs: &Disassembly) {
        records.retain(|record| match record {
            TraceRecord::Instruction {
                address,
                asm_instruction,
                ..
            } => cs.check_for_register(
                asm_instruction,
                *address,
                self.register as u32 - RegisterARM::R0 as u32,
            ),
            _ => false,
        });
    }

    /// Try to parse a Glitch fault from a string
    fn try_from(&self, input: &str) -> Option<FaultType> {
        // divide name from attribute
        let collect: Vec<&str> = input.split('_').collect();
        // check if name and attribute are present
        let fault_type = collect.first().copied()?;
        let attribute_1 = collect.get(1).copied()?;
        let attribute_2 = collect.get(2).copied()?;
        // check if fault type is glitch
        if fault_type == "regbf" {
            // check if attribute is a register
            if let Some(stripped) = attribute_1.strip_prefix('r') {
                // check if attribute is a valid register
                if let Ok(register) = stripped.parse::<usize>() {
                    // check if attribute is a valid value
                    if let Ok(xor_value) = u32::from_str_radix(attribute_2, 16) {
                        // return Glitch struct
                        return Some(Self::new(ARM_REG[register], xor_value));
                    }
                }
            }
        }
        None
    }
    /// Get the list of possible/good faults
    fn get_list(&self) -> Vec<String> {
        let mut list = Vec::new();
        // Generate a list of all possible register bitflips
        // Values will look like: regbf_r0_00000001, regbf_r0_00000002, ...
        for reg in 0..=12 {
            for index in 0..=31 {
                list.push(format!("regbf_r{}_{:08x}", reg, 1 << index));
            }
        }
        list
    }
}
