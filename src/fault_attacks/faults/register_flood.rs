use super::{Disassembly, FaultFunctions, FaultType};
use crate::simulation::{
    cpu::{Cpu, ARM_REG},
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
};
use std::fmt::Debug;
use std::sync::Arc;
use unicorn_engine::RegisterARM;

/// Register flood fault structure
///
#[derive(Clone, Copy)]
pub struct RegisterFlood {
    pub register: RegisterARM,
    pub value: u32,
}

impl Debug for RegisterFlood {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Register Flood (regflood_r{}_{:08x})",
            self.register as u32 - RegisterARM::R0 as u32,
            self.value
        )
    }
}

/// Implementation for RegisterFlood fault
impl RegisterFlood {
    /// Creates a new `RegisterFlood` fault.
    ///
    /// # Arguments
    ///
    /// * `register` - The register to flood.
    /// * `value` - The value to flood the register with.
    ///
    /// # Returns
    ///
    /// * `Arc<Self>` - Returns an `Arc` containing the `RegisterFlood` instance.
    pub fn new(register: RegisterARM, value: u32) -> Arc<Self> {
        Arc::new(Self { register, value })
    }
}

impl FaultFunctions for RegisterFlood {
    /// Executes a register flood fault by overwriting the specified register with a given value.
    ///
    /// This method modifies the value of the specified register and records the fault details for analysis.
    ///
    /// # Arguments
    ///
    /// * `cpu` - The CPU instance where the fault is injected.
    /// * `fault` - The fault record containing details of the fault.
    ///
    /// # Returns
    ///
    /// * `bool` - Always returns `false` as no cleanup is required after the fault injection.
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool {
        let address = cpu.get_program_counter();

        // Read and write changed register
        let reg_val = cpu.register_read(self.register).unwrap();
        cpu.register_write(self.register, self.value as u64)
            .unwrap();

        // Read assembler line
        let mut original_instructions = vec![0; cpu.get_asm_cmd_size(address).unwrap()];
        // Read original instructions
        cpu.memory_read(address, &mut original_instructions)
            .unwrap();

        let record = TraceRecord::Fault {
            address,
            fault_type: format!(
                "Register Flood (Reg: R{}, Value: {:08x}) 0x{:08x} -> 0x{:08x}",
                self.register as u32 - RegisterARM::R0 as u32,
                self.value,
                reg_val,
                self.value as u64
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

    /// Filters the trace records based on the disassembly.
    ///
    /// # Arguments
    ///
    /// * `records` - The trace records to filter.
    /// * `cs` - The disassembly context.
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

    /// Tries to create a `RegisterFlood` fault from the given input string.
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
        let attribute_2 = collect.get(2).copied()?;
        // check if fault type is glitch
        if fault_type == "regfld" {
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

    /// Returns a list of possible/good faults.
    ///
    /// # Returns
    ///
    /// * `Vec<String>` - Returns a vector of fault names.
    fn get_list(&self) -> Vec<String> {
        let mut list = Vec::new();
        // Generate a list of all possible register bitflips
        // Values will look like: regbf_r0_000000000, regbf_r0_FFFFFFFF, ...
        for reg in 0..=12 {
            list.push(format!("regfld_r{}_{:08x}", reg, 0));
            list.push(format!("regfld_r{}_{:08x}", reg, 0xFFFFFFFFu32));
        }
        list
    }
}
