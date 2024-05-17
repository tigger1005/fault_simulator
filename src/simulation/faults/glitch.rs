use super::{FaultData, FaultType};
use crate::simulation::cpu::{Cpu, ARM_REG};
use crate::simulation::record::{SimulationFaultRecord, TraceRecord};

const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

/// Execute a glitch skipping `n` instructions.
pub fn execute_glitch(cpu: &mut Cpu, fault: &SimulationFaultRecord) {
    let address = cpu.get_program_counter();
    let mut offset = 0;
    let mut manipulated_instructions = Vec::new();

    let FaultType::Glitch(n) = fault.fault_type;
    for _count in 0..n {
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
        fault_type: fault.fault_type,
    };
    cpu.get_trace_data().push(record.clone());

    // Push to fault data vector
    cpu.get_fault_data().push(FaultData {
        original_instructions,
        record,
        fault: *fault,
    });
}
