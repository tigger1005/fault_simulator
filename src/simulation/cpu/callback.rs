use super::{CpuState, RunState, TraceRecord, ARM_REG};

use unicorn_engine::unicorn_const::MemType;
use unicorn_engine::Unicorn;

use log::debug;

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed DECISION_DATA flow
pub fn mmio_auth_write_callback(
    emu: &mut Unicorn<CpuState>,
    _mem_type: MemType,
    _address: u64,
    _size: usize,
    value: i64,
) -> bool {
    match value {
        0x11111111 => {
            emu.get_data_mut().state = RunState::Success;
            debug!("Indicator: __SET_SIM_SUCCESS()")
        }
        0x22222222 => {
            emu.get_data_mut().state = RunState::Failed;
            debug!("Indicator: __SET_SIM_FAILED()")
        }
        _ => {
            emu.get_data_mut().state = RunState::Error;
            debug!("Indicator: Wrong_Value")
        }
    }
    emu.emu_stop().expect("failed to stop");
    true
}

/// Callback for serial mem IO write access
///
/// This IO write displays printed messages
pub fn mmio_serial_write_callback(
    emu: &mut Unicorn<CpuState>,
    _address: u64,
    _size: usize,
    value: u64,
) {
    if !emu.get_data().deactivate_print {
        print!("{}", value as u8 as char);
    }
}

/// Hook for decision_activation callback handling
///
pub fn hook_code_decision_activation_callback(
    emu: &mut Unicorn<CpuState>,
    _address: u64,
    _size: u32,
) {
    debug!("Call of decision_activation");
    // Set decision data according the run (negative/positive)
    let success: bool = !emu.get_data_mut().negative_run;
    write_decision_element(emu, success);
}

/// Code Hook for tracing functionality
pub fn hook_code_callback(emu: &mut Unicorn<CpuState>, address: u64, size: u32) {
    let emu_data = &emu.get_data();
    // Check if tracing is already started
    if emu_data.start_trace {
        let mut asm_instruction = vec![0x00; size as usize];
        emu.mem_read(address, &mut asm_instruction).unwrap();

        let registers = if emu_data.with_register_data {
            let mut registers: [u32; 17] = [0; 17];
            ARM_REG.iter().enumerate().for_each(|(index, register)| {
                registers[index] = emu.reg_read(*register).unwrap() as u32;
            });
            Some(registers)
        } else {
            None
        };

        let index = emu.get_data().trace_data.len();
        // Record data
        emu.get_data_mut()
            .trace_data
            .push(TraceRecord::Instruction {
                address,
                index,
                asm_instruction,
                registers,
            });
    }
}

/// Write data to the decision data element according to given bool value
/// true: success data will be copied to decision data element
/// false: false data will be copied to decision data element
///
pub fn write_decision_element(emu: &mut Unicorn<CpuState>, success: bool) {
    let mut decision_element_size: [u8; 4] = [0x0; 4];
    let decision_struct_address: u64 = emu
        .get_data()
        .file_data
        .symbol_map
        .get("decisiondata")
        .unwrap()
        .st_value;
    let decision_data_address: u64 = decision_struct_address + 4;

    // Read size of decision element
    emu.mem_read(decision_struct_address, &mut decision_element_size)
        .expect("failed to read decision element size");
    let element_size: u32 = u32::from_le_bytes(decision_element_size);

    let success_data_address = decision_data_address + element_size as u64;
    let failure_data_address = decision_data_address + (element_size as u64 * 2);

    let mut data: Vec<u8> = vec![0x00; element_size as usize];
    // Read specific data (success/failure)
    if success {
        emu.mem_read(success_data_address, &mut data)
            .expect("failed to read failure data");
    } else {
        emu.mem_read(failure_data_address, &mut data)
            .expect("failed to read success data");
    }
    //debug!("Data written {:?}", &data);
    // Write specifc data to decision data
    emu.mem_write(decision_data_address, &data)
        .expect("failed to write to decision data element");
}
