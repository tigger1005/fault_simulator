use super::{CpuState, RunState, TraceRecord, ARM_REG};

use unicorn_engine::unicorn_const::MemType;
use unicorn_engine::Unicorn;

use log::debug;

/// Handles memory-mapped IO (MMIO) write access for authentication.
///
/// This callback updates the simulation state based on the written value:
/// - `0x11111111`: Sets the state to `Success`.
/// - `0x22222222`: Sets the state to `Failed`.
/// - Any other value: Sets the state to `Error`.
///
/// # Arguments
///
/// * `emu` - The Unicorn emulator instance.
/// * `_mem_type` - The type of memory access (unused).
/// * `_address` - The memory address being written to (unused).
/// * `_size` - The size of the write operation (unused).
/// * `value` - The value being written.
///
/// # Returns
///
/// * `bool` - Always returns `true` to indicate the callback was handled.
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

/// Dedicated hook for custom success/failure address monitoring
/// This hook only checks for user-defined success and failure addresses
pub fn hook_custom_addresses_callback(emu: &mut Unicorn<CpuState>, address: u64, _size: u32) {
    let emu_data = emu.get_data();

    // Check for success addresses
    if emu_data.success_addresses.contains(&address) {
        emu.get_data_mut().state = RunState::Success;
        debug!("Custom success address reached: 0x{:x}", address);
        emu.emu_stop().expect("failed to stop");
        return;
    }

    // Check for failure addresses
    if emu_data.failure_addresses.contains(&address) {
        emu.get_data_mut().state = RunState::Failed;
        debug!("Custom failure address reached: 0x{:x}", address);
        emu.emu_stop().expect("failed to stop");
    }
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

/// Callback for all memory errors to see the exact address being accessed
pub fn capture_memory_errors(
    emu: &mut Unicorn<CpuState>,
    mem_type: MemType,
    address: u64,
    _size: usize,
    _value: i64,
) -> bool {
    if emu.get_data().print_unicorn_errors {
        let pc = emu.pc_read().unwrap_or(0);
        let access_type = match mem_type {
            MemType::READ_UNMAPPED => "READ_UNMAPPED",
            MemType::WRITE_UNMAPPED => "WRITE_UNMAPPED",
            MemType::FETCH_UNMAPPED => "FETCH_UNMAPPED",
            MemType::READ_PROT => "READ_PROT",
            MemType::WRITE_PROT => "WRITE_PROT",
            MemType::FETCH_PROT => "FETCH_PROT",
            _ => {
                // Print unknown memory error types with debug info
                eprintln!(
                    "Unicorn Error: {:?} at PC 0x{:08X} (accessing 0x{:08X})",
                    mem_type, pc, address
                );
                return false;
            }
        };
        eprintln!(
            "Unicorn Error: {} at PC 0x{:08X} (accessing 0x{:08X})",
            access_type, pc, address
        );
    }
    false // Let the error propagate
}
