use super::{
    debug, EmulationData, MemType, RegisterARM, RunState, TraceRecord, Unicorn, BOOT_STAGE,
};

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed boot flow
pub(super) fn mmio_auth_write_callback(
    emu: &mut Unicorn<EmulationData>,
    _mem_type: MemType,
    _address: u64,
    _size: usize,
    value: i64,
) -> bool {
    match value {
        1 => {
            emu.get_data_mut().state = RunState::Success;
            debug!("Indicator: __SET_SIM_SUCCESS()")
        }
        2 => {
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
pub(super) fn mmio_serial_write_callback(
    emu: &mut Unicorn<EmulationData>,
    _address: u64,
    _size: usize,
    value: u64,
) {
    if !emu.get_data().deactivate_print {
        print!("{}", value as u8 as char);
    }
}

/// Hook for flash_load_img callback handling
///
pub(super) fn hook_code_flash_load_img_callback(
    emu: &mut Unicorn<EmulationData>,
    _address: u64,
    _size: u32,
) {
    if emu.get_data_mut().negative_run {
        // Write flash data to boot stage memory
        let boot_stage: [u8; 4] = [0xB8, 0x45, 0x85, 0xFD];
        emu.mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    } else {
        // Write flash data to boot stage memory
        let boot_stage: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
        emu.mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    }
    debug!("Call of flash_load_img");
}

/// Code Hook for tracing functionality
///
pub(super) fn hook_code_callback(emu: &mut Unicorn<EmulationData>, address: u64, size: u32) {
    // Check if tracing is already started
    if emu.get_data().start_trace {
        // Prepare data record
        let mut record = TraceRecord {
            size: size as usize,
            address: address,
            asm_instruction: vec![0x00; size as usize],
            cpsr: emu.reg_read(RegisterARM::CPSR).unwrap() as u32,
        };
        emu.mem_read(address, &mut record.asm_instruction).unwrap();

        // Record data
        emu.get_data_mut().trace_data.push(record);
    }
}

// Code Hook for attack simulation
//
// 1. Case: Single attack
//     a. Record negative command trace: cmd_trace
//         a1. Analyze trace to find double addresses -> Set count of double addresses from 1 to n
//             Setup hashtable if value is already in list count++ in hash table and set count of vec array to new count value
//     b. Attack inserted from start to beginning of neagtive test flow cmd_trace[0..]
//         b1. Go through the list if address match check count: If count > 1: count-- else insert attack remove entry
// 2. Case: Double attack
//     a. Set single attack -> Start record after empty fault array
//         a1. Analyze trace to find double addresses -> Set count of double addresses from 1 to n
//             Setup hashtable if value is already in list count++ in hash table and set count of vec array to new count value
//     b. Attack inserted from start to beginning of neagtive test flow cmd_trace[0..]
//         b1. Go through the list if address match check count: If count > 1: count-- else insert attack remove entry
//
// pub(super) fn hook_nop_code_callback(emu: &mut Unicorn<EmulationData>, address: u64, _size: u32) {
//     // search for corresponding fault
//     if let Some(fault) = emu.get_data().fault_data.first() {
//         let fault = fault.clone();
//         // Check address
//         if fault.fault.address == address {
//             // println!("Taken : 0x{:X}", fault.fault.address);
//             emu.get_data_mut().fault_data.remove(0);
//             // Skip instruction(s)
//             skip_asm_cmds(emu, &fault);
//         }
//     }
// }

// Code Hook for tracing functionality with attack simulation
//
// pub(super) fn hook_nop_code_callback_trace(
//     emu: &mut Unicorn<EmulationData>,
//     address: u64,
//     size: u32,
// ) {
//     // search for corresponding fault
//     if let Some(fault) = emu.get_data().fault_data.first() {
//         let fault = fault.clone();
//         // Check address
//         if fault.fault.address == address {
//             // println!("Taken : 0x{:X}", fault.fault.address);
//             emu.get_data_mut().fault_data.remove(0);
//             // Skip instruction(s)
//             skip_asm_cmds(emu, &fault);
//         }
//     }
//     // Record complete trace flow
//     emu.get_data_mut().trace_data.push(TraceRecord {
//         size: size as usize,
//         address: address,
//     });
// }

// Skip instruction(s)
// fn skip_asm_cmds(emu: &mut Unicorn<EmulationData>, fault: &FaultData) {
//     // Save and restore CPSR register as Unicorn changes its value
//     let cpsr = emu.reg_read(RegisterARM::CPSR).unwrap();
//     emu.reg_write(
//         RegisterARM::PC,
//         (fault.fault.address + fault.fault.size as u64) | 1,
//     )
//     .unwrap();
//     emu.reg_write(RegisterARM::CPSR, cpsr).unwrap();
// }
