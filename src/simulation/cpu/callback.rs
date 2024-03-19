use super::{CpuState, RunState, TraceRecord, ARM_REG, BOOT_STAGE};

use unicorn_engine::unicorn_const::MemType;
use unicorn_engine::Unicorn;

use log::debug;

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed boot flow
pub fn mmio_auth_write_callback(
    emu: &mut Unicorn<CpuState>,
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

const POSITIVE_VALUE: u32 = 0x5555AAAAu;
const NEGATIVE_VALUE: u32 = 0xAAAA5555u;
const FIH_UINT_MASK_VALUE: u32 = 0xB779A31C;
#[repr(C)]
struct FihUint {
    val: u32,
    msk: u32,
}
const FIH_SUCCESS: FihUint = FihUint {
    val: POSITIVE_VALUE,
    msk: (POSITIVE_VALUE ^ FIH_UINT_MASK_VALUE),
};
const FIH_FAILURE: FihUint = FihUint {
    val: POSITIVE_VALUE,
    msk: (POSITIVE_VALUE ^ FIH_UINT_MASK_VALUE),
};

/// Hook for flash_load_img callback handling
pub fn hook_code_flash_load_img_callback(emu: &mut Unicorn<CpuState>, _address: u64, _size: u32) {
    if emu.get_data_mut().negative_run {
        // Write flash data to boot stage memory
        let boot_stage: [u8; 8] = FIH_FAILURE;
        emu.mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    } else {
        // Write flash data to boot stage memory
        let boot_stage: [u8; 8] = FIH_SUCCESS;
        emu.mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    }
    debug!("Call of flash_load_img");
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

        // Record data
        emu.get_data_mut()
            .trace_data
            .push(TraceRecord::Instruction {
                address,
                asm_instruction,
                registers,
            });
    }
}
