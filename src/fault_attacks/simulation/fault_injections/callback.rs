use super::{debug, EmulationData, MemType, RunState, TraceRecord, Unicorn, BOOT_STAGE};

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed boot flow
pub(super) fn mmio_auth_write_callback<D>(
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
pub(super) fn mmio_serial_write_callback<D>(
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
pub(super) fn hook_code_flash_load_img_callback<D>(
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
pub(super) fn hook_code_callback<D>(emu: &mut Unicorn<EmulationData>, address: u64, size: u32) {
    let record = TraceRecord {
        size: size as usize,
        count: 1,
    };

    emu.get_data_mut()
        .trace_data
        .entry(address)
        .and_modify(|record| record.count += 1)
        .or_insert(record);
}
