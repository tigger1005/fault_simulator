#![allow(dead_code)]

use log::debug;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(PartialEq)]
enum RunState {
    Init = 0,
    Success,
    Failed,
    Error,
}

static RUN_STATE: AtomicUsize = AtomicUsize::new(RunState::Init as usize);
static RUN_TYPE_POSITIV: AtomicBool = AtomicBool::new(true);

mod elf_file;
use elf_file::ElfFile;

use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
//use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

const ARM_REG: [RegisterARM; 16] = [
    RegisterARM::R0,
    RegisterARM::R1,
    RegisterARM::R2,
    RegisterARM::R3,
    RegisterARM::R4,
    RegisterARM::R5,
    RegisterARM::R6,
    RegisterARM::R7,
    RegisterARM::R8,
    RegisterARM::R9,
    RegisterARM::R10,
    RegisterARM::R11,
    RegisterARM::R12,
    RegisterARM::SP,
    RegisterARM::LR,
    RegisterARM::PC,
];

const MAX_INSTRUCTIONS: usize = 20000000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const CODE_START: u64 = 0x80000000;
const BOOT_STAGE: u64 = 0x32000000;

fn main() {
    // Load and parse elf file
    let file_data: ElfFile = ElfFile::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));

    // Setup platform -> ARMv8-m.base
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS)
        .expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    // Setup memory and IO
    setup_mmio(emu, &file_data);

    // Setup breakpoints
    setup_breakpoints(emu, &file_data);

    // Run simulation
    run_simulation(emu, &file_data, true);
    assert_eq!(
        RUN_STATE.load(Ordering::Relaxed),
        RunState::Success as usize
    );

    run_simulation(emu, &file_data, false);
    assert_eq!(RUN_STATE.load(Ordering::Relaxed), RunState::Failed as usize);
}

fn run_simulation<D>(emu: &mut Unicorn<D>, file_data: &ElfFile, run_successful: bool) {
    // Clear registers
    ARM_REG
        .iter()
        .for_each(|reg| emu.reg_write(*reg, 0x00).unwrap());

    // Setup registers
    emu.reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
        .expect("failed to set register");

    // Write code to memory area
    emu.mem_write(file_data.program_header.p_paddr as u64, &file_data.program)
        .expect("failed to write file data");

    // Set run type
    RUN_TYPE_POSITIV.store(run_successful, Ordering::Relaxed);

    // Set global state to initilized
    RUN_STATE.store(RunState::Init as usize, Ordering::Relaxed);

    // Start execution
    debug!("Start program");

    //let mut pc: u64 = file_address as u64;
    // for _i in 0..200 {
    //     //println!("Executing address : 0x{:X}", pc);

    //     emu.emu_start(
    //         pc + 1,
    //         (file_address + elf_file.data().len() + 1) as u64,
    //         0,
    //         1,
    //     )
    //     .expect("failed to run program");

    //     pc = emu.reg_read(RegisterARM::PC).unwrap();
    // }

    let ret_info = emu.emu_start(
        (file_data.program_header.p_paddr + 1) as u64,
        (file_data.program_header.p_paddr + file_data.program_header.p_filesz + 1) as u64,
        SECOND_SCALE,
        MAX_INSTRUCTIONS,
    );
    if ret_info == Ok(()) {
        debug!("Program stopped successful");
    } else {
        debug!("Program stopped with {:?}", ret_info);
        RUN_STATE.store(RunState::Error as usize, Ordering::Relaxed);
    }
    //print_register_and_data(emu);
}

fn print_register_and_data<D>(emu: &mut Unicorn<D>) {
    println!(
        "Register R4 : 0x{:X}",
        emu.reg_read(RegisterARM::R4).unwrap()
    );
    println!(
        "Register R7 : 0x{:X}",
        emu.reg_read(RegisterARM::R7).unwrap()
    );
    println!(
        "Register LR : 0x{:X}",
        emu.reg_read(RegisterARM::LR).unwrap()
    );
    println!(
        "Register SP : 0x{:X}",
        emu.reg_read(RegisterARM::SP).unwrap()
    );

    let pc = emu.reg_read(RegisterARM::PC).unwrap();

    let mut data: [u8; 10] = [0; 10];
    emu.mem_read(pc, &mut data).expect("Read memory");
    println!("Register PC : 0x{:X}", pc);
    println!("Code: {:?}", data);
}

/// Setup the system
///
/// This include memory and mem IO ranges according with their specific read and write rights.
///
/// Next boot stage mem
/// { 0x32000000, new MemoryRegion { Size = 0x1000, Permission = MemoryPermission.RW }  }
///
/// Code
/// { 0x80000000, new MemoryRegion { Data = flashBin, Size = 0x20000, Permission = MemoryPermission.RWX } }
///
/// Stack
/// { 0x80100000, new MemoryRegion { Size = 0x10000, Permission = MemoryPermission.RW } }
///
/// Auth success / failed trigger
/// { 0xAA01000, new HwPeripheral((eng, address, size, value) }
///
fn setup_mmio<D>(emu: &mut Unicorn<D>, _elf: &ElfFile) {
    // Next boot stage mem
    emu.mem_map(0x32000000, 0x1000, Permission::READ | Permission::WRITE)
        .expect("failed to map boot stage page");

    // Code
    emu.mem_map(CODE_START, 0x20000, Permission::ALL)
        .expect("failed to map code page");

    // Stack
    emu.mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)
        .expect("failed to map stack page");

    // Auth success / failed trigger
    emu.mmio_map_wo(0xAA01000, 0x1000, mmio_auth_write_callback)
        .expect("failed to map mmio");

    // IO address space
    emu.mmio_map_wo(0x11000000, 0x1000, mmio_serial_write_callback)
        .expect("failed to map serial IO");
}

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed boot flow
///
/// { eng.RequestStop(value == 1 ? Result.Completed : Result.Failed); })
fn mmio_auth_write_callback<D>(emu: &mut Unicorn<D>, _address: u64, _size: usize, value: u64) {
    match value {
        1 => {
            RUN_STATE.store(RunState::Success as usize, Ordering::Relaxed);
            debug!("Indicator: __SET_SIM_SUCCESS()")
        }
        2 => {
            RUN_STATE.store(RunState::Failed as usize, Ordering::Relaxed);
            debug!("Indicator: __SET_SIM_FAILED()")
        }
        _ => {
            RUN_STATE.store(RunState::Error as usize, Ordering::Relaxed);
            debug!("Indicator: Wrong_Value")
        }
    }

    emu.emu_stop().expect("failed to stop");
}

/// Callback for serial mem IO write access
///
/// This IO write displays printed messages
///
fn mmio_serial_write_callback<D>(_emu: &mut Unicorn<D>, _address: u64, _size: usize, value: u64) {
    print!("{}", value as u8 as char);
}

/// Setup all breakpoints
///
/// BreakPoints
/// { binInfo.Symbols["flash_load_img"].Address }
fn setup_breakpoints<D>(emu: &mut Unicorn<D>, file_data: &ElfFile) {
    emu.add_code_hook(
        file_data.flash_load_img.st_value,
        file_data.flash_load_img.st_value + 1,
        hook_code_flash_load_img_callback,
    )
    .expect("failed to set flash_load_img code hook");
}

/// Hook for flash_load_img callback handling.
///
/// eng => {
///     var useAltData = ((MyConfig) eng.Config).UseAltData;        
///         if (useAltData) {
///             eng.Write(0x32000000, Encoding.ASCII.GetBytes("!! Pwned boot !!"));
///         }
///         else {
///             eng.Write(0x32000000, Encoding.ASCII.GetBytes("Test Payload!!!!"));
///         }
///     } },
fn hook_code_flash_load_img_callback<A>(emu: &mut Unicorn<A>, _address: u64, _size: u32) {
    if RUN_TYPE_POSITIV.load(Ordering::Relaxed) == true {
        // Write flash data to boot stage memory
        let boot_stage: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
        emu.mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    } else {
        // Write flash data to boot stage memory
        let boot_stage: [u8; 4] = [0xB8, 0x45, 0x85, 0xFD];
        emu.mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    }
    debug!("Call of flash_load_img");
}

// emu.add_mem_hook(HookType::MEM_READ, 0x1000, 0x1002, hook_read_callback)
//     .expect("failed to set memory hook");
// fn hook_write_callback<A>(
//     _emu: &mut Unicorn<A>,
//     _mem_type: MemType,
//     _address: u64,
//     _size: usize,
//     _temp: i64,
// ) -> bool {
//     println!("hook_write_callback");
//     true
// }

/*
# Check for correct system
- Prepare system
- Set state to positive run
    - Run
- Check Success_State
- Prepare system
- Set state to negative run
    - Run
- Check Failed_State

# Get address table
- Prepare system
- Set state to negative run
- Go with single step till Failed_State
    - Count Steps
    - Note all individual addresses into array

# NOP run
- Loop from Count 0..Steps
    - Prepare system
    - Set state to negative run
    - Run (Count)
        Check for ASM Cmd - 16/32 Bit
        Change to NOP
    - Run (1/2)
        Change back
    - Run till Success/Failed state
        If Success add to found list
- Repeat till end of loop

# Glitch run
- Loop from Count 0..Steps
    - Loop (16/32) according to cmd size
        - Prepare system
        - Set state to negative run
        - Run (Count)
            Check for ASM Cmd - 16/32 Bit
            Change (xor) bit in cmd
        - Run (1/2)
            Change back
        - Run till Success/Failed state
            If Success add to found list
- Repeat till end of loop

*/
