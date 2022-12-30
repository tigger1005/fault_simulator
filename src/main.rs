//use std::mem;

use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
//use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

//use elf::hash::sysv_hash;
//use elf::note::Note;
//use elf::note::NoteGnuBuildId;

// use elf::endian::AnyEndian;
// use elf::section::SectionHeader;
// use elf::ElfBytes;

use elfy::Elf;
//use elfy::{Section, SectionData, SectionFlags, SectionType};

//const MAX_INSTRUCTIONS: usize = 20000000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const CODE_START: u64 = 0x80000000;
const BOOT_STAGE: u64 = 0x32000000;

// Patches = {
//     { binInfo.Symbols["serial_putc"].Address, AArch32Info.A32_RET },
// },

fn main() {
    // Load elf file
    let elf = open_elf_file();
    let elf_file = elf.segments().next().unwrap();
    // Elf file header data
    let file_address = elf_file.header().physical_address();

    // Setup platform -> ARMv8-m.base
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS)
        .expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    // Setup memory and IO
    setup_mmio(emu, &elf);

    // Setup breakpoints
    setup_breakpoints(emu, &elf);

    // Setup registers
    emu.reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
        .expect("failed to set register");

    // Write code to memory area
    emu.mem_write(file_address as u64, &elf_file.data())
        .expect("failed to write file data");

    // Write flash data to boot stage memory
    let boot_stage: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
    emu.mem_write(BOOT_STAGE, &boot_stage)
        .expect("failed to write boot stage data");

    // Start execution
    println!("Start program");

    let mut pc: u64 = file_address as u64;
    for _i in 0..200 {
        //println!("Executing address : 0x{:X}", pc);

        emu.emu_start(
            pc + 1,
            (file_address + elf_file.data().len() + 1) as u64,
            0,
            1,
        )
        .expect("failed to run program");

        pc = emu.reg_read(RegisterARM::PC).unwrap();
    }
    println!("Program stopped");

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
fn setup_mmio<D>(emu: &mut Unicorn<D>, _elf: &Elf) {
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
fn mmio_auth_write_callback<D>(_emu: &mut Unicorn<D>, address: u64, size: usize, value: u64) {
    println!(
        "mmio_write_callback address 0x{:X} length 0x{:X} value 0x{:X}",
        address, size, value
    );
}

/// Callback for serial mem IO write access
///
/// This IO write displays printed messages
///
fn mmio_serial_write_callback<D>(_emu: &mut Unicorn<D>, address: u64, size: usize, value: u64) {
    print!("{}", value as u8 as char);
}

/// Setup all breakpoints
///
/// BreakPoints
/// { binInfo.Symbols["flash_load_img"].Address }
fn setup_breakpoints<D>(emu: &mut Unicorn<D>, _elf: &Elf) {
    emu.add_code_hook(0x1006, 0x1008, hook_code_flash_load_img_callback)
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
fn hook_code_flash_load_img_callback<A>(_emu: &mut Unicorn<A>, address: u64, size: u32) {
    println!(
        "hook_code_callback address 0x{:X} with length of 0x{}",
        address, size
    );
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

// assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
// assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));

fn open_elf_file() -> Elf {
    let elf = Elf::load("Content/bin/aarch32/bl1.elf").expect("Something went wrong!");
    // Get first element (Header + Data)
    let elf_file = elf.segments().next().unwrap();
    // Check main assets
    let header = elf_file.header();
    assert_eq!(
        header.program_header_type(),
        elfy::types::ProgramHeaderType::Loadable
    );
    assert_eq!(
        header.flags(),
        elfy::types::ProgramHeaderFlags::ReadWriteExecute
    );
    assert_eq!(header.alignment().unwrap(), 4);
    // Check addresses
    let physical_address = header.physical_address();
    let virtual_address = header.virtual_address();
    assert_eq!(physical_address, virtual_address);

    // Check file size
    let file_size = header.file_size();
    let memory_size = header.memory_size();
    assert_eq!(file_size, memory_size);

    elf
}
