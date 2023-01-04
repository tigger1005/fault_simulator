use log::debug;

use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

mod elf_file;
use elf_file::ElfFile;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr
const T1_NOP: [u8; 2] = [0x00, 0xBF];

const MAX_INSTRUCTIONS: usize = 20000000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const BOOT_STAGE: u64 = 0x32000000;

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

#[derive(PartialEq, Debug)]
enum RunState {
    Init = 0,
    Success,
    Failed,
    Error,
}

struct SimulationData {
    state: RunState,
    is_positiv: bool,
}

pub struct Simulation<'a> {
    file_data: ElfFile,
    emu: Unicorn<'a, SimulationData>,
}

impl<'a> Simulation<'a> {
    pub fn new(path: std::path::PathBuf) -> Self {
        // Setup simulation data structure
        let simulation_data = SimulationData {
            state: RunState::Init,
            is_positiv: true,
        };
        // Load elf file
        let file_data: ElfFile = ElfFile::new(path);
        // Setup platform -> ARMv8-m.base
        let emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            simulation_data,
        )
        .expect("failed to initialize Unicorn instance");
        //let emu = &mut unicorn;

        Self { file_data, emu }
    }

    pub fn setup_simulation(&mut self) {
        // Setup memory and IO
        self.setup_mmio();

        // Setup breakpoints
        self.setup_breakpoints();
    }

    pub fn check_simulation(&mut self) {
        // Run simulation
        self.run_simulation(true);
        assert_eq!(self.emu.get_data().state, RunState::Success);

        self.run_simulation(false);
        assert_eq!(self.emu.get_data().state, RunState::Failed);
    }

    fn run_simulation(&mut self, run_successful: bool) {
        // Clear registers
        ARM_REG
            .iter()
            .for_each(|reg| self.emu.reg_write(*reg, 0x00).unwrap());

        // Setup registers
        self.emu
            .reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
            .expect("failed to set register");

        // Write code to memory area
        self.emu
            .mem_write(
                self.file_data.program_header.p_paddr as u64,
                &self.file_data.program,
            )
            .expect("failed to write file data");

        // Set run type
        self.emu.get_data_mut().is_positiv = run_successful;

        // Set global state to initilized
        self.emu.get_data_mut().state = RunState::Init;

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

        let ret_info = self.emu.emu_start(
            (self.file_data.program_header.p_paddr + 1) as u64,
            (self.file_data.program_header.p_paddr + self.file_data.program_header.p_filesz + 1)
                as u64,
            SECOND_SCALE,
            MAX_INSTRUCTIONS,
        );
        if ret_info == Ok(()) {
            debug!("Program stopped successful");
        } else {
            debug!("Program stopped with {:?}", ret_info);
            self.emu.get_data_mut().state = RunState::Error;
        }
        //print_register_and_data(emu);
    }

    fn print_register_and_data(&self) {
        println!(
            "Register R4 : 0x{:X}",
            self.emu.reg_read(RegisterARM::R4).unwrap()
        );
        println!(
            "Register R7 : 0x{:X}",
            self.emu.reg_read(RegisterARM::R7).unwrap()
        );
        println!(
            "Register LR : 0x{:X}",
            self.emu.reg_read(RegisterARM::LR).unwrap()
        );
        println!(
            "Register SP : 0x{:X}",
            self.emu.reg_read(RegisterARM::SP).unwrap()
        );

        let pc = self.emu.reg_read(RegisterARM::PC).unwrap();

        let mut data: [u8; 10] = [0; 10];
        self.emu.mem_read(pc, &mut data).expect("Read memory");
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
    fn setup_mmio(&mut self) {
        // Next boot stage mem
        self.emu
            .mem_map(0x32000000, 0x1000, Permission::READ | Permission::WRITE)
            .expect("failed to map boot stage page");

        // Code
        self.emu
            .mem_map(
                self.file_data.program_header.p_paddr,
                0x20000,
                Permission::ALL,
            )
            .expect("failed to map code page");

        // Stack
        self.emu
            .mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)
            .expect("failed to map stack page");

        // Auth success / failed trigger
        self.emu
            .mmio_map_wo(
                0xAA01000,
                0x1000,
                mmio_auth_write_callback::<SimulationData>,
            )
            .expect("failed to map mmio");

        // IO address space
        self.emu
            .mmio_map_wo(
                0x11000000,
                0x1000,
                mmio_serial_write_callback::<SimulationData>,
            )
            .expect("failed to map serial IO");
    }

    /// Setup all breakpoints
    ///
    /// BreakPoints
    /// { binInfo.Symbols["flash_load_img"].Address }
    fn setup_breakpoints(&mut self) {
        self.emu
            .add_code_hook(
                self.file_data.flash_load_img.st_value,
                self.file_data.flash_load_img.st_value + 1,
                hook_code_flash_load_img_callback::<SimulationData>,
            )
            .expect("failed to set flash_load_img code hook");

        // emu.add_mem_hook(HookType::MEM_READ, 0x1000, 0x1002, hook_read_callback)
        //     .expect("failed to set memory hook");
    }
}

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed boot flow
///
/// { eng.RequestStop(value == 1 ? Result.Completed : Result.Failed); })
fn mmio_auth_write_callback<D>(
    emu: &mut Unicorn<SimulationData>,
    _address: u64,
    _size: usize,
    value: u64,
) {
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
}

/// Callback for serial mem IO write access
///
/// This IO write displays printed messages
///
fn mmio_serial_write_callback<D>(
    _emu: &mut Unicorn<SimulationData>,
    _address: u64,
    _size: usize,
    value: u64,
) {
    print!("{}", value as u8 as char);
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
fn hook_code_flash_load_img_callback<D>(
    emu: &mut Unicorn<SimulationData>,
    _address: u64,
    _size: u32,
) {
    if emu.get_data_mut().is_positiv == true {
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
