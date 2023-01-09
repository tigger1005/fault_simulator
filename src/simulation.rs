use log::debug;

use unicorn_engine::unicorn_const::{uc_error, Arch, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

use crate::elf_file::ElfFile;

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

struct Cpu {
    cycles: usize,
    pc: u64,
}

#[derive(Copy, Clone)]
pub struct FaultData {
    pub data: [u8; 4],
    pub data_changed: [u8; 4],
    pub address: u64,
}

struct SimulationData {
    state: RunState,
    is_positiv: bool,
    cpu: Cpu,
    fault_data: Option<FaultData>,
    print_output: bool,
}

pub struct Simulation<'a> {
    file_data: &'a ElfFile,
    emu: Unicorn<'a, SimulationData>,
}

impl<'a> Simulation<'a> {
    pub fn new(file_data: &'a ElfFile) -> Self {
        // Setup simulation data structure
        let simulation_data = SimulationData {
            state: RunState::Init,
            is_positiv: true,
            cpu: Cpu { cycles: 0, pc: 0 },
            fault_data: None,
            print_output: true,
        };

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

    pub fn setup(&mut self) {
        // Setup memory and IO
        self.setup_mmio();

        // Setup breakpoints
        self.setup_breakpoints();
    }

    pub fn check(&mut self) {
        // Run simulation
        self.run(true);
        assert_eq!(self.emu.get_data().state, RunState::Success);

        self.run(false);
        assert_eq!(self.emu.get_data().state, RunState::Failed);
    }

    pub fn init_and_load(&mut self, run_successful: bool) {
        self.init_register();
        // Write code to memory area
        self.load_code();
        // Init state
        self.init_states(run_successful);
    }

    pub fn get_address_list(&mut self) -> Vec<u64> {
        //
        let mut address_list: Vec<u64> = Vec::new();
        // Initialize and load
        self.init_and_load(false);
        // Deactivate io print
        self.emu
            .mem_write(self.file_data.serial_puts.st_value & 0xfffffffe, &T1_RET)
            .unwrap();

        self.set_start_address(self.file_data.program_header.p_paddr);
        address_list.push(self.emu.get_data().cpu.pc);

        let mut cycles: usize = 0;

        let mut ret_val = Ok(());
        while ret_val == Ok(()) {
            //println!("Executing address : 0x{:X}", self.emu.get_data().cpu.pc);
            ret_val = self.run_steps(1, false);
            if ret_val == Ok(()) {
                cycles += 1;
            }
            // debug!("PC : 0x{:X}", pc);
            address_list.push(self.emu.get_data().cpu.pc);
            if self.emu.get_data().state == RunState::Failed {
                // debug!("Stoped on Failed marker");
                break;
            }
        }
        debug!("Return : {:?}", ret_val);

        self.emu.get_data_mut().cpu.cycles = cycles;
        debug!("Cycles : {}", self.emu.get_data().cpu.cycles);
        address_list
            .iter()
            .for_each(|adr| debug!("Address: 0x{:X}", adr));

        address_list
    }

    fn run(&mut self, run_successful: bool) {
        let ret_info = self.run_till(run_successful, MAX_INSTRUCTIONS);

        if ret_info == Ok(()) {
            debug!("Program stopped successful");
        } else {
            debug!("Program stopped with {:?}", ret_info);
            self.emu.get_data_mut().state = RunState::Error;
        }
        //print_register_and_data(emu);
    }

    pub fn run_till(&mut self, run_successful: bool, steps: usize) -> Result<(), uc_error> {
        self.init_and_load(run_successful);
        // Start execution
        debug!("Run : {} Steps", steps);
        self.set_start_address(self.file_data.program_header.p_paddr);
        self.run_steps(steps, false)
    }

    pub fn print_memory(&self, address: u64, size: usize) {
        let data = self.emu.mem_read_as_vec(address, size).unwrap();
        println!("Memory at 0x{:X}", address);
        data.iter().for_each(|x| print!("0x{:X} ", x));
        println!("");
    }

    pub fn run_with_nop(&mut self, address: u64) -> Option<FaultData> {
        self.init_and_load(false);
        // Deactivate io print
        self.emu.get_data_mut().print_output = false;
        self.emu
            .mem_write(self.file_data.serial_puts.st_value & 0xfffffffe, &T1_RET)
            .unwrap();
        // set initial program start address
        self.set_start_address(self.file_data.program_header.p_paddr);
        // Set nop
        self.set_nop(address);
        // Run
        let _ret_val = self.run_steps(MAX_INSTRUCTIONS, false);
        if self.emu.get_data().state == RunState::Success {
            return self.emu.get_data().fault_data;
        }
        return None;
    }

    pub fn steps(&self) -> usize {
        self.emu.get_data().cpu.cycles
    }

    /// Set nop at specified address
    ///
    /// If initial value is 32 bit two nops are placed
    /// Overwritten data is stored for restauration
    fn set_nop(&mut self, address: u64) {
        let mut nop_context: FaultData = FaultData {
            data: [0; 4],
            data_changed: [0; 4],
            address,
        };
        self.emu.mem_read(address, &mut nop_context.data).unwrap();
        self.emu.get_data_mut().fault_data = Some(nop_context).clone();

        // Check for 32bit cmd (0b11101... 0b1111....)
        if (nop_context.data[1] & 0xF8 == 0xE8) || (nop_context.data[1] & 0xF0 == 0xF0) {
            nop_context.data[2..4].copy_from_slice(&T1_NOP);
        }
        nop_context.data[0..2].copy_from_slice(&T1_NOP);
        // Write back
        self.emu.mem_write(address, &nop_context.data).unwrap();
    }

    fn set_nop_at_pc(&mut self) {
        self.set_nop(self.emu.get_data().cpu.pc);
    }

    fn restore(&mut self) {
        let context = self.emu.get_data().fault_data.unwrap();
        self.emu.mem_write(context.address, &context.data).unwrap();
        self.emu.get_data_mut().fault_data = None;
    }

    pub fn set_start_address(&mut self, address: u64) {
        self.emu.get_data_mut().cpu.pc = address;
    }

    fn run_steps(&mut self, cycles: usize, debug: bool) -> Result<(), uc_error> {
        let mut ret_val;
        if debug {
            let mut cyc = cycles;
            ret_val = Ok(());
            while ret_val == Ok(()) && cyc != 0 {
                //println!("Executing address : 0x{:X}", self.emu.get_data().cpu.pc);
                ret_val = self.run_steps(1, false);
                cyc -= 1;
                println!("PC : 0x{:X}", self.emu.pc_read().unwrap());
                if self.emu.get_data().state != RunState::Init {
                    println!("Stopped on marker: {:?}", self.emu.get_data().state);
                    break;
                }
            }
        } else {
            let end_address =
                self.file_data.program_header.p_paddr + self.file_data.program_header.p_filesz;

            // Start from last PC
            ret_val = self.emu.emu_start(
                self.emu.get_data().cpu.pc | 1,
                end_address | 1,
                SECOND_SCALE,
                cycles,
            );
            debug!("Started at: 0x{:X}", self.emu.get_data().cpu.pc);
            debug!(
                "Stopped at: 0x{:X} with marker: {:?} and {:?}",
                self.emu.pc_read().unwrap(),
                self.emu.get_data().state,
                ret_val
            );
        } // Store new PC
        self.set_start_address(self.emu.pc_read().unwrap());

        ret_val
    }

    fn init_states(&mut self, run_state: bool) {
        // Set run type
        self.emu.get_data_mut().is_positiv = run_state;

        // Set global state to initilized
        self.emu.get_data_mut().state = RunState::Init;
    }

    fn load_code(&mut self) {
        self.emu
            .mem_write(
                self.file_data.program_header.p_paddr as u64,
                &self.file_data.program,
            )
            .expect("failed to write file data");
    }

    fn init_register(&mut self) {
        // Clear registers
        ARM_REG
            .iter()
            .for_each(|reg| self.emu.reg_write(*reg, 0x00).unwrap());

        // Setup registers
        self.emu
            .reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
            .expect("failed to set register");
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
    emu: &mut Unicorn<SimulationData>,
    _address: u64,
    _size: usize,
    value: u64,
) {
    if emu.get_data().print_output == true {
        print!("{}", value as u8 as char);
    }
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
