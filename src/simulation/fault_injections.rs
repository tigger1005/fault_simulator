use std::ops::Shl;

use super::{ElfFile, SimulationFaultRecord, TraceRecord};

mod callback;
use callback::*;

pub use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use unicorn_engine::{RegisterARM, Unicorn};

use log::debug;

pub const MAX_INSTRUCTIONS: usize = 2000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const BOOT_STAGE: u64 = 0x32000000;
const AUTH_BASE: u64 = 0xAA01000;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr
const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

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

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RunState {
    Init = 0,
    Success,
    Failed,
    Error,
}

struct Cpu {
    pc: u64,
}

#[derive(Clone, Copy)]
pub enum FaultType {
    Uninitialized,
    NopCached(usize),
    BitFlipCached(usize),
}

#[derive(Clone)]
pub struct FaultData {
    pub data: Vec<u8>,
    pub data_changed: Vec<u8>,
    pub address: u64,
    pub count: usize,
}

impl FaultData {
    pub fn new(address_record: SimulationFaultRecord) -> Self {
        Self {
            data: Vec::new(),
            data_changed: Vec::new(),
            address: address_record.address,
            count: 0,
        }
    }
}

pub struct FaultInjections<'a> {
    file_data: ElfFile,
    emu: Unicorn<'a, EmulationData>,
    cpu: Cpu,
    fault_data: Vec<FaultData>,
}

struct EmulationData {
    state: RunState,
    is_positiv: bool,
    print_output: bool,
}

impl<'a> FaultInjections<'a> {
    pub fn new(file_data: &ElfFile) -> Self {
        // Setup simulation data structure
        let emu_data = EmulationData {
            state: RunState::Init,
            is_positiv: true,
            print_output: true,
        };

        // Setup platform -> ARMv8-m.base
        let emu = Unicorn::new_with_data(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS, emu_data)
            .expect("failed to initialize Unicorn instance");

        // Get file data -> could also be a pointer TODO
        let temp_file_data = file_data.clone();
        Self {
            file_data: temp_file_data,
            emu,
            cpu: Cpu { pc: 0 },
            fault_data: Vec::new(),
        }
    }

    /// Initialize all required register to zero
    ///
    /// Additionally the SP is set to start of stack
    pub fn init_register(&mut self) {
        // Clear registers
        ARM_REG
            .iter()
            .for_each(|reg| self.emu.reg_write(*reg, 0x00).unwrap());

        // Setup registers
        self.emu
            .reg_write(RegisterARM::SP, STACK_BASE + STACK_SIZE as u64 - 4)
            .expect("failed to set register");
    }

    /// Load source code from elf file into simulation
    ///
    /// The PC is set to the start of the program
    pub fn load_code(&mut self) {
        self.emu
            .mem_write(
                self.file_data.program_header.p_paddr,
                &self.file_data.program,
            )
            .expect("failed to write file data");
        // set initial program start address
        self.cpu.pc = self.file_data.program_header.p_paddr;
    }

    /// Function to deactivate printf of c program to
    /// avoid unexpected output
    ///
    pub fn deactivate_printf_function(&mut self) {
        self.emu.get_data_mut().print_output = false;
        self.emu
            .mem_write(self.file_data.serial_puts.st_value & 0xfffffffe, &T1_RET)
            .unwrap();
    }

    /// Setup all breakpoints
    ///
    /// BreakPoints
    /// { binInfo.Symbols["flash_load_img"].Address }
    pub fn setup_breakpoints(&mut self) {
        self.emu
            .add_code_hook(
                self.file_data.flash_load_img.st_value,
                self.file_data.flash_load_img.st_value + 1,
                hook_code_flash_load_img_callback::<EmulationData>,
            )
            .expect("failed to set flash_load_img code hook");

        self.emu
            .add_mem_hook(
                HookType::MEM_WRITE,
                AUTH_BASE,
                AUTH_BASE + 4,
                mmio_auth_write_callback::<EmulationData>,
            )
            .expect("failed to set memory hook");
    }

    /// Setup memory mapping, stack, io mapping
    ///
    pub fn setup_mmio(&mut self) {
        const MINIMUM_MEMORY_SIZE: usize = 0x1000;
        // Next boot stage mem
        self.emu
            .mem_map(
                0x32000000,
                MINIMUM_MEMORY_SIZE,
                Permission::READ | Permission::WRITE,
            )
            .expect("failed to map boot stage page");

        // Code
        let code_size = (self.file_data.program.len() + MINIMUM_MEMORY_SIZE) & 0xfffff000;
        self.emu
            .mem_map(
                self.file_data.program_header.p_paddr,
                code_size,
                Permission::ALL,
            )
            .expect("failed to map code page");

        // Stack
        self.emu
            .mem_map(STACK_BASE, STACK_SIZE, Permission::READ | Permission::WRITE)
            .expect("failed to map stack page");

        // Auth success / failed trigger
        self.emu
            .mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Permission::WRITE)
            .expect("failed to map mmio replacement");

        // IO address space
        self.emu
            .mmio_map_wo(
                0x11000000,
                MINIMUM_MEMORY_SIZE,
                mmio_serial_write_callback::<EmulationData>,
            )
            .expect("failed to map serial IO");
    }

    /// Execute code on pc set in internal structure till cycles
    ///
    /// If debug is set to true, execution is done by single steps
    ///
    pub fn run_steps(&mut self, cycles: usize, debug: bool) -> Result<(), uc_error> {
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
            ret_val = self
                .emu
                .emu_start(self.cpu.pc | 1, end_address | 1, SECOND_SCALE, cycles);
        }
        // Store new PC
        self.cpu.pc = self.emu.pc_read().unwrap();

        ret_val
    }

    /// Set fault at specified address with given parameters
    ///
    /// Original and replaced data is stored for restauration
    /// and printing
    pub fn set_fault(&mut self, address_record: SimulationFaultRecord) {
        let mut fault_data: FaultData = FaultData::new(address_record);

        // Generate data with fault specific handling
        match address_record.fault_type {
            FaultType::NopCached(number) => {
                let mut address = address_record.address;
                for _count in 0..number {
                    let temp_size = self.get_asm_cmd_size(address).unwrap();
                    for i in 0..temp_size {
                        fault_data.data_changed.push(*T1_NOP.get(i).unwrap())
                    }
                    address += temp_size as u64;
                }
                // Set to same size as data_changed
                fault_data.data = fault_data.data_changed.clone();
                // Read original data
                self.emu
                    .mem_read(address_record.address, &mut fault_data.data)
                    .unwrap();
            }
            FaultType::BitFlipCached(pos) => {
                let temp_size = self.get_asm_cmd_size(address_record.address).unwrap();
                fault_data.data = vec![0; temp_size];
                // Read original data
                self.emu
                    .mem_read(address_record.address, &mut fault_data.data)
                    .unwrap();
                fault_data.data_changed = fault_data.data.clone();
                fault_data.data_changed[pos / 8] ^= (0x01_u8).shl(pos % 8);
            }
            _ => {
                panic!("No fault type set")
            }
        }

        // Write generated data to address
        self.emu
            .mem_write(address_record.address, &fault_data.data_changed)
            .unwrap();

        // Push to fault data vector
        self.fault_data.push(fault_data);
    }

    fn get_asm_cmd_size(&self, address: u64) -> Option<usize> {
        let mut data: [u8; 2] = [0; 2];
        // Check for 32bit cmd (0b11101... 0b1111....)
        if self.emu.mem_read(address, &mut data).is_ok() {
            if (data[1] & 0xF8 == 0xE8) || (data[1] & 0xF0 == 0xF0) {
                return Some(4);
            }
            return Some(2);
        }
        None
    }

    /// Read address_record from given address
    ///
    /// Read data from current local stored program counter pc
    pub fn get_cmd_address_record(&mut self) -> Option<(u64, TraceRecord)> {
        if let Some(size) = self.get_asm_cmd_size(self.cpu.pc) {
            return Some((self.cpu.pc, TraceRecord { size, count: 1 }));
        }
        None
    }

    /// Initialize the internal program state
    ///
    pub fn init_states(&mut self, run_state: bool) {
        // Set run type
        self.emu.get_data_mut().is_positiv = run_state;

        // Set global state to initilized
        self.emu.get_data_mut().state = RunState::Init;
    }

    /// Get current state of simulation
    ///
    pub fn get_state(&self) -> RunState {
        self.emu.get_data().state
    }

    /// Get fault_data
    pub fn get_fault_data(&self) -> &Vec<FaultData> {
        &self.fault_data
    }
}
