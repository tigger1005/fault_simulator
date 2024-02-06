use super::{ElfFile, SimulationFaultRecord, TraceRecord};

mod callback;
use callback::*;

pub use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};

use unicorn_engine::{RegisterARM, Unicorn};

use log::debug;

use std::collections::HashSet;

pub const MAX_INSTRUCTIONS: usize = 2000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const BOOT_STAGE: u64 = 0x32000000;
const AUTH_BASE: u64 = 0xAA01000;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr
const T1_NOP: [u8; 4] = [0x00, 0xBF, 0x00, 0xBF];

const ARM_REG: [RegisterARM; 17] = [
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
    RegisterARM::CPSR,
];

#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub enum RunState {
    #[default]
    Init = 0,
    Success,
    Failed,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub enum FaultType {
    //    Uninitialized,
    Glitch(usize),
    // BitFlipCached(usize),
}

#[derive(Clone, Debug)]
pub struct FaultData {
    pub data: Vec<u8>,
    pub data_changed: Vec<u8>,
    pub fault: SimulationFaultRecord,
}

impl FaultData {
    pub fn get_simulation_fault_records(
        fault_data_records: &[FaultData],
    ) -> Vec<SimulationFaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault.clone())
            .collect()
    }
}

pub struct Cpu<'a> {
    file_data: &'a ElfFile,
    emu: Unicorn<'a, CpuState>,
    program_counter: u64,
}

#[derive(Default)]
struct CpuState {
    state: RunState,
    start_trace: bool,
    with_register_data: bool,
    negative_run: bool,
    deactivate_print: bool,
    trace_data: Vec<TraceRecord>,
    fault_data: Vec<FaultData>,
}

impl<'a> Cpu<'a> {
    pub fn new(file_data: &'a ElfFile) -> Self {
        // Setup platform -> ARMv8-m.base
        let emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            CpuState::default(),
        )
        .expect("failed to initialize Unicorn instance");

        Self {
            file_data,
            emu,
            program_counter: 0,
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
        self.program_counter = self.file_data.program_header.p_paddr;

        // Write wrong flash data to boot stage memory
        let boot_stage: [u8; 4] = [0xB8, 0x45, 0x85, 0xFD];
        self.emu
            .mem_write(BOOT_STAGE, &boot_stage)
            .expect("failed to write boot stage data");
    }

    /// Function to deactivate printf of c program to
    /// avoid unexpected output
    ///
    pub fn deactivate_printf_function(&mut self) {
        self.emu.get_data_mut().deactivate_print = true;
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
                hook_code_flash_load_img_callback,
            )
            .expect("failed to set flash_load_img code hook");

        self.emu
            .add_mem_hook(
                HookType::MEM_WRITE,
                AUTH_BASE,
                AUTH_BASE + 4,
                mmio_auth_write_callback,
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
            .mmio_map_wo(0x11000000, MINIMUM_MEMORY_SIZE, mmio_serial_write_callback)
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
                //println!("Executing address : 0x{:X}", self.emu.get_data().program_counter);
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
                self.program_counter | 1,
                end_address | 1,
                SECOND_SCALE,
                cycles,
            );
        }
        // Store new PC
        self.program_counter = self.emu.pc_read().unwrap();

        ret_val
    }

    /// Generate fault injection data record and add it to internal fault vector
    ///
    /// Original and replaced data is stored for restauration
    /// and printing
    pub fn set_fault(&mut self, record: &SimulationFaultRecord) {
        let mut fault_data_entry = FaultData {
            data: Vec::new(),
            data_changed: Vec::new(),
            fault: record.clone(),
        };
        // Generate data with fault specific handling
        match fault_data_entry.fault.fault_type {
            FaultType::Glitch(number) => {
                fault_data_entry.fault.record.size = 0;
                let mut address = fault_data_entry.fault.record.address;
                for _count in 0..number {
                    let temp_size = self.get_asm_cmd_size(address).unwrap();
                    for i in 0..temp_size {
                        fault_data_entry.data_changed.push(*T1_NOP.get(i).unwrap())
                    }
                    address += temp_size as u64;
                    fault_data_entry.fault.record.size += temp_size;
                }
                // Set to same size as data_changed
                fault_data_entry.data = fault_data_entry.data_changed.clone();
                // Read original data
                self.emu
                    .mem_read(
                        fault_data_entry.fault.record.address,
                        &mut fault_data_entry.data,
                    )
                    .unwrap();
            }
        }
        // Push to fault data vector
        self.emu.get_data_mut().fault_data.push(fault_data_entry);
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

    /// Initialize the internal program state
    ///
    pub fn init_states(&mut self, run_state: bool) {
        // Set run type
        self.emu.get_data_mut().negative_run = !run_state;

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
        &self.emu.get_data().fault_data
    }

    /// Set code hook for tracing
    ///
    pub fn set_trace_hook(&mut self) {
        self.emu
            .add_code_hook(
                self.file_data.program_header.p_paddr,
                self.file_data.program_header.p_memsz,
                hook_code_callback,
            )
            .expect("failed to setup trace hook");
    }

    pub fn start_tracing(&mut self, with_register_data: bool) {
        let cpu_state = self.emu.get_data_mut();
        cpu_state.with_register_data = with_register_data;
        cpu_state.start_trace = true;
    }

    /// Release hook function and all stored data in internal structure
    ///
    pub fn release_usage_fault_hooks(&mut self) {
        // Remove hooks from list
        self.emu.get_data_mut().fault_data.clear();
    }

    /// Copy trace data to caller
    pub fn get_trace(&self) -> &Vec<TraceRecord> {
        &self.emu.get_data().trace_data
    }

    /// Remove duplicates to speed up testing
    pub fn reduce_trace(&mut self) {
        let trace_data = &mut self.emu.get_data_mut().trace_data;
        let hash_set: HashSet<TraceRecord> = HashSet::from_iter(trace_data.clone());
        *trace_data = Vec::from_iter(hash_set);
    }

    pub fn add_to_trace(&mut self, fault: &FaultData) {
        let mut record = TraceRecord {
            size: fault.fault.record.size,
            address: fault.fault.record.address,
            asm_instruction: fault.data_changed.clone(),
            registers: None,
        };

        let mut registers: [u32; 17] = [0; 17];
        ARM_REG.iter().enumerate().for_each(|(index, register)| {
            registers[index] = self.emu.reg_read(*register).unwrap() as u32;
        });
        record.registers = Some(registers);
        // Record data
        self.emu.get_data_mut().trace_data.push(record);
    }

    /// Execute fault injection according to fault type
    /// Program is stopped and will be continued after fault injection
    ///
    pub fn execute_fault_injection(&mut self, fault: &FaultData) {
        match fault.fault.fault_type {
            FaultType::Glitch(_) => {
                self.program_counter += fault.fault.record.size as u64;
            }
        }
    }
}
