use log::debug;

use unicorn_engine::unicorn_const::{
    uc_error, Arch, HookType, MemType, Mode, Permission, SECOND_SCALE,
};
use unicorn_engine::{RegisterARM, Unicorn};

use crate::elf_file::ElfFile;

use std::collections::HashMap;
use std::ops::Shl;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr
const T1_NOP: [u8; 2] = [0x00, 0xBF];

const MAX_INSTRUCTIONS: usize = 2000;
const STACK_BASE: u64 = 0x80100000;
const STACK_SIZE: usize = 0x10000;
const BOOT_STAGE: u64 = 0x32000000;
const AUTH_BASE: u64 = 0xAA01000;

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
    pub size: usize,
}

#[derive(Clone, Copy)]
pub enum FaultType {
    Uninitialized,
    NopCached,
    BitFlipCached(usize),
}

#[derive(Copy, Clone)]
pub struct AddressRecord {
    size: usize,
    count: usize,
}

#[derive(Clone, Copy)]
pub struct ExternalRecord {
    pub address: u64,
    pub size: usize,
    pub count: usize,
    pub fault_type: FaultType,
}

impl ExternalRecord {
    pub fn new(record_map: HashMap<u64, AddressRecord>) -> Vec<ExternalRecord> {
        let mut list: Vec<ExternalRecord> = Vec::new();
        record_map.iter().for_each(|record| {
            list.push(ExternalRecord {
                address: *record.0,
                size: record.1.size,
                count: record.1.count,
                fault_type: FaultType::Uninitialized,
            });
        });

        list
    }
    pub fn set_fault_type(&mut self, fault_type: FaultType) {
        self.fault_type = fault_type;
    }
}

struct SimulationData {
    state: RunState,
    is_positiv: bool,
    cpu: Cpu,
    fault_data: Vec<FaultData>,
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
            fault_data: Vec::new(),
            print_output: true,
        };

        // Setup platform -> ARMv8-m.base
        let emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            simulation_data,
        )
        .expect("failed to initialize Unicorn instance");

        // Setup emulator
        let mut simulation: Simulation = Simulation { file_data, emu };
        simulation.setup();

        simulation
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

    fn get_cmd_address_record(&mut self, address: u64) -> Option<(u64, AddressRecord)> {
        let mut data: [u8; 2] = [0; 2];

        self.set_start_address(address);

        if self
            .emu
            .mem_read(self.emu.get_data().cpu.pc, &mut data)
            .is_ok()
        {
            let mut size = 2;
            // Check for 32bit cmd (0b11101... 0b1111....)
            if (data[1] & 0xF8 == 0xE8) || (data[1] & 0xF0 == 0xF0) {
                size = 4;
            }
            return Some((address, AddressRecord { size, count: 1 }));
        }
        None
    }

    pub fn get_address_list(
        &mut self,
        external_record: Vec<ExternalRecord>,
    ) -> Vec<ExternalRecord> {
        //
        let mut address_list = HashMap::new();
        // Initialize and load
        self.init_and_load(false);
        // Deactivate io print
        self.emu.get_data_mut().print_output = false;
        self.deactivate_printf_function();

        let (adr, rec) = self
            .get_cmd_address_record(self.file_data.program_header.p_paddr)
            .unwrap();
        address_list.insert(adr, rec);

        // Insert nop
        external_record
            .iter()
            .for_each(|record| self.set_fault(*record));

        let mut cycles: usize = 0;

        let mut ret_val = Ok(());
        while ret_val == Ok(()) {
            //println!("Executing address : 0x{:X}", self.emu.get_data().cpu.pc);
            ret_val = self.run_steps(1, false);
            if ret_val != Ok(()) {
                break;
            }
            cycles += 1;
            if cycles > MAX_INSTRUCTIONS {
                break;
            }

            // debug!("PC : 0x{:X}", pc);
            if let Some((adr, rec)) = self.get_cmd_address_record(self.emu.get_data().cpu.pc) {
                address_list
                    .entry(adr)
                    .and_modify(|record| record.count += 1)
                    .or_insert(rec);
            } else {
                break;
            }

            if self.emu.get_data().state == RunState::Failed {
                // debug!("Stoped on Failed marker");
                break;
            }
        }
        debug!("Return : {:?}", ret_val);

        self.emu.get_data_mut().cpu.cycles = cycles;
        debug!("Cycles : {}", self.emu.get_data().cpu.cycles);
        address_list.iter().for_each(|rec| {
            debug!(
                "Address: 0x{:X} count {}, size {}",
                rec.0, rec.1.count, rec.1.size
            )
        });

        ExternalRecord::new(address_list)
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

    // pub fn print_memory(&self, address: u64, size: usize) {
    //     let data = self.emu.mem_read_as_vec(address, size).unwrap();
    //     println!("Memory at 0x{:X}", address);
    //     data.iter().for_each(|x| print!("0x{:X} ", x));
    //     println!("");
    // }

    fn deactivate_printf_function(&mut self) {
        self.emu
            .mem_write(self.file_data.serial_puts.st_value & 0xfffffffe, &T1_RET)
            .unwrap();
    }

    pub fn run_with_faults(
        &mut self,
        external_record: Vec<ExternalRecord>,
    ) -> Option<Vec<FaultData>> {
        self.init_and_load(false);
        // Deactivate io print
        self.emu.get_data_mut().print_output = false;
        self.deactivate_printf_function();
        // set initial program start address
        self.set_start_address(self.file_data.program_header.p_paddr);
        // Set nop
        external_record
            .iter()
            .for_each(|record| self.set_fault(*record));
        // Run
        let _ret_val = self.run_steps(MAX_INSTRUCTIONS, false);
        if self.emu.get_data().state == RunState::Success {
            return Some(self.get_fault_data());
        }
        None
    }

    pub fn get_fault_data(&self) -> Vec<FaultData> {
        self.emu.get_data().fault_data.clone()
    }

    /// Set fault at specified address with given parameters
    ///
    /// Original and replaced data is stored for restauration
    /// and printing
    fn set_fault(&mut self, address_record: ExternalRecord) {
        let mut context: FaultData = FaultData {
            data: [0; 4],
            data_changed: [0; 4],
            address: address_record.address,
            size: address_record.size,
        };
        // Read original data
        self.emu
            .mem_read(address_record.address, &mut context.data)
            .unwrap();

        // Generate data with fault specific handling
        match address_record.fault_type {
            FaultType::NopCached => {
                context.data_changed[0..2].copy_from_slice(&T1_NOP);
                if address_record.size == 4 {
                    context.data_changed[2..4].copy_from_slice(&T1_NOP);
                } else {
                    context.data_changed[2..4].copy_from_slice(&context.data[2..4]);
                }
            }
            FaultType::BitFlipCached(pos) => {
                context.data_changed = context.data;
                context.data_changed[pos / 8] ^= (0x01_u8).shl(pos % 8);
            }
            _ => {
                panic!("No fault type set")
            }
        }

        self.emu.get_data_mut().fault_data.push(context);

        // Write generated data to address
        self.emu
            .mem_write(address_record.address, &context.data_changed)
            .unwrap();
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

            // let origin = panic::take_hook();
            // panic::set_hook(Box::new(|_info| {}));
            // let ret_val = panic::catch_unwind(|| {
            //     self.emu.emu_start(
            //         self.emu.get_data().cpu.pc | 1,
            //         end_address | 1,
            //         SECOND_SCALE,
            //         cycles,
            //     );
            // });
            // let _ = panic::take_hook();

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
                self.file_data.program_header.p_paddr,
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

    // fn print_register_and_data(&self) {
    //     ARM_REG.iter().for_each(|reg| {
    //         println!(
    //             "Register {:?} : 0x{:X}",
    //             reg,
    //             self.emu.reg_read(RegisterARM::R4).unwrap()
    //         )
    //     });

    //     let pc = self.emu.reg_read(RegisterARM::PC).unwrap();
    //     let mut data: [u8; 10] = [0; 10];
    //     self.emu.mem_read(pc, &mut data).expect("Read memory");
    //     println!("Code: {:?}", data);
    // }

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
        // self.emu
        //     .mmio_map_wo(
        //         0xAA01000,
        //         0x1000,
        //         mmio_auth_write_callback::<SimulationData>,
        //     )
        //     .expect("failed to map mmio");
        self.emu
            .mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Permission::WRITE)
            .expect("failed to map mmio replacement");

        // IO address space
        self.emu
            .mmio_map_wo(
                0x11000000,
                MINIMUM_MEMORY_SIZE,
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

        self.emu
            .add_mem_hook(
                HookType::MEM_WRITE,
                AUTH_BASE,
                AUTH_BASE + 4,
                mmio_auth_write_callback::<SimulationData>,
            )
            .expect("failed to set memory hook");
    }
}

/// Callback for auth mem IO write access
///
/// This IO call signalize the Successful or Failed boot flow
///
/// { eng.RequestStop(value == 1 ? Result.Completed : Result.Failed); })
// fn mmio_auth_write_callback<D>(
//     emu: &mut Unicorn<SimulationData>,
//     _address: u64,
//     _size: usize,
//     value: u64,
// ) {
//     match value {
//         1 => {
//             emu.get_data_mut().state = RunState::Success;
//             debug!("Indicator: __SET_SIM_SUCCESS()")
//         }
//         2 => {
//             emu.get_data_mut().state = RunState::Failed;
//             debug!("Indicator: __SET_SIM_FAILED()")
//         }
//         _ => {
//             emu.get_data_mut().state = RunState::Error;
//             debug!("Indicator: Wrong_Value")
//         }
//     }

//     emu.emu_stop().expect("failed to stop");
// }
fn mmio_auth_write_callback<D>(
    emu: &mut Unicorn<SimulationData>,
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
///
fn mmio_serial_write_callback<D>(
    emu: &mut Unicorn<SimulationData>,
    _address: u64,
    _size: usize,
    value: u64,
) {
    if emu.get_data().print_output {
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
    if emu.get_data_mut().is_positiv {
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
