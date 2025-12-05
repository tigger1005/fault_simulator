use crate::elf_file::{ElfFile, PF_R, PF_W, PF_X};
use crate::simulation::{
    record::{FaultRecord, TraceRecord},
    FaultElement, TraceElement,
};

mod callback;

use callback::{
    capture_memory_errors, hook_code_callback, hook_code_decision_activation_callback,
    hook_custom_addresses_callback, mmio_auth_write_callback, mmio_serial_write_callback,
};

use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot, SECOND_SCALE};
use unicorn_engine::{Context, RegisterARM, Unicorn};

use log::debug;
use std::collections::{HashMap, HashSet};

// Constant variable definitions
const AUTH_BASE: u64 = 0xAA01000;

const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr

pub const ARM_REG: [RegisterARM; 17] = [
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

/// Struct representing the CPU for the simulation.
pub struct Cpu<'a> {
    emu: Unicorn<'a, CpuState<'a>>,
    program_counter: u64,
    cpu_context: Context,
    initial_registers: HashMap<RegisterARM, u64>,
}

struct CpuState<'a> {
    state: RunState,
    start_trace: bool,
    with_register_data: bool,
    negative_run: bool,
    deactivate_print: bool,
    print_unicorn_errors: bool,
    trace_data: TraceElement,
    fault_data: FaultElement,
    file_data: &'a ElfFile,
    success_addresses: Vec<u64>,
    failure_addresses: Vec<u64>,
}

impl<'a> Cpu<'a> {
    /// Creates a new `Cpu` instance.
    ///
    /// # Arguments
    ///
    /// * `file_data` - The ELF file data.
    /// * `success_addresses` - List of memory addresses that indicate success when executed.
    /// * `failure_addresses` - List of memory addresses that indicate failure when executed.
    /// * `initial_registers` - HashMap of RegisterARM to initial values.
    ///
    /// # Returns
    ///
    /// * `Self` - Returns a `Cpu` instance.
    pub fn new(
        file_data: &'a ElfFile,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: HashMap<RegisterARM, u64>,
    ) -> Self {
        // Setup platform -> ARMv8-m.base
        let emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            CpuState {
                state: Default::default(),
                start_trace: false,
                with_register_data: false,
                negative_run: false,
                deactivate_print: false,
                print_unicorn_errors: true,
                trace_data: Vec::new(),
                fault_data: Vec::new(),
                file_data,
                success_addresses,
                failure_addresses,
            },
        )
        .expect("failed to initialize Unicorn instance");

        // Get inital context
        let cpu_context = emu.context_init().unwrap();

        debug!("Setup new unicorn instance");
        Self {
            emu,
            program_counter: 0,
            cpu_context,
            initial_registers,
        }
    }

    /// Initialize all required register to zero or custom values
    ///
    /// Additionally the SP is set to start of stack
    pub fn init_register(&mut self) {
        // Clear all registers first
        ARM_REG
            .iter()
            .for_each(|reg| self.emu.reg_write(*reg, 0x00).unwrap());

        // Setup stack pointer (if .stack section exists)
        if let Some(stack) = self.emu.get_data().file_data.section_map.get(".stack") {
            self.emu
                .reg_write(RegisterARM::SP, stack.sh_addr + stack.sh_size)
                .expect("failed to set register");
        }

        // Set initial program start address (default from ELF)
        self.program_counter = self.emu.get_data().file_data.header.e_entry;

        // Apply custom register values (these can override the defaults above)
        for (&register, &value) in &self.initial_registers {
            self.emu
                .reg_write(register, value)
                .unwrap_or_else(|_| panic!("Failed to set register {:?}", register));

            // If PC is being set via initial_registers, update our internal program_counter too
            if register == RegisterARM::PC {
                self.program_counter = value;
            }
        }
    }

    /// Load source code from elf file into simulation
    pub fn load_code(&mut self) {
        let program_parts = &self.emu.get_data().file_data.program_data;

        // Iterate over all program parts and write them to memory
        // Use virtual address (p_vaddr) for ARM Cortex-M flat memory model
        for part in program_parts {
            self.emu
                .mem_write(part.0.p_vaddr, &part.1)
                .expect("failed to write program data");
        }
    }

    /// Function to deactivate printf of c program to
    /// avoid unexpected output
    pub fn deactivate_printf_function(&mut self) {
        self.emu.get_data_mut().deactivate_print = true;

        if let Some(serial_puts) = self.emu.get_data().file_data.symbol_map.get("serial_puts") {
            self.emu
                .mem_write(serial_puts.st_value & 0xfffffffe, &T1_RET)
                .unwrap();
        }
    }

    /// Enable or disable error printing
    pub fn set_print_errors(&mut self, print_unicorn_errors: bool) {
        self.emu.get_data_mut().print_unicorn_errors = print_unicorn_errors;
    }

    /// Get the current print_unicorn_errors setting
    pub fn get_print_errors(&self) -> bool {
        self.emu.get_data().print_unicorn_errors
    }

    /// Setup all breakpoints
    ///
    /// BreakPoints
    /// { binInfo.Symbols["decision_activation"].Address }
    pub fn setup_breakpoints(&mut self, decision_activation_active: bool) {
        // Setup decision_activation code hook
        if decision_activation_active {
            if let Some(decision_activation) = self
                .emu
                .get_data()
                .file_data
                .symbol_map
                .get("decision_activation")
            {
                self.emu
                    .add_code_hook(
                        decision_activation.st_value,
                        decision_activation.st_value + 1,
                        hook_code_decision_activation_callback,
                    )
                    .expect("failed to set decision_activation code hook");
            }
        }

        // Set up code hooks for custom success/failure addresses (if any provided)
        let has_custom_addresses = !self.emu.get_data().success_addresses.is_empty()
            || !self.emu.get_data().failure_addresses.is_empty();
        if has_custom_addresses {
            // Add code hook for all program segments to check for custom addresses
            // Use virtual addresses (p_vaddr) for ARM Cortex-M flat memory model
            let program_data = &self.emu.get_data().file_data.program_data.clone();
            for segment in program_data {
                self.emu
                    .add_code_hook(
                        segment.0.p_vaddr,
                        segment.0.p_vaddr + segment.0.p_memsz,
                        hook_custom_addresses_callback,
                    )
                    .expect("failed to set custom address code hook");
            }
        } else {
            // Only set up the MMIO hook when NOT using custom addresses
            self.emu
                .add_mem_hook(
                    HookType::MEM_WRITE,
                    AUTH_BASE,
                    AUTH_BASE + 4,
                    mmio_auth_write_callback,
                )
                .expect("failed to set memory hook");
        }
    }

    /// Setup memory mapping, stack, io mapping
    pub fn setup_mmio(&mut self, memory_regions: &[crate::config::MemoryRegion]) {
        const MINIMUM_MEMORY_SIZE: u64 = 0x1000;

        let segments = &self.emu.get_data().file_data.program_data;

        // First pass: collect all segment ranges
        let mut ranges: Vec<(u64, u64, Prot)> = Vec::new();

        for segment in segments {
            let mut permission = Prot::NONE;
            if segment.0.p_flags & PF_X != 0 {
                permission |= Prot::EXEC;
            }
            if segment.0.p_flags & PF_W != 0 {
                permission |= Prot::WRITE;
            }
            if segment.0.p_flags & PF_R != 0 {
                permission |= Prot::READ;
            }

            // Align address down to page boundary
            // Use virtual address (p_vaddr) for ARM Cortex-M flat memory model
            let addr = segment.0.p_vaddr & 0xfffff000;
            let segment_end = segment.0.p_vaddr + segment.0.p_memsz;
            let size = ((segment_end - addr + MINIMUM_MEMORY_SIZE - 1) & 0xfffff000)
                .max(MINIMUM_MEMORY_SIZE);
            let end = addr + size;

            ranges.push((addr, end, permission));
        }

        // Sort ranges by start address
        ranges.sort_by_key(|r| r.0);

        // Apply force_overwrite: extend ranges to cover the entire requested region
        for region in memory_regions {
            if region.force_overwrite {
                let region_start = region.address;
                let region_end = region.address + region.size;

                // Find all ranges that overlap with this force_overwrite region
                let mut matching_indices = Vec::new();
                for (i, (addr, end, _perm)) in ranges.iter().enumerate() {
                    if *addr < region_end && *end > region_start {
                        matching_indices.push(i);
                    }
                }

                if !matching_indices.is_empty() {
                    // Merge all matching ranges into one that covers the full requested region
                    let mut combined_perm = Prot::NONE;
                    for &i in &matching_indices {
                        combined_perm |= ranges[i].2;
                    }

                    // Replace first matching range with merged range covering full region
                    let first_idx = matching_indices[0];
                    ranges[first_idx] = (
                        region_start,
                        region_end,
                        combined_perm | Prot::READ | Prot::WRITE,
                    );

                    // Remove other matching ranges (in reverse order to maintain indices)
                    for &i in matching_indices.iter().skip(1).rev() {
                        ranges.remove(i);
                    }
                }
            }
        }

        // Sort again after modifications
        ranges.sort_by_key(|r| r.0);

        // Merge only overlapping and adjacent ranges (no automatic merging)
        let mut merged_ranges: Vec<(u64, u64, Prot)> = Vec::new();

        for (addr, end, perm) in ranges {
            if let Some(last) = merged_ranges.last_mut() {
                if addr <= last.1 {
                    // Overlapping, merge
                    last.1 = last.1.max(end);
                    last.2 |= perm;
                } else {
                    // Not overlapping, add as new range
                    merged_ranges.push((addr, end, perm));
                }
            } else {
                // First range
                merged_ranges.push((addr, end, perm));
            }
        }

        // Map all merged ranges
        for (addr, end, permission) in merged_ranges {
            let size = end - addr;
            println!(
                "Mapping ELF segment: 0x{:08X} - 0x{:08X} ({} bytes, perm: {:?})",
                addr, end, size, permission
            );
            self.emu
                .mem_map(addr, size, permission)
                .expect("failed to map code page");
        }

        // Auth success / failed trigger
        self.emu
            .mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Prot::WRITE)
            .expect("failed to map mmio replacement");

        // IO address space
        self.emu
            .mmio_map_wo(0x11000000, MINIMUM_MEMORY_SIZE, mmio_serial_write_callback)
            .expect("failed to map serial IO");

        // Hook to capture memory errors (unmapped and protection violations only)
        self.emu
            .add_mem_hook(
                HookType::MEM_UNMAPPED | HookType::MEM_PROT,
                0,
                u64::MAX,
                capture_memory_errors,
            )
            .expect("failed to add unmapped mem hook");
    }

    /// Setup custom memory regions from configuration
    pub fn setup_memory_regions(&mut self, memory_regions: &[crate::config::MemoryRegion]) {
        for region in memory_regions {
            // Try to map the memory region
            match self.emu.mem_map(
                region.address,
                region.size,
                unicorn_engine::unicorn_const::Prot::READ
                    | unicorn_engine::unicorn_const::Prot::WRITE,
            ) {
                Ok(_) => {
                    println!(
                        "Successfully mapped memory region: 0x{:08X} - 0x{:08X} ({} bytes)",
                        region.address,
                        region.address + region.size,
                        region.size
                    );
                }
                Err(unicorn_engine::unicorn_const::uc_error::MAP) => {
                    println!(
                        "Region at 0x{:08X} (size: 0x{:X}) already mapped by ELF.",
                        region.address, region.size
                    );
                    // Try to ensure the region has write permissions
                    match self.emu.mem_protect(
                        region.address,
                        region.size,
                        unicorn_engine::unicorn_const::Prot::READ
                            | unicorn_engine::unicorn_const::Prot::WRITE,
                    ) {
                        Ok(_) => {
                            println!(
                                "Updated permissions to RW for region at 0x{:08X}",
                                region.address
                            );
                        }
                        Err(e) => {
                            println!(
                                "Warning: Could not update permissions for 0x{:08X}: {:?}",
                                region.address, e
                            );
                            println!(
                                "Region may be partially mapped - will try to write data anyway."
                            );
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "Warning: Failed to map memory region at 0x{:08X} (size: 0x{:X}): {:?}",
                        region.address, region.size, e
                    );
                }
            }

            // If data is provided, always try to write it
            if let Some(ref data) = region.data {
                // Ensure we don't write more data than the region size
                let write_size = std::cmp::min(data.len(), region.size as usize);
                match self.emu.mem_write(region.address, &data[..write_size]) {
                    Ok(_) => {
                        println!(
                            "Wrote {} bytes of data to memory region at 0x{:08X}",
                            write_size, region.address
                        );
                    }
                    Err(unicorn_engine::unicorn_const::uc_error::WRITE_UNMAPPED) => {
                        println!(
                            "Error: Region at 0x{:08X} is not fully mapped (only partial mapping exists).",
                            region.address
                        );
                        println!("ELF segments may not cover the full requested range.");
                        println!("Consider splitting this into multiple smaller regions that match ELF segments.");
                    }
                    Err(e) => {
                        println!(
                            "Error: Failed to write data to memory region at 0x{:08X}: {:?}",
                            region.address, e
                        );
                    }
                }
            }
        }
    }

    /// Execute code on pc set in internal structure till cycles
    ///
    /// If debug is set to true, execution is done by single steps
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
            let end_address = self.emu.get_data().file_data.program_data[0].0.p_paddr
                + self.emu.get_data().file_data.program_data[0].0.p_memsz;

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

    /// Returns the size of the assembler command at the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address of the command.
    ///
    /// # Returns
    ///
    /// * `Option<usize>` - Returns the size of the command if successful, otherwise `None`.
    pub fn get_asm_cmd_size(&self, address: u64) -> Option<usize> {
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
    pub fn init_states(&mut self, run_state: bool) {
        // Set run type
        self.emu.get_data_mut().negative_run = !run_state;

        // Set global state to initilized
        self.emu.get_data_mut().state = RunState::Init;
    }

    /// Get current state of simulation
    pub fn get_state(&self) -> RunState {
        self.emu.get_data().state
    }

    /// Get fault_data
    pub fn get_fault_data(&mut self) -> &mut FaultElement {
        &mut self.emu.get_data_mut().fault_data
    }

    /// Set code hook for tracing
    pub fn set_trace_hook(&mut self) {
        // TODO: go through all program data parts
        self.emu
            .add_code_hook(
                self.emu.get_data().file_data.program_data[0].0.p_paddr,
                self.emu.get_data().file_data.program_data[0].0.p_memsz,
                hook_code_callback,
            )
            .expect("failed to setup trace hook");
    }

    /// Starts tracing the CPU execution.
    ///
    /// # Arguments
    ///
    /// * `record_registers` - Whether to record register values during tracing.
    pub fn start_tracing(&mut self, with_register_data: bool) {
        let cpu_state = self.emu.get_data_mut();
        cpu_state.with_register_data = with_register_data;
        cpu_state.start_trace = true;
    }

    /// Clear fault data in internal structure
    pub fn clear_fault_data(&mut self) {
        // Remove hooks from list
        self.emu.get_data_mut().fault_data.clear();
    }

    /// Clear trace data in internal structure
    pub fn clear_trace_data(&mut self) {
        // Remove hooks from list
        self.emu.get_data_mut().trace_data.clear();
    }

    /// Initialize the CPUState
    ///
    pub fn init_cpu_state(&mut self) {
        self.emu.get_data_mut().state = RunState::Init;
        self.emu.get_data_mut().start_trace = false;
        self.emu.get_data_mut().with_register_data = false;
        self.emu.get_data_mut().negative_run = false;
        self.emu.get_data_mut().deactivate_print = false;
        self.emu.get_data_mut().trace_data.clear();
        self.emu.get_data_mut().fault_data.clear();
    }

    /// Copy trace data to caller
    pub fn get_trace_data(&mut self) -> &mut TraceElement {
        &mut self.emu.get_data_mut().trace_data
    }

    /// Remove duplicates to speed up testing
    pub fn reduce_trace(&mut self) {
        let trace_data = &mut self.emu.get_data_mut().trace_data;
        let mut seen = HashSet::new();
        trace_data.retain(|trace| seen.insert(trace.clone()));
    }

    /// Execute fault injection according to fault type
    /// Program is stopped and will be continued after fault injection
    pub fn execute_fault_injection(&mut self, fault: &FaultRecord) -> bool {
        fault.fault_type.execute(self, fault)
    }

    /// Get Program counter from internal variable
    pub fn get_program_counter(&self) -> u64 {
        self.program_counter
    }

    /// Set Program counter from internal variable
    pub fn set_program_counter(&mut self, program_counter: u64) {
        self.program_counter = program_counter;
    }

    /// Read register value
    ///
    pub fn register_read(&self, regid: RegisterARM) -> Result<u64, uc_error> {
        self.emu.reg_read(regid)
    }

    /// Write register value
    ///
    pub fn register_write(&mut self, regid: RegisterARM, value: u64) -> Result<(), uc_error> {
        self.emu.reg_write(regid, value)
    }

    /// Read memory
    ///
    pub fn memory_read(&self, address: u64, buffer: &mut [u8]) -> Result<(), uc_error> {
        self.emu.mem_read(address, buffer)
    }

    /// Write memory
    ///
    pub fn memory_write(&mut self, address: u64, buffer: &[u8]) -> Result<(), uc_error> {
        self.emu.mem_write(address, buffer)
    }

    /// Read assembler instruction from memory (current programm counter)
    ///
    pub fn asm_cmd_read(&mut self) -> (u64, Vec<u8>) {
        let address = self.get_program_counter();
        let cmd_size = self.get_asm_cmd_size(address).unwrap();
        // Read assembler instruction from memory
        let mut instruction = vec![0; cmd_size];
        self.memory_read(address, &mut instruction).unwrap();
        (address, instruction)
    }

    /// Write assembler instruction to memory. After modification the simulation cache is cleared for
    /// the changed command to ensure written cmds are immidiately active
    ///
    pub fn asm_cmd_write(&mut self, address: u64, instruction: &[u8]) -> Result<(), uc_error> {
        // Write assembler instruction to memory
        self.memory_write(address, instruction).unwrap();
        // Clear cached instruction
        self.emu
            .ctl_remove_cache(address, address + instruction.len() as u64)
    }

    /// Save the current state of the CPU.
    pub fn save_state(&mut self) -> Result<(), uc_error> {
        // Save current state of the CPU
        self.emu
            .context_save(&mut self.cpu_context)
            .expect("failed to save context");
        Ok(())
    }

    /// Restore the CPU state from a saved context.
    pub fn restore_state(&mut self) -> Result<(), uc_error> {
        // Restore CPU state
        self.emu
            .context_restore(&self.cpu_context)
            .expect("failed to restore context");
        Ok(())
    }
}
