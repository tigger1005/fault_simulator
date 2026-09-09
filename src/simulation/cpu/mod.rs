//! # CPU Emulation and Execution Control
//!
//! This module provides ARM Cortex-M processor emulation using the Unicorn Engine.
//! It handles program execution, fault injection, memory management, and execution
//! state tracking for comprehensive fault injection simulation.
//!
//! ## Key Capabilities
//!
//! * **ARM Cortex-M Emulation**: Full ARMv8-M instruction set support
//! * **Memory Management**: ELF loading, MMIO simulation, memory protection
//! * **Execution Hooks**: Instruction-level monitoring and control
//! * **Fault Injection**: Runtime fault application and state modification
//! * **Trace Recording**: Comprehensive execution trace collection
//!
//! ## Architecture Support
//!
//! Specifically tuned for ARM Cortex-M processors with:
//! * Thumb-2 instruction set
//! * M-Profile system architecture
//! * Memory-mapped I/O simulation
//! * Exception and interrupt handling

use crate::elf_file::{ElfFile, PF_R, PF_W, PF_X};
use crate::error::SimulatorError;
use crate::simulation::record::{AsmInstruction, FaultRecord, TraceRecord};
use crate::simulation::{FaultElement, TraceElement};

mod callback;

use callback::{
    capture_memory_errors, hook_code_callback, hook_code_decision_activation_callback,
    hook_custom_addresses_callback, hook_result_check_callback, mmio_auth_write_callback,
    mmio_serial_write_callback,
};

use unicorn_engine::unicorn_const::uc_error;
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot};
use unicorn_engine::{RegisterARM, Unicorn};

use log::debug;

/// Why the last call to [`Cpu::run_steps`] stopped.
///
/// Deriving this from the program counter alone cannot distinguish an aborted run
/// from an exhausted instruction budget, which made the simulator advise
/// "increase --max-instructions" for programs that in fact died on an unmapped
/// memory access. The reason is therefore recorded where it is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopReason {
    /// No run has been executed yet.
    #[default]
    NotRun,
    /// The program reached a success or failure verdict.
    Verdict,
    /// Execution ran to the end of the loaded program image.
    ImageEnd,
    /// The instruction budget was used up before a verdict was reached.
    InstructionLimit,
    /// Unicorn aborted the run, e.g. on an unmapped access or an invalid instruction.
    EmulationError,
}
use std::collections::{HashMap, HashSet};

/// Base address for authentication system MMIO region.
///
/// This address is used for simulating authentication peripherals
/// that are commonly targeted in fault injection attacks.
const AUTH_BASE: u64 = 0xAA01000;

/// ARM Thumb-1 return instruction encoding (bx lr).
///
/// Used for function patching and control flow manipulation
/// during fault injection simulation.
const T1_RET: [u8; 2] = [0x70, 0x47]; // bx lr

/// Complete ARM register set for Cortex-M processors.
///
/// Defines all general-purpose registers (R0-R12), stack pointer (SP),
/// link register (LR), program counter (PC), and program status register (CPSR)
/// in the order used by the Unicorn Engine for state access.
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

/// Execution state enumeration for simulation control and result classification.
///
/// Tracks the current state of program execution and provides clear
/// categorization of simulation outcomes for fault injection analysis.
#[derive(PartialEq, Debug, Clone, Copy, Default)]
pub enum RunState {
    /// Initial state before execution begins.
    #[default]
    Init = 0,
    /// Successful execution reaching success criteria.
    Success,
    /// Failed execution (detected attack or normal termination).
    Failed,
    /// Error state (crashes, invalid operations, etc.).
    Error,
}

/// ARM CPU emulator for fault injection simulation.
///
/// This struct encapsulates a Unicorn Engine ARM CPU emulator instance along with
/// simulation state, memory management, and fault injection tracking. It provides
/// methods for program execution, fault injection, tracing, and state management.
///
/// # Fields
///
/// The struct contains the CPU emulator, memory layout, execution state tracking,
/// fault data collection, trace recording, and various simulation parameters.
pub struct Cpu<'a> {
    emu: Unicorn<'a, CpuState<'a>>,
    program_counter: u64,
    initial_registers: HashMap<RegisterARM, u64>,
    /// Handle for the trace code hook, if registered.
    trace_hook: Option<unicorn_engine::UcHookId>,
    /// Reusable all-zero buffer used to clear BSS regions.
    zeros: Vec<u8>,
    /// Custom memory regions from the configuration.
    ///
    /// They live outside the ELF segments, so neither `clear_segment_memory` nor
    /// `load_code` restores them. Kept here so every run can start from the same
    /// content instead of inheriting whatever the previous run wrote.
    memory_regions: Vec<crate::cli_args::MemoryRegion>,
    /// Set when instruction memory was patched (e.g. by a command bit flip fault).
    ///
    /// Restoring the ELF image via `load_code` does not invalidate the JIT
    /// translation blocks, so a full flush is required before the next clean run —
    /// but only if the instruction stream was actually modified.
    code_modified: bool,
    /// Why the last `run_steps` call stopped.
    stop_reason: StopReason,
}

struct CpuState<'a> {
    state: RunState,
    start_trace: bool,
    with_register_data: bool,
    negative_run: bool,
    deactivate_print: bool,
    trace_data: TraceElement,
    fault_data: FaultElement,
    file_data: &'a ElfFile,
    success_addresses: HashSet<u64>,
    failure_addresses: HashSet<u64>,
    result_checks: Option<crate::cli_args::ResultChecks>,
    /// Addresses mentioned by any success or failure check.
    ///
    /// The result check hook runs on every instruction, so this set provides an
    /// O(1) rejection for the overwhelming majority of addresses.
    result_check_addresses: HashSet<u64>,
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
    /// * `result_checks` - Register-based success/failure checking configuration.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Returns a `Cpu` instance.
    /// * `Err(SimulatorError)` - If the Unicorn engine instance could not be created.
    pub fn new(
        file_data: &'a ElfFile,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: HashMap<RegisterARM, u64>,
        result_checks: Option<crate::cli_args::ResultChecks>,
    ) -> Result<Self, SimulatorError> {
        // Setup platform -> ARMv8-m.base
        let result_check_addresses = result_checks
            .as_ref()
            .map(|checks| {
                checks
                    .success_checks
                    .iter()
                    .chain(&checks.failure_checks)
                    .map(|check| check.address)
                    .collect()
            })
            .unwrap_or_default();

        let emu = Unicorn::new_with_data(
            Arch::ARM,
            Mode::LITTLE_ENDIAN | Mode::MCLASS,
            CpuState {
                state: Default::default(),
                start_trace: false,
                with_register_data: false,
                negative_run: false,
                deactivate_print: false,
                trace_data: Vec::new(),
                fault_data: Vec::new(),
                file_data,
                success_addresses: success_addresses.into_iter().collect(),
                failure_addresses: failure_addresses.into_iter().collect(),
                result_checks,
                result_check_addresses,
            },
        )
        .map_err(|e| {
            SimulatorError::simulation(format!("Failed to initialize Unicorn instance: {:?}", e))
        })?;

        debug!("Setup new unicorn instance");
        Ok(Self {
            emu,
            program_counter: 0,
            initial_registers,
            trace_hook: None,
            zeros: Vec::new(),
            memory_regions: Vec::new(),
            code_modified: false,
            stop_reason: StopReason::NotRun,
        })
    }

    /// Initialize all ARM registers to zero or custom initial values.
    ///
    /// Sets all general-purpose registers (R0-R12) to zero by default, then applies
    /// any custom initial values specified in the configuration. The stack pointer (SP)
    /// is initialized to the start of the designated stack memory region.
    ///
    /// # Note
    ///
    /// Custom register values from `initial_registers` HashMap take precedence over defaults.
    pub fn init_register(&mut self) -> Result<(), SimulatorError> {
        // Clear all registers first
        for reg in ARM_REG.iter() {
            self.emu.reg_write(*reg, 0x00).map_err(|e| {
                SimulatorError::simulation(format!("Failed to clear register {:?}: {:?}", reg, e))
            })?;
        }

        // Setup stack pointer (if .stack section exists)
        if let Some(stack) = self.emu.get_data().file_data.section_map.get(".stack") {
            self.emu
                .reg_write(RegisterARM::SP, stack.sh_addr + stack.sh_size)
                .map_err(|e| {
                    SimulatorError::simulation(format!("Failed to set stack pointer: {:?}", e))
                })?;
        }

        // Set initial program start address (default from ELF)
        self.program_counter = self.emu.get_data().file_data.header.e_entry;

        // Apply custom register values (these can override the defaults above)
        for (&register, &value) in &self.initial_registers {
            self.emu.reg_write(register, value).map_err(|e| {
                SimulatorError::simulation(format!(
                    "Failed to set register {:?}: {:?}",
                    register, e
                ))
            })?;

            // If PC is being set via initial_registers, update our internal program_counter too
            if register == RegisterARM::PC {
                self.program_counter = value;
            }
        }
        Ok(())
    }

    /// Load source code from elf file into simulation
    pub fn load_code(&mut self) -> Result<(), SimulatorError> {
        let file_data: &'a ElfFile = self.emu.get_data().file_data;

        // Iterate over all program parts and write them to memory
        // Use virtual address (p_vaddr) for ARM Cortex-M flat memory model
        for (header, data) in &file_data.program_data {
            self.emu.mem_write(header.p_vaddr, data).map_err(|e| {
                SimulatorError::simulation(format!(
                    "Failed to write program data at 0x{:08X}: {:?}",
                    header.p_vaddr, e
                ))
            })?;
        }
        Ok(())
    }

    /// Zero the BSS part of every segment (the range between `p_filesz` and
    /// `p_memsz`) and the AUTH_BASE state.
    /// Called before load_code() on every run; load_code() restores the
    /// file-backed part of each segment afterwards.
    pub fn clear_segment_memory(&mut self) {
        let file_data: &'a ElfFile = self.emu.get_data().file_data;
        for (header, data) in &file_data.program_data {
            let bss_size = (header.p_memsz as usize).saturating_sub(data.len());
            if bss_size == 0 {
                continue;
            }
            if self.zeros.len() < bss_size {
                self.zeros.resize(bss_size, 0);
            }
            let _ = self
                .emu
                .mem_write(header.p_vaddr + data.len() as u64, &self.zeros[..bss_size]);
        }
        // Clear AUTH_BASE state
        let _ = self.emu.mem_write(AUTH_BASE, &[0u8; 4]);
        // Restoring the ELF image does not invalidate translation blocks, and a
        // per-instruction `ctl_remove_cache` does not cover the block that contains
        // it, so drop the whole JIT cache if a previous run patched the instruction
        // stream. Without this, a stale block silently decides the next run.
        if self.code_modified {
            let _ = self.emu.ctl_flush_tb();
            self.code_modified = false;
        }
    }

    /// Reset every configured memory region to its initial content.
    ///
    /// Custom memory regions (SRAM, peripherals, memory dumps) live outside the ELF
    /// segments, so `clear_segment_memory` and `load_code` do not touch them. Worker
    /// threads reuse one `Control` for all runs, so without this reset whatever a
    /// previous (faulted) run wrote into such a region would decide the outcome of
    /// the next one — and, because runs are distributed over threads, the result of a
    /// campaign would differ from execution to execution.
    ///
    /// Called before `load_code()`, mirroring the order of the initial setup so that
    /// ELF content still wins over a region that overlaps a segment.
    pub fn restore_memory_regions(&mut self) {
        if self.memory_regions.is_empty() {
            return;
        }
        let regions = std::mem::take(&mut self.memory_regions);
        for region in &regions {
            let size = region.size as usize;
            if self.zeros.len() < size {
                self.zeros.resize(size, 0);
            }
            // Partially mapped regions are reported during setup; ignore the error here.
            let _ = self.emu.mem_write(region.address, &self.zeros[..size]);
            if let Some(data) = &region.data {
                let write_size = data.len().min(size);
                let _ = self.emu.mem_write(region.address, &data[..write_size]);
            }
        }
        self.memory_regions = regions;
    }

    /// Test helper: read raw bytes from the emulated memory.
    #[cfg(test)]
    pub(crate) fn read_memory(&self, address: u64, buffer: &mut [u8]) {
        self.emu.mem_read(address, buffer).unwrap();
    }

    /// Test helper: write raw bytes into the emulated memory.
    #[cfg(test)]
    pub(crate) fn write_memory(&mut self, address: u64, data: &[u8]) {
        self.emu.mem_write(address, data).unwrap();
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

    /// Setup all breakpoints
    ///
    /// BreakPoints
    /// { binInfo.Symbols["decision_activation"].Address }
    pub fn setup_breakpoints(
        &mut self,
        decision_activation_active: bool,
    ) -> Result<(), SimulatorError> {
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
                    .map_err(|e| {
                        SimulatorError::simulation(format!(
                            "Failed to set decision_activation code hook: {:?}",
                            e
                        ))
                    })?;
            }
        }

        // Set up code hooks for custom success/failure addresses (if any provided)
        // Priority: result_checks > custom addresses > MMIO-based checking
        let has_result_checks = self.emu.get_data().result_checks.is_some();
        let has_custom_addresses = !self.emu.get_data().success_addresses.is_empty()
            || !self.emu.get_data().failure_addresses.is_empty();

        if has_result_checks {
            // Use register-based checking (new mechanism)
            debug!("Using register-based success/failure checking");
            let program_data = &self.emu.get_data().file_data.program_data.clone();
            for segment in program_data {
                self.emu
                    .add_code_hook(
                        segment.0.p_vaddr,
                        segment.0.p_vaddr + segment.0.p_memsz,
                        hook_result_check_callback,
                    )
                    .map_err(|e| {
                        SimulatorError::simulation(format!(
                            "Failed to set result check code hook: {:?}",
                            e
                        ))
                    })?;
            }
        } else if has_custom_addresses {
            // Use address-based checking (backward compatibility)
            debug!("Using address-based success/failure checking");
            let program_data = &self.emu.get_data().file_data.program_data.clone();
            for segment in program_data {
                self.emu
                    .add_code_hook(
                        segment.0.p_vaddr,
                        segment.0.p_vaddr + segment.0.p_memsz,
                        hook_custom_addresses_callback,
                    )
                    .map_err(|e| {
                        SimulatorError::simulation(format!(
                            "Failed to set custom address code hook: {:?}",
                            e
                        ))
                    })?;
            }
        } else {
            // Only set up the MMIO hook when NOT using custom addresses or result checks
            debug!("Using MMIO-based success/failure checking");
            self.emu
                .add_mem_hook(
                    HookType::MEM_WRITE,
                    AUTH_BASE,
                    AUTH_BASE + 4,
                    mmio_auth_write_callback,
                )
                .map_err(|e| {
                    SimulatorError::simulation(format!("Failed to set memory hook: {:?}", e))
                })?;
        }
        Ok(())
    }

    /// Setup memory mapping, stack, io mapping
    pub fn setup_mmio(
        &mut self,
        memory_regions: &[crate::cli_args::MemoryRegion],
    ) -> Result<(), SimulatorError> {
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
            log::debug!(
                "Mapping ELF segment: 0x{:08X} - 0x{:08X} ({} bytes, perm: {:?})",
                addr,
                end,
                size,
                permission
            );
            self.emu.mem_map(addr, size, permission).map_err(|e| {
                SimulatorError::simulation(format!(
                    "Failed to map memory region 0x{:08X}-0x{:08X}: {:?}",
                    addr, end, e
                ))
            })?;
        }

        // Auth success / failed trigger
        self.emu
            .mem_map(AUTH_BASE, MINIMUM_MEMORY_SIZE, Prot::WRITE)
            .map_err(|e| {
                SimulatorError::simulation(format!("Failed to map mmio replacement: {:?}", e))
            })?;

        // IO address space
        self.emu
            .mmio_map_wo(0x11000000, MINIMUM_MEMORY_SIZE, mmio_serial_write_callback)
            .map_err(|e| SimulatorError::simulation(format!("Failed to map serial IO: {:?}", e)))?;

        // Hook to capture memory errors (unmapped and protection violations only)
        self.emu
            .add_mem_hook(
                HookType::MEM_UNMAPPED | HookType::MEM_PROT,
                0,
                u64::MAX,
                capture_memory_errors,
            )
            .map_err(|e| {
                SimulatorError::simulation(format!("Failed to add unmapped mem hook: {:?}", e))
            })?;
        Ok(())
    }

    /// Setup custom memory regions from configuration
    pub fn setup_memory_regions(&mut self, memory_regions: &[crate::cli_args::MemoryRegion]) {
        // Remember the regions so `restore_memory_regions` can reset them before every run.
        self.memory_regions = memory_regions.to_vec();
        for region in memory_regions {
            // Try to map the memory region
            match self.emu.mem_map(
                region.address,
                region.size,
                unicorn_engine::unicorn_const::Prot::READ
                    | unicorn_engine::unicorn_const::Prot::WRITE,
            ) {
                Ok(_) => {
                    log::debug!(
                        "Successfully mapped memory region: 0x{:08X} - 0x{:08X} ({} bytes)",
                        region.address,
                        region.address + region.size,
                        region.size
                    );
                }
                Err(unicorn_engine::unicorn_const::uc_error::MAP) => {
                    log::debug!(
                        "Region at 0x{:08X} (size: 0x{:X}) already mapped by ELF.",
                        region.address,
                        region.size
                    );
                    // Try to ensure the region has write permissions
                    match self.emu.mem_protect(
                        region.address,
                        region.size,
                        unicorn_engine::unicorn_const::Prot::READ
                            | unicorn_engine::unicorn_const::Prot::WRITE,
                    ) {
                        Ok(_) => {
                            log::debug!(
                                "Updated permissions to RW for region at 0x{:08X}",
                                region.address
                            );
                        }
                        Err(e) => {
                            log::warn!(
                                "Could not update permissions for 0x{:08X}: {:?}",
                                region.address,
                                e
                            );
                            log::debug!(
                                "Region may be partially mapped - will try to write data anyway."
                            );
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to map memory region at 0x{:08X} (size: 0x{:X}): {:?}",
                        region.address,
                        region.size,
                        e
                    );
                }
            }

            // If data is provided, always try to write it
            if let Some(ref data) = region.data {
                // Ensure we don't write more data than the region size
                let write_size = std::cmp::min(data.len(), region.size as usize);
                match self.emu.mem_write(region.address, &data[..write_size]) {
                    Ok(_) => {
                        log::debug!(
                            "Wrote {} bytes of data to memory region at 0x{:08X}",
                            write_size,
                            region.address
                        );
                    }
                    Err(unicorn_engine::unicorn_const::uc_error::WRITE_UNMAPPED) => {
                        log::error!(
                            "Region at 0x{:08X} is not fully mapped (only partial mapping exists).",
                            region.address
                        );
                        log::info!("ELF segments may not cover the full requested range.");
                        log::info!("Consider splitting this into multiple smaller regions that match ELF segments.");
                    }
                    Err(e) => {
                        log::error!(
                            "Failed to write data to memory region at 0x{:08X}: {:?}",
                            region.address,
                            e
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
            let end_address = self.end_address();

            // Start from last PC
            ret_val = self.emu.emu_start(
                self.program_counter | 1,
                end_address | 1,
                0, // No wall-clock timeout; rely on cycle count only
                cycles,
            );
            // Store new PC
            self.program_counter = self.emu.pc_read().unwrap();
            self.stop_reason = self.classify_stop(&ret_val, end_address);
            return ret_val;
        }
        // Store new PC
        self.program_counter = self.emu.pc_read().unwrap();

        ret_val
    }

    /// Determine why `emu_start` returned.
    ///
    /// The four cases are mutually exclusive and cover every way a run can end.
    /// Recording them explicitly avoids guessing from the program counter, which
    /// cannot tell an aborted run apart from an exhausted instruction budget.
    fn classify_stop(&self, result: &Result<(), uc_error>, end_address: u64) -> StopReason {
        if result.is_err() {
            StopReason::EmulationError
        } else if self.emu.get_data().state != RunState::Init {
            StopReason::Verdict
        } else if (self.program_counter | 1) == (end_address | 1) {
            StopReason::ImageEnd
        } else {
            StopReason::InstructionLimit
        }
    }

    /// Address at which emulation stops (end of the loaded program image).
    ///
    /// An image can consist of several `PT_LOAD` segments, so the stop address is the
    /// highest end of all executable ones. Using `program_data[0]` unconditionally
    /// stops emulation at an arbitrary address as soon as the code does not happen to
    /// live in the first segment.
    fn end_address(&self) -> u64 {
        let program_data = &self.emu.get_data().file_data.program_data;
        program_data
            .iter()
            .filter(|(header, _)| header.p_flags & PF_X != 0)
            .map(|(header, _)| header.p_paddr + header.p_memsz)
            .max()
            .unwrap_or_else(|| {
                // No segment is marked executable: fall back to the whole image.
                program_data
                    .iter()
                    .map(|(header, _)| header.p_paddr + header.p_memsz)
                    .max()
                    .unwrap_or(0)
            })
    }

    /// Why the last run stopped.
    pub fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }

    /// True when the last run used up its instruction budget without reaching a verdict.
    ///
    /// Emulation stops either on a verdict (marker write, checked address, register
    /// check), at the end of the program image, on an emulation error, or when the
    /// instruction budget is used up. Only the last case is reported here — typically
    /// an endless loop caused by a fault.
    pub fn instruction_limit_reached(&self) -> bool {
        self.stop_reason == StopReason::InstructionLimit
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

    /// Move the collected fault data out of the emulator state
    pub fn take_fault_data(&mut self) -> FaultElement {
        std::mem::take(&mut self.emu.get_data_mut().fault_data)
    }

    /// Set code hook for tracing (idempotent — only registers the hook once)
    pub fn set_trace_hook(&mut self) {
        if self.trace_hook.is_some() {
            return;
        }
        // TODO: go through all program data parts
        let hook_id = self
            .emu
            .add_code_hook(
                self.emu.get_data().file_data.program_data[0].0.p_paddr,
                self.emu.get_data().file_data.program_data[0].0.p_memsz,
                hook_code_callback,
            )
            .expect("failed to setup trace hook");
        self.trace_hook = Some(hook_id);
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

    /// Execute fault injection according to fault type
    /// Program is stopped and will be continued after fault injection
    pub fn execute_fault_injection(&mut self, fault: &FaultRecord) -> bool {
        fault.fault_type.execute(self, fault)
    }
    pub fn init_cpu_state(&mut self) {
        self.stop_reason = StopReason::NotRun;
        let state = self.emu.get_data_mut();
        state.state = RunState::Init;
        state.start_trace = false;
        state.with_register_data = false;
        state.negative_run = false;
        state.deactivate_print = false;
        state.trace_data.clear();
        state.fault_data.clear();
    }

    /// Copy trace data to caller
    pub fn get_trace_data(&mut self) -> &mut TraceElement {
        &mut self.emu.get_data_mut().trace_data
    }

    /// Move the collected trace data out of the emulator state
    pub fn take_trace_data(&mut self) -> TraceElement {
        std::mem::take(&mut self.emu.get_data_mut().trace_data)
    }

    /// Remove duplicates to speed up testing
    pub fn reduce_trace(&mut self) {
        let trace_data = &mut self.emu.get_data_mut().trace_data;
        let mut seen = HashSet::with_capacity(trace_data.len());
        trace_data.retain(|trace| match trace {
            TraceRecord::Instruction { address, .. } => seen.insert(*address),
            TraceRecord::Fault { .. } => true,
        });
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
    pub fn asm_cmd_read(&mut self) -> (u64, AsmInstruction) {
        let address = self.get_program_counter();
        let cmd_size = self.get_asm_cmd_size(address).unwrap();
        // Read assembler instruction from memory
        let mut instruction = AsmInstruction::zeroed(cmd_size);
        self.memory_read(address, instruction.as_mut_slice())
            .unwrap();
        (address, instruction)
    }

    /// Write assembler instruction to memory. After modification the simulation cache is cleared for
    /// the changed command to ensure written cmds are immediately active
    pub fn asm_cmd_write(&mut self, address: u64, instruction: &[u8]) -> Result<(), uc_error> {
        // Write assembler instruction to memory
        self.memory_write(address, instruction).unwrap();
        self.code_modified = true;
        // Clear cached instruction
        self.emu
            .ctl_remove_cache(address, address + instruction.len() as u64)
    }
}
