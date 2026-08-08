//! # Simulation Module
//!
//! Core simulation engine for fault injection attacks on ARM processors.
//! This module provides the foundational types and execution control for
//! running fault injection simulations using CPU emulation.
//!
//! ## Submodules
//!
//! * `cpu` - CPU emulation and execution control
//! * `fault_data` - Fault injection data structures
//! * `record` - Execution trace recording and analysis

pub mod cpu;
pub mod fault_data;
pub mod record;

use crate::elf_file::ElfFile;
use crate::error::SimulatorError;
use cpu::{Cpu, RunState};
use fault_data::FaultData;
use log::info;
use record::FaultRecord;
pub use record::TraceRecord;
use unicorn_engine::uc_error;

/// Type alias for a collection of fault injection data elements.
///
/// Represents a sequence of fault injections that were successfully applied
/// during a simulation run. Each `FaultData` contains information about
/// the fault location, type, and timing.
pub type FaultElement = Vec<FaultData>;

/// Type alias for a collection of execution trace records.
///
/// Represents the complete execution trace of a simulation run, including
/// all instructions executed, memory accesses, and control flow changes.
/// Used for analysis and replay of simulation results.
pub type TraceElement = Vec<TraceRecord>;

/// Specifies the type of simulation run to execute.
///
/// Different run types collect different information and have different
/// performance characteristics. Choose the appropriate type based on
/// the analysis requirements.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RunType {
    /// Execute with fault injection and minimal tracing.
    ///
    /// This is the fastest execution mode, collecting only essential
    /// information needed to detect successful fault attacks.
    Run,
    /// Record instruction-level execution trace without full details.
    ///
    /// Captures basic execution flow for analysis while maintaining
    /// reasonable performance. Suitable for most fault attack analysis.
    RecordTrace,
    /// Record complete execution trace with full details.
    ///
    /// Captures comprehensive execution information including memory
    /// accesses, register states, and detailed timing. Slowest but
    /// most comprehensive analysis mode.
    RecordFullTrace,
}

/// Represents the data returned by a simulation run.
///
/// The type of data returned depends on the `RunType` specified
/// when starting the simulation. This enum encapsulates all
/// possible return values from simulation execution.
pub enum Data {
    /// Successful fault injection data.
    ///
    /// Contains the sequence of faults that were applied and resulted
    /// in a successful attack (reached success criteria).
    Fault(FaultElement),
    /// Execution trace data.
    ///
    /// Contains the complete or partial execution trace collected
    /// during the simulation run.
    Trace(TraceElement),
    /// No data returned.
    ///
    /// Indicates the simulation completed without collecting specific
    /// data, or the operation was not successful.
    None,
}

/// Central control structure for managing CPU emulation and simulation execution.
///
/// This structure encapsulates the CPU emulator and provides high-level methods
/// for executing fault injection simulations. It manages the emulation lifecycle,
/// fault injection timing, and result collection.
///
/// # Lifetime
///
/// The lifetime parameter `'a` ensures the Control instance doesn't outlive
/// the ELF file data it references for program execution.
///
/// # Usage
///
/// 1. Create with `new()` providing ELF file and configuration
/// 2. Use `run()` to execute simulations with optional fault injection
/// 3. Extract results through the returned `Data` enum
pub struct Control<'a> {
    /// The CPU emulator instance that executes the target program.
    emu: Cpu<'a>,
}

impl<'a> Control<'a> {
    /// Creates a new `Control` instance.
    ///
    /// # Arguments
    ///
    /// * `program_data` - A reference to the ELF file containing the program data.
    /// * `decision_activation_active` - A boolean indicating whether decision activation is enabled.
    /// * `success_addresses` - List of memory addresses that indicate success when executed.
    /// * `failure_addresses` - List of memory addresses that indicate failure when executed.
    /// * `initial_registers` - HashMap of RegisterARM to initial values for CPU registers.
    /// * `memory_regions` - Custom memory regions to initialize.
    /// * `result_checks` - Register-based success/failure checking configuration.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Returns a new `Control` instance.
    /// * `Err(SimulatorError)` - If CPU/memory setup fails (e.g. invalid memory regions).
    pub fn new(
        program_data: &'a ElfFile,
        decision_activation_active: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
        memory_regions: &[crate::config::MemoryRegion],
        result_checks: Option<crate::config::ResultChecks>,
    ) -> Result<Self, SimulatorError> {
        // Setup cpu emulation
        let mut emu = Cpu::new(
            program_data,
            success_addresses,
            failure_addresses,
            initial_registers,
            result_checks,
        )?;
        // Cpu setup
        emu.setup_mmio(memory_regions)?;
        emu.setup_memory_regions(memory_regions);
        emu.setup_breakpoints(decision_activation_active)?;
        // Write code to memory area
        emu.load_code()?;

        Ok(Self { emu })
    }

    /// Setup system state to a successful or failed state
    /// and run the program. Return the state of the program after compilation
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the program.
    /// * `run_successful` - Whether to run the program in a successful state.
    ///
    /// # Returns
    ///
    /// * `RunState` - Returns the state of the program after running.
    fn run(&mut self, cycles: usize, run_successful: bool) -> Result<RunState, SimulatorError> {
        // Initial and load program
        self.init(run_successful, false)?;
        // Start execution with the given amount of instructions
        let ret_info = self.emu.run_steps(cycles, false);

        info!("Program stopped successful {:?}", ret_info);
        // Return emulation state
        Ok(self.emu.get_state())
    }

    /// Initialize cpu state and load the program code into the cpu
    /// and set the initial state.
    /// When `clean_memory` is true, all segment memory is zeroed before
    /// loading code to ensure a pristine state (needed for trace recordings).
    fn init(&mut self, run_successful: bool, clean_memory: bool) -> Result<(), SimulatorError> {
        self.emu.init_register()?;
        // Zero memory for clean state when required (trace recordings)
        if clean_memory {
            self.emu.clear_segment_memory();
        }
        // Write code to memory area
        self.emu.load_code()?;
        // Set initial state
        self.emu.init_cpu_state();
        // Init state
        self.emu.init_states(run_successful);
        Ok(())
    }

    /// Validates correct program behavior by testing both success and failure paths.
    ///
    /// Executes the program twice: once configured for success (should reach success_addresses)
    /// and once configured for failure (should reach failure_addresses). This ensures the
    /// target program behaves correctly before fault injection testing begins.
    ///
    /// # Arguments
    ///
    /// * `cycles` - Maximum number of CPU cycles to execute for each validation run.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Both success and failure paths behave as expected.
    /// * `Err(String)` - Program validation failed with descriptive error message.
    pub fn check_program(&mut self, cycles: usize) -> Result<(), SimulatorError> {
        // Deactivate io print
        self.emu.deactivate_printf_function();
        if self.run(cycles, true)? != RunState::Success {
            return Err(SimulatorError::simulation(
                "Program function check failed. Success path is not working properly!",
            ));
        }
        if self.run(cycles, false)? != RunState::Failed {
            return Err(SimulatorError::simulation(
                "Program function check failed. Failure path is not working properly!",
            ));
        }
        println!("Program checked successfully");
        Ok(())
    }

    /// Runs the simulation with the specified fault injection sequence.
    ///
    /// Executes the target program with fault injections applied at specific points during execution.
    /// The behavior depends on the run_type: normal execution returns fault data on success,
    /// while trace modes return execution trace records for analysis.
    ///
    /// # Arguments
    ///
    /// * `cycles` - Maximum number of CPU cycles to execute during simulation.
    /// * `run_type` - Type of simulation (Run, RecordTrace, or RecordFullTrace).
    /// * `deep_analysis_trace` - Whether to perform detailed loop analysis during trace recording.
    /// * `faults` - Sequence of fault injection records to apply during execution.
    ///
    /// # Returns
    ///
    /// * `Ok(Data::Fault(FaultElement))` - Fault data if execution reaches success state.
    /// * `Ok(Data::Trace(TraceElement))` - Execution trace if run_type is trace mode.
    /// * `Ok(Data::None)` - No meaningful result (execution failed or no success).
    /// * `Err(String)` - Error message if simulation setup or execution fails.
    pub fn run_with_faults(
        &mut self,
        cycles: usize,
        run_type: RunType,
        deep_analysis_trace: bool,
        faults: &[FaultRecord],
    ) -> Result<Data, SimulatorError> {
        let mut restore_required = false;
        // Initialize and load — use clean memory for trace recordings
        let clean_memory = matches!(run_type, RunType::RecordTrace | RunType::RecordFullTrace);
        self.init(false, clean_memory)?;
        // Deactivate io print
        self.emu.deactivate_printf_function();

        match run_type {
            RunType::RecordTrace => {
                // Set trace hook
                self.emu.set_trace_hook();
            }
            RunType::RecordFullTrace => {
                // Set trace hook
                self.emu.set_trace_hook();
                // Switch on tracing from the beginning and record also register values
                self.emu.start_tracing(true);
            }
            _ => (),
        }

        // Preload instruction backup if fault is inserted with index = 0
        let (mut address, mut instruction) = self.emu.asm_cmd_read();
        // Iterate over all faults and run the program step by step
        for fault in faults {
            if fault.index != 0 {
                // One single step
                if let Err(e) = self.emu.run_steps(1, false) {
                    let error_msg = self.report_unicorn_error(e, "fault injection step 1");
                    return Err(SimulatorError::simulation(error_msg));
                }
                // Restore instruction if required
                if restore_required {
                    self.emu.asm_cmd_write(address, &instruction).unwrap();
                    restore_required = false;
                }
                // Execute remaining steps
                if fault.index != 1 {
                    if let Err(e) = self.emu.run_steps(fault.index - 1, false) {
                        let error_msg = self.report_unicorn_error(e, "Unicorn Error");
                        return Err(SimulatorError::simulation(error_msg));
                    }
                }
                // Read instruction for later restore
                (address, instruction) = self.emu.asm_cmd_read();
            }
            // Inject fault
            restore_required |= self.emu.execute_fault_injection(fault);
        }

        // Start tracing or check previous run state
        match run_type {
            RunType::RecordTrace => {
                self.emu.start_tracing(false);
            }
            RunType::Run if self.emu.get_state() == RunState::Success => {
                return Err(SimulatorError::simulation("Successfull state reached before critical glitch inserted! Maybe failure can be triggered with less glitches"));
            }
            _ => (),
        }

        // Run to completion
        if restore_required {
            if let Err(e) = self.emu.run_steps(1, false) {
                let error_msg = self.report_unicorn_error(e, "Unicorn Error");
                return Err(SimulatorError::simulation(error_msg));
            }
            self.emu.asm_cmd_write(address, &instruction).unwrap();
        }
        if let Err(e) = self.emu.run_steps(cycles, false) {
            let error_msg = self.report_unicorn_error(e, "Unicorn Error");

            // Still collect trace data even if execution failed
            match run_type {
                RunType::RecordTrace | RunType::RecordFullTrace => {
                    self.emu.clear_fault_data();
                    if !deep_analysis_trace {
                        self.emu.reduce_trace();
                    }
                    // Log execution failure but return trace data
                    log::info!(
                        "Execution failed, but returning collected trace data up to error point"
                    );
                    return Ok(Data::Trace(self.emu.take_trace_data()));
                }
                RunType::Run => {
                    return Err(SimulatorError::simulation(error_msg));
                }
            }
        }

        // Cleanup and return data to caller
        match run_type {
            RunType::RecordTrace | RunType::RecordFullTrace => {
                self.emu.clear_fault_data();

                // Reduce traces if necessary
                if !deep_analysis_trace {
                    self.emu.reduce_trace();
                }
                Ok(Data::Trace(self.emu.take_trace_data()))
            }
            RunType::Run => {
                // Check if fault attack was successful if yes return faults
                if self.emu.get_state() == RunState::Success {
                    Ok(Data::Fault(self.emu.take_fault_data()))
                } else {
                    Ok(Data::None)
                }
            }
        }
    }

    /// Helper method to report unicorn emulator errors
    fn report_unicorn_error(&mut self, error: uc_error, context: &str) -> String {
        let pc = self.emu.get_program_counter();

        // Log errors using the log crate
        match error {
            // All memory-related errors are already printed by the callback
            uc_error::READ_UNMAPPED
            | uc_error::WRITE_UNMAPPED
            | uc_error::FETCH_UNMAPPED
            | uc_error::READ_PROT
            | uc_error::WRITE_PROT
            | uc_error::FETCH_PROT => {
                // Already printed by callback with address
            }
            // Log non-memory errors (EXCEPTION, INSN_INVALID, etc.)
            _ => {
                log::error!("Unicorn Error: {:?} at PC 0x{:08X}", error, pc);
            }
        }
        format!("{}: {:?} at PC 0x{:08X}", context, error, pc)
    }
}
