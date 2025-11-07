pub mod cpu;
pub mod fault_data;
pub mod record;

use crate::elf_file::ElfFile;
use cpu::{Cpu, RunState};
use fault_data::FaultData;
use log::info;
use record::FaultRecord;
pub use record::TraceRecord;
use unicorn_engine::uc_error;

#[derive(PartialEq, Debug, Clone, Copy)]
/// Enum representing the type of run for the simulation.
pub enum RunType {
    Run,
    RecordTrace,
    RecordFullTrace,
}

/// Enum representing the data returned by the simulation.
pub enum Data {
    Fault(Vec<FaultData>),
    Trace(Vec<TraceRecord>),
    None,
}

/// Struct representing the control for the simulation.
pub struct Control<'a> {
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
    ///
    /// # Returns
    ///
    /// * `Self` - Returns a new `Control` instance.
    pub fn new(
        program_data: &'a ElfFile,
        decision_activation_active: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
    ) -> Self {
        // Setup cpu emulation
        let mut emu = Cpu::new(
            program_data,
            success_addresses,
            failure_addresses,
            initial_registers,
        );
        // Cpu setup
        emu.setup_mmio();
        emu.setup_breakpoints(decision_activation_active);
        // Write code to memory area
        emu.load_code();

        Self { emu }
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
    fn run(&mut self, cycles: usize, run_successful: bool) -> RunState {
        // Initial and load program
        self.init(run_successful);
        // Start execution with the given amount of instructions
        let ret_info = self.emu.run_steps(cycles, false);

        info!("Program stopped successful {:?}", ret_info);
        // Return emulation state
        self.emu.get_state()
    }

    /// Initialize cpu state and load the program code into the cpu
    /// and set the initial state
    fn init(&mut self, run_successful: bool) {
        self.emu.init_register();
        // Write code to memory area
        self.emu.load_code();
        // Set initial state
        self.emu.init_cpu_state();
        // Init state
        self.emu.init_states(run_successful);
    }

    /// Checks the program for correct behavior.
    /// Check if code under investigation is working correct for
    /// positive and negative execution
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the check.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn check_program(&mut self, cycles: usize) -> Result<(), String> {
        // Deactivate io print
        self.emu.deactivate_printf_function();
        if self.run(cycles, true) != RunState::Success {
            return Err(
                "Program function check failed. Success path is not working properly!".to_string(),
            );
        }
        if self.run(cycles, false) != RunState::Failed {
            return Err(
                "Program function check failed. Failure path is not working properly!".to_string(),
            );
        }
        println!("Program checked successfully");
        Ok(())
    }

    /// Runs the simulation with the specified faults.
    /// Execute or trace loaded code with the given faults
    /// If code execution with successful state, a vector array will be returned with the injected faults
    /// If code tracing was activated a vector array with the trace records will be returned
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the simulation.
    /// * `run_type` - The type of run to execute (e.g., normal, stress test).
    /// * `deep_analysis` - Whether to perform a deep analysis during the simulation.
    /// * `records` - A collection of records to be used during the simulation.
    ///
    /// # Returns
    ///
    /// * `Result<Data, String>` - Returns the resulting data from the simulation if successful, otherwise an error message.
    pub fn run_with_faults(
        &mut self,
        cycles: usize,
        run_type: RunType,
        deep_analysis_trace: bool,
        faults: &[FaultRecord],
    ) -> Result<Data, String> {
        let mut restore_required = false;
        // Initialize and load
        self.init(false);
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
            RunType::Run => {
                // Enable basic tracing for error reporting (but don't start recording yet)
                self.emu.set_trace_hook();
            }
        }

        // Enable tracing for error reporting purposes (capture last 10-20 instructions)
        if run_type == RunType::Run {
            self.emu.start_tracing(false); // Start basic tracing without registers
        }

        // Preload instruction backup if fault is inserted with index = 0
        let (mut address, mut instruction) = self.emu.asm_cmd_read();
        // Iterate over all faults and run the program step by step
        for fault in faults {
            if fault.index != 0 {
                // One single step
                if let Err(e) = self.emu.run_steps(1, false) {
                    let error_msg = self.report_unicorn_error(e, "fault injection step 1");
                    return Err(error_msg);
                }
                // Restore instruction if required
                if restore_required {
                    self.emu.asm_cmd_write(address, &instruction).unwrap();
                    restore_required = false;
                }
                // Execute remaining steps
                if fault.index != 1 {
                    if let Err(e) = self.emu.run_steps(fault.index - 1, false) {
                        let error_msg = self.report_unicorn_error(e, "fault injection steps");
                        return Err(error_msg);
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
            RunType::Run => {
                if self.emu.get_state() == RunState::Success {
                    return Err("Successfull state reached before critical glitch inserted! Maybe failure can be triggered with less glitches".to_string());
                }
            }
            _ => (),
        }

        // Run to completion
        if restore_required {
            if let Err(e) = self.emu.run_steps(1, false) {
                let error_msg = self.report_unicorn_error(e, "instruction restore step");
                return Err(error_msg);
            }
            self.emu.asm_cmd_write(address, &instruction).unwrap();
        }
        if let Err(e) = self.emu.run_steps(cycles, false) {
            let error_msg = self.report_unicorn_error(e, "final execution cycles");
            return Err(error_msg);
        }

        // Cleanup and return data to caller
        match run_type {
            RunType::RecordTrace | RunType::RecordFullTrace => {
                self.emu.clear_fault_data();

                // Reduce traces if necessary
                if !deep_analysis_trace {
                    self.emu.reduce_trace();
                }
                Ok(Data::Trace(self.emu.get_trace_data().clone()))
            }
            RunType::Run => {
                // Check if fault attack was successful if yes return faults
                if self.emu.get_state() == RunState::Success {
                    Ok(Data::Fault(self.emu.get_fault_data().clone()))
                } else {
                    Ok(Data::None)
                }
            }
        }
    }

    /// Helper method to report unicorn emulator errors
    fn report_unicorn_error(&mut self, error: uc_error, context: &str) -> String {
        let pc = self.emu.get_program_counter();
        eprintln!("Unicorn error during {}: {:?} at PC 0x{:08X}", context, error, pc);
        format!("Simulation failed during {}: {:?} at PC 0x{:08X}", context, error, pc)
    }
}
