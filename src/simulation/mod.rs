mod cpu;
pub use cpu::*;

mod fault;
pub use fault::{FaultData, FaultType, SimulationFaultRecord, TraceRecord};

use log::info;

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RunType {
    Run,
    RecordTrace,
    RecordFullTrace,
}

pub enum Data {
    Fault(Vec<FaultData>),
    Trace(Vec<TraceRecord>),
    None,
}

pub struct Control<'a> {
    emu: Cpu<'a>,
}

impl<'a> Control<'a> {
    /// Create a new instance of the control module
    /// The elf file is used to load the program code
    /// and to setup the cpu emulation
    pub fn new(program_data: &'a ElfFile) -> Self {
        // Setup cpu emulation
        let mut emu = Cpu::new(program_data);
        // Cpu setup
        emu.setup_mmio();
        emu.setup_breakpoints();
        Self { emu }
    }

    /// Setup system state to a successful or failed state
    /// and run the program. Return the state of the program after compilation
    fn run(&mut self, run_successful: bool) -> RunState {
        // Initial and load program
        self.init_and_load(run_successful);
        // Start execution with the given amount of instructions
        let ret_info = self.emu.run_steps(MAX_INSTRUCTIONS, false);

        info!("Program stopped successful {:?}", ret_info);
        // Return emulation state
        self.emu.get_state()
    }

    /// Initialize registers and load the program code into the cpu
    /// and set the initial state
    fn init_and_load(&mut self, run_successful: bool) {
        self.emu.init_register();
        // Write code to memory area
        self.emu.load_code();
        // Init state
        self.emu.init_states(run_successful);
    }

    /// Check if code under investigation is working correct for
    /// positive and negative execution
    pub fn check_program(&mut self) -> Result<(), String> {
        // Deactivate io print
        self.emu.deactivate_printf_function();
        if self.run(true) != RunState::Success {
            return Err(
                "Program function check failed. Success path is not working properly!".to_string(),
            );
        }
        if self.run(false) != RunState::Failed {
            return Err(
                "Program function check failed. Failure path is not working properly!".to_string(),
            );
        }
        println!("Program checked successfully");
        Ok(())
    }

    /// Execute or trace loaded code with the given faults
    /// If code execution with successful state, a vector array will be returned with the injected faults
    /// If code tracing was activated a vector array with the trace records will be returned
    pub fn run_with_faults(
        &mut self,
        run_type: RunType,
        low_complexity_trace: bool,
        faults: &[SimulationFaultRecord],
    ) -> Result<Data, String> {
        // Initialize and load
        self.init_and_load(false);
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

        // Iterate over all faults and run the program step by step
        for fault in faults {
            let mut ret_val = Ok(());
            if fault.index != 0 {
                ret_val = self.emu.run_steps(fault.index, false);
            }
            if ret_val.is_ok() {
                self.emu.execute_fault_injection(fault);
            } else {
                return Ok(Data::None);
            }
        }

        // Start tracing or check previous run state
        match run_type {
            RunType::RecordTrace => {
                self.emu.start_tracing(false);
            }
            RunType::Run => {
                if self.emu.get_state() == RunState::Success {
                    return Err("This should not happen. Successfull state reached before critical glitch inserted!".to_string());
                }
            }
            _ => (),
        }

        // Run to completion
        let ret_val = self.emu.run_steps(MAX_INSTRUCTIONS, false);
        if ret_val.is_err() {
            return Ok(Data::None);
        }

        // Cleanup and return data to caller
        match run_type {
            RunType::RecordTrace | RunType::RecordFullTrace => {
                self.emu.release_usage_fault_hooks();

                // Reduce traces if necessary
                if low_complexity_trace {
                    self.emu.reduce_trace();
                }
                Ok(Data::Trace(self.emu.get_trace().clone()))
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
}
