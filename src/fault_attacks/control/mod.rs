use super::ElfFile;

mod cpu;
use cpu::*;
pub use cpu::{FaultData, FaultType};

use std::fmt;

use log::info;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct TraceRecord {
    pub address: u64,
    pub size: usize,
    pub asm_instruction: Vec<u8>,
    pub registers: Option<[u32; 17]>,
}

#[derive(Clone)]
pub struct SimulationFaultRecord {
    pub index: usize,
    pub record: TraceRecord,
    pub fault_type: FaultType,
}

impl TraceRecord {
    pub fn get_fault_record(&self, index: usize, fault_type: FaultType) -> SimulationFaultRecord {
        SimulationFaultRecord {
            index,
            record: self.clone(),
            fault_type,
        }
    }
}

impl fmt::Debug for SimulationFaultRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "address: 0x{:X} size: 0x{:?} fault_type: {:?}",
            self.record.address, self.record.size, self.fault_type
        )
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum RunType {
    Run,
    RecordTrace,
    RecordFullTrace,
}

pub struct Control<'a> {
    emu: Cpu<'a>,
}

impl<'a> Control<'a> {
    /// Create a new instance of the control module
    /// The elf file is used to load the program code
    /// and to setup the cpu emulation
    ///
    pub fn new(program_data: &'a ElfFile) -> Self {
        // Setup cpu emulation
        let mut emu = Cpu::new(program_data);
        // Cpu setup
        emu.setup_mmio();
        emu.setup_breakpoints();
        Self { emu }
    }

    /// Setup system state to a successful or failed state
    /// and run the program. Return the state of the program after complition
    ///
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
    ///
    fn init_and_load(&mut self, run_successful: bool) {
        self.emu.init_register();
        // Write code to memory area
        self.emu.load_code();
        // Init state
        self.emu.init_states(run_successful);
    }

    /// Check if code under investigation is working correct for
    /// positive and negative execution
    ///
    pub fn check_program(&mut self) {
        assert_eq!(self.run(true), RunState::Success);
        assert_eq!(self.run(false), RunState::Failed);
    }

    /// Execute or trace loaded code with the given faults
    /// If code execution with successful state, a vector array will be returned with the injected faults
    /// If code traceing was activated a vector array with the trace records will be returned
    ///
    pub fn run_with_faults(
        &mut self,
        run_type: RunType,
        low_complexity_trace: bool,
        faults: Vec<SimulationFaultRecord>,
    ) -> (Option<Vec<FaultData>>, Option<&Vec<TraceRecord>>) {
        // Initialize and load
        self.init_and_load(false);
        // Deactivate io print
        self.emu.deactivate_printf_function();

        // Write all faults into fault_data list
        faults.iter().for_each(|attack| self.emu.set_fault(attack));

        if run_type != RunType::Run {
            // Set hook with faults and run program
            self.emu.set_trace_hook(faults);
        }

        // If full trace is required, switch on tracing from the beginning
        if run_type == RunType::RecordFullTrace {
            self.emu.start_tracing();
            self.emu.with_register_data();
        }

        let fault_data = self.emu.get_fault_data().clone();
        // Iterate over all faults and run the program step by step
        fault_data.iter().for_each(|fault| {
            let mut ret_val = Ok(());
            if fault.fault.index != 0 {
                ret_val = self.emu.run_steps(fault.fault.index, false);
            }
            if ret_val.is_ok() {
                self.emu.execute_fault_injection(&fault);
                // If full trace is required, add fault cmds to trace
                if run_type == RunType::RecordFullTrace {
                    self.emu.add_to_trace(fault);
                }
            }
        });

        // Start tracing or check previous run state
        match run_type {
            RunType::RecordTrace | RunType::RecordFullTrace => {
                self.emu.start_tracing();
            }
            _ => {
                if self.emu.get_state() == RunState::Success {
                    println!("Da schein ein Fehler aufgetreten zu sein");
                    return (None, None);
                }
            }
        }

        // Run
        let _ret_val = self.emu.run_steps(MAX_INSTRUCTIONS, false);
        if run_type != RunType::Run {
            self.emu.release_usage_fault_hooks();

            if low_complexity_trace {
                self.emu.reduce_trace();
            }
        }

        // Check for available trace data
        if run_type != RunType::Run {
            (None, Some(self.emu.get_trace()))
        } else {
            // Check if fault attack was successful
            if self.emu.get_state() == RunState::Success {
                (Some(fault_data), None)
            } else {
                (None, None)
            }
        }
    }
}
