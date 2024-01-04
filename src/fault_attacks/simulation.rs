use super::ElfFile;

mod fault_injections;
use fault_injections::*;
pub use fault_injections::{FaultData, FaultType};

use log::debug;
use std::fmt;

#[derive(Hash, PartialEq, Eq, Clone)]
pub struct TraceRecord {
    pub address: u64,
    pub size: usize,
    pub asm_instruction: Vec<u8>,
    pub registers: Option<[u32;17]>,
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

pub struct Simulation<'a> {
    emu: FaultInjections<'a>,
}

impl<'a> Simulation<'a> {
    pub fn new(file_data: &'a ElfFile) -> Self {
        // Setup emulator
        let mut emu = FaultInjections::new(file_data);
        // Initial setup
        emu.setup_mmio();
        emu.setup_breakpoints();
        Self { emu }
    }

    /// Check if code under investigation is working correct for
    /// positive and negative execution
    ///
    pub fn check_program(&mut self) {
        // Run simulation
        self.run(true);
        assert_eq!(self.emu.get_state(), RunState::Success);

        self.run(false);
        assert_eq!(self.emu.get_state(), RunState::Failed);
    }

    fn init_and_load(&mut self, run_successful: bool) {
        self.emu.init_register();
        // Write code to memory area
        self.emu.load_code();
        // Init state
        self.emu.init_states(run_successful);
    }

    /// Record the program flow till the program ends on positiv or negative program execution
    /// A vector array with the recorded addresses is returned
    ///
    pub fn record_code_trace(
        &mut self,
        full_trace: bool,
        low_complexity: bool,
        faults: Vec<SimulationFaultRecord>,
    ) -> &Vec<TraceRecord> {
        // Initialize and load
        self.init_and_load(false);
        // Deactivate io print
        self.emu.deactivate_printf_function();

        // Write all faults into fault_data list
        faults
            .iter()
            .for_each(|attack| self.emu.set_fault(attack));

        // Set hook with faults and run program
        self.emu.set_trace_hook(faults);

        let fault_data = self.emu.get_fault_data().clone();

        // If full trace is required, switch on tracing from the beginning
        if full_trace {
            self.emu.start_tracing();
            self.emu.with_register_data();
        }

        // Get the first one, set it and start
        fault_data.into_iter().for_each(|fault| {
            let mut ret_val = Ok(());
            if fault.fault.index != 0 {
                ret_val = self.emu.run_steps(fault.fault.index, false);
            }
            if ret_val.is_ok() {
                self.emu.skip_asm_cmds(&fault);
                // If full trace is required, add fault cmds to trace
                if full_trace {
                    self.emu.add_to_trace(&fault);
                }
            }
        });
        // Start tracing
        self.emu.start_tracing();

        // Run
        let _ret_val = self.emu.run_steps(MAX_INSTRUCTIONS, false);

        self.emu.release_usage_fault_hooks();

        if low_complexity {
            self.emu.reduce_trace();
        } 
        self.emu.get_trace()
    }

    fn run(&mut self, run_successful: bool) {
        let ret_info = self.run_till(run_successful, MAX_INSTRUCTIONS);

        if ret_info == Ok(()) {
            debug!("Program stopped successful");
        } else {
            debug!("Program stopped with {:?}", ret_info);
        }
        //print_register_and_data(emu);
    }

    fn run_till(&mut self, run_successful: bool, steps: usize) -> Result<(), uc_error> {
        self.init_and_load(run_successful);
        // Start execution
        debug!("Run : {} Steps", steps);
        self.emu.run_steps(steps, false)
    }

    /// Execute loaded code with the given faults injected bevor code execution
    /// If code finishes with successful state, a vector array will be returned with the
    /// injected faults
    ///
    pub fn run_with_faults(
        &mut self,
        external_record: &[SimulationFaultRecord],
    ) -> Option<Vec<FaultData>> {
        self.init_and_load(false);
        // Deactivate io print
        self.emu.deactivate_printf_function();

        // Write all faults into fault_data list
        external_record
            .iter()
            .for_each(|attack| self.emu.set_fault(attack));

        let fault_data = self.emu.get_fault_data().clone();
        // Get the first one, set it and start
        if !fault_data.is_empty() {
            fault_data.iter().for_each(|fault| {
                let mut ret_val = Ok(());
                if fault.fault.index != 0 {
                    ret_val = self.emu.run_steps(fault.fault.index, false);
                }
                if ret_val.is_ok() {
                    self.emu.skip_asm_cmds(fault);
                }
            });

            if self.emu.get_state() == RunState::Success {
                println!("Da schein ein Fehler aufgetreten zu sein");
                return None;
            }

            // Run
            let _ret_val = self.emu.run_steps(MAX_INSTRUCTIONS, false);
            // Check state
            if self.emu.get_state() == RunState::Success {
                return Some(fault_data);
            }
        }

        None
    }
}
