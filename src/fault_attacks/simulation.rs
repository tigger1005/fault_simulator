use super::ElfFile;

mod fault_injections;
use fault_injections::*;
pub use fault_injections::{FaultData, FaultType};

use log::debug;
use std::fmt;

#[derive(Copy, Clone)]
pub struct TraceRecord {
    address: u64,
    size: usize,
}

#[derive(Clone, Copy)]
pub struct SimulationFaultRecord {
    pub address: u64,
    pub size: usize,
    pub fault_type: FaultType,
}

impl SimulationFaultRecord {
    pub fn new(record_map: Vec<TraceRecord>) -> Vec<SimulationFaultRecord> {
        let mut list: Vec<SimulationFaultRecord> = Vec::new();
        record_map.iter().for_each(|record| {
            list.push(SimulationFaultRecord {
                address: record.address,
                size: record.size,
                fault_type: FaultType::Uninitialized,
            });
        });

        list
    }
    pub fn set_fault_type(&mut self, fault_type: FaultType) {
        self.fault_type = fault_type;
    }
}

impl fmt::Debug for SimulationFaultRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "address: 0x{:X} size: 0x{:?} fault_type: 0x{:?}",
            self.address, self.size, self.fault_type
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
        faults: Vec<SimulationFaultRecord>,
    ) -> Vec<SimulationFaultRecord> {
        // Initialize and load
        self.init_and_load(false);
        // Deactivate io print
        self.emu.deactivate_printf_function();

        // Set hook with faults and run program
        self.emu.set_trace_hook(faults);
        let _ret = self.emu.run_steps(MAX_INSTRUCTIONS, false);
        self.emu.release_usage_fault_hooks();
        // Convert from hashmap to vector array
        SimulationFaultRecord::new(self.emu.get_trace())
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
            .for_each(|attack| self.emu.set_fault(*attack));

        // Inverse order of list

        let fault_data = self.emu.get_fault_data().clone();
        // Get the first one, set it and start
        if !fault_data.is_empty() {
            // Set fault hooks
            fault_data
                .iter()
                .for_each(|fault_data_entry| self.emu.set_usage_fault_hook(fault_data_entry));

            // Run
            let _ret_val = self.emu.run_steps(MAX_INSTRUCTIONS, false);
            // Release all hooks
            self.emu.release_usage_fault_hooks();
            // Check state
            if self.emu.get_state() == RunState::Success {
                return Some(fault_data);
            }
        }

        None
    }
}
