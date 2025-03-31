pub mod faults;

use super::simulation::{
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    Control, Data, RunType,
};
use crate::{disassembly::Disassembly, elf_file::ElfFile};
use faults::*;
use itertools::iproduct;
use log::debug;
use rayon::prelude::*;
use std::{
    slice::Iter,
    sync::mpsc::{channel, Sender},
};

/// Struct representing fault attacks.
pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<Vec<FaultData>>,
    pub count_sum: usize,
}

impl FaultAttacks {
    /// Creates a new `FaultAttacks` instance from the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - A `PathBuf` representing the path to the ELF file.
    ///
    /// # Returns
    ///
    /// * `Result<Self, String>` - Returns a `FaultAttacks` instance if successful, otherwise an error message.
    pub fn new(path: std::path::PathBuf) -> Result<Self, String> {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path)?;

        Ok(Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: Vec::new(),
            count_sum: 0,
        })
    }

    /// Sets the fault data for the `FaultAttacks` instance.
    ///
    /// # Arguments
    ///
    /// * `fault_data` - A vector of vectors containing `FaultData`.
    pub fn set_fault_data(&mut self, fault_data: Vec<Vec<FaultData>>) {
        self.fault_data = fault_data;
    }

    /// Prints the fault data.
    pub fn print_fault_data(&self) {
        let debug_context = self.file_data.get_debug_context();

        self.cs
            .print_fault_records(&self.fault_data, &debug_context);
    }

    /// Prints the trace for a specific fault.
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the trace.
    /// * `attack_number` - The attack number to trace.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn print_trace_for_fault(&self, cycles: usize, attack_number: usize) -> Result<(), String> {
        if !self.fault_data.is_empty() {
            let fault_records = FaultData::get_simulation_fault_records(
                self.fault_data.get(attack_number).unwrap(),
            );
            // Run full trace
            let trace_records = Some(trace_run(
                &mut Control::new(&self.file_data, false),
                cycles,
                RunType::RecordFullTrace,
                true,
                &fault_records,
            )?);
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            let debug_context = self.file_data.get_debug_context();

            self.cs
                .disassembly_trace_records(&trace_records, &debug_context);
        }
        Ok(())
    }

    /// Prints the trace.
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the trace.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn print_trace(&self, cycles: usize) -> Result<(), String> {
        // Run full trace
        let trace_records = Some(trace_run(
            &mut Control::new(&self.file_data, false),
            cycles,
            RunType::RecordFullTrace,
            true,
            &[],
        )?);

        let debug_context = self.file_data.get_debug_context();

        self.cs
            .disassembly_trace_records(&trace_records, &debug_context);

        Ok(())
    }

    /// Checks for correct behavior.
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the check.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn check_for_correct_behavior(&self, cycles: usize) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data, true);
        simulation.check_program(cycles)
    }

    /// Runs single glitch attacks.
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the attack.
    /// * `deep_analysis` - Whether to perform a deep analysis.
    /// * `groups` - An iterator over the fault groups.
    /// * `run_through` - Whether to run through all faults.
    ///
    /// # Returns
    ///
    /// * `Result<(bool, usize), String>` - Returns a tuple containing a boolean indicating success and the number of attacks.
    pub fn single(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        groups: &mut Iter<String>,
        run_through: bool,
    ) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        for list in lists {
            // Iterate over all faults in the list
            for fault in list {
                // Get fault type
                let fault = get_fault_from(&fault).unwrap();

                // Run simulation with fault
                let mut fault_data =
                    self.fault_simulation(cycles, &[fault.clone()], deep_analysis)?;

                if !fault_data.is_empty() {
                    // Push intermediate data to fault data
                    self.fault_data.append(&mut fault_data);
                    // check for run through flag
                    if !run_through {
                        return Ok((true, self.count_sum));
                    }
                    any_success = true;
                }
            }
        }
        Ok((any_success, self.count_sum))
    }

    /// Runs double glitch attacks.
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the attack.
    /// * `deep_analysis` - Whether to perform a deep analysis.
    /// * `groups` - An iterator over the fault groups.
    /// * `run_through` - Whether to run through all faults.
    ///
    /// # Returns
    ///
    /// * `Result<(bool, usize), String>` - Returns a tuple containing a boolean indicating success and the number of attacks.
    pub fn double(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        groups: &mut Iter<String>,
        run_through: bool,
    ) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        for list in lists {
            // Iterate over all faults in the list
            let iter = iproduct!(list.clone(), list).map(|(a, b)| (a, b));
            // Iterate over all fault pairs
            for t in iter {
                let fault1 = get_fault_from(&t.0).unwrap();
                let fault2 = get_fault_from(&t.1).unwrap();

                let mut fault_data =
                    self.fault_simulation(cycles, &[fault1, fault2], deep_analysis)?;

                if !fault_data.is_empty() {
                    // Push intermediate data to fault data
                    self.fault_data.append(&mut fault_data);
                    // check for run through flag
                    if !run_through {
                        return Ok((true, self.count_sum));
                    }
                    any_success = true;
                }
            }
        }
        Ok((any_success, self.count_sum))
    }

    /// Runs the fault simulation.
    ///
    /// # Arguments
    ///
    /// * `cycles` - The number of cycles to run the simulation.
    /// * `faults` - The faults to inject.
    /// * `deep_analysis` - Whether to perform a deep analysis.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Vec<FaultData>>, String>` - Returns a vector of fault data if successful, otherwise an error message.
    pub fn fault_simulation(
        &mut self,
        cycles: usize,
        faults: &[FaultType],
        deep_analysis: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        //
        println!("Running simulation for faults: {faults:?}");

        // Check if faults are empty
        if faults.is_empty() {
            return Ok(Vec::new());
        }

        // Run simulation to record normal fault program flow as a base for fault injection
        let mut records = trace_run(
            &mut Control::new(&self.file_data, false), // Use a temporary Control for tracing
            cycles,
            RunType::RecordTrace,
            deep_analysis,
            &[],
        )?;
        debug!("Number of trace steps: {}", records.len());

        let (sender, receiver) = channel();

        // Split faults into first and remaining faults
        let (first_fault, remaining_faults) = faults.split_first().unwrap();
        // Filter records according to fault type
        first_fault.filter(&mut records, &self.cs);

        // Run main fault simulation loop
        let n_result: Result<usize, String> = records
            .into_par_iter()
            .map_with(sender, |s, record| -> Result<usize, String> {
                // Create a simulation instance for each thread
                let mut simulation = Control::new(&self.file_data, false);
                let number;
                // Get index of the record
                if let TraceRecord::Instruction { index, .. } = record {
                    // Create a simulation fault record list with the first fault in the list
                    let simulation_fault_records = vec![FaultRecord {
                        index,
                        fault_type: first_fault.clone(),
                    }];

                    // Call recursive fault simulation with first simulation fault record
                    number = Self::fault_simulation_inner(
                        &mut simulation,
                        cycles,
                        remaining_faults,
                        &simulation_fault_records,
                        deep_analysis,
                        s,
                        &Disassembly::new(),
                    )?;
                } else {
                    return Err("No instruction record found".to_string());
                }

                Ok(number)
            })
            .sum();

        // Sum up successful attacks
        let n = n_result?;
        self.count_sum += n;

        // Return collected successful attacks to caller
        let data: Vec<_> = receiver.iter().collect();
        println!("-> {} attacks executed, {} successful", n, data.len());
        if data.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(data)
        }
    }

    /// Inner recursive function for fault simulation.
    ///
    /// # Arguments
    ///
    /// * `file_data` - The ELF file data.
    /// * `cycles` - The number of cycles to run the simulation.
    /// * `faults` - The faults to inject.
    /// * `simulation_fault_records` - The current simulation fault records.
    /// * `deep_analysis` - Whether to perform a deep analysis.
    /// * `s` - The sender for fault data.
    /// * `cs` - The disassembly context.
    ///
    /// # Returns
    ///
    /// * `Result<usize, String>` - Returns the number of successful attacks if successful, otherwise an error message.
    fn fault_simulation_inner(
        simulation: &mut Control,
        cycles: usize,
        faults: &[FaultType],
        simulation_fault_records: &[FaultRecord],
        deep_analysis: bool,
        s: &mut Sender<Vec<FaultData>>,
        cs: &Disassembly,
    ) -> Result<usize, String> {
        let mut n = 0;

        // Check if there are no remaining faults left
        if faults.is_empty() {
            // Run fault simulation. This is the end of the recursion
            simulation_run(simulation, cycles, simulation_fault_records, s)?;
            n += 1;
        } else {
            // Collect trace records with simulation fault records to get new running length (time)
            let mut records = trace_run(
                simulation,
                cycles,
                RunType::RecordTrace,
                deep_analysis,
                simulation_fault_records,
            )?;

            // Split faults into first and remaining faults
            let (first_fault, remaining_faults) = faults.split_first().unwrap();
            // Filter records according to fault type
            first_fault.filter(&mut records, cs);
            // Iterate over trace records
            for record in records {
                // Get index of the record
                if let TraceRecord::Instruction { index, .. } = record {
                    // Create a copy of the simulation fault records
                    let mut index_simulation_fault_records = simulation_fault_records.to_vec();
                    // Add the created simulation fault record to the list of simulation fault records
                    index_simulation_fault_records.push(FaultRecord {
                        index,
                        fault_type: first_fault.clone(),
                    });

                    // Call recursive fault simulation with remaining faults
                    n += Self::fault_simulation_inner(
                        simulation,
                        cycles,
                        remaining_faults,
                        &index_simulation_fault_records,
                        deep_analysis,
                        s,
                        cs,
                    )?;
                }
            }
        }

        Ok(n)
    }
}

/// Runs the simulation with faults for the specified number of cycles and returns the resulting data.
///
/// # Arguments
///
/// * `cycles` - The number of cycles to run the simulation.
/// * `run_type` - The type of run to execute (e.g., normal, stress test).
/// * `deep_analysis` - A boolean indicating whether to perform a deep analysis during the simulation.
/// * `records` - A collection of records to be used during the simulation.
///
/// # Returns
///
/// * `data` - The resulting data from running the simulation with faults.
///
/// # Errors
///
/// This function will return an error if the simulation fails to run with the specified faults.
fn trace_run(
    simulation: &mut Control,
    cycles: usize,
    run_type: RunType,
    deep_analysis: bool,
    records: &[FaultRecord],
) -> Result<Vec<TraceRecord>, String> {
    let data = simulation.run_with_faults(cycles, run_type, deep_analysis, records)?;
    match data {
        Data::Trace(trace) => Ok(trace),
        _ => Ok(Vec::new()),
    }
}

/// Runs the simulation with faults and sends the resulting fault data to the provided sender.
///
/// # Arguments
///
/// * `file_data` - The ELF file data.
/// * `cycles` - The number of cycles to run the simulation.
/// * `records` - A collection of fault records to be used during the simulation.
/// * `s` - The sender for fault data.
///
/// # Returns
///
/// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
fn simulation_run(
    simulation: &mut Control,
    cycles: usize,
    records: &[FaultRecord],
    s: &mut Sender<Vec<FaultData>>,
) -> Result<(), String> {
    let data = simulation.run_with_faults(cycles, RunType::Run, false, records)?;
    if let Data::Fault(fault) = data {
        if !fault.is_empty() {
            s.send(fault).unwrap();
        }
    }

    Ok(())
}
