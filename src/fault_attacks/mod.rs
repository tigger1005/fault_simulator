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
use std::{
    slice::Iter,
    sync::{Arc, Mutex},
};

use crossbeam_channel::{unbounded, Receiver, Sender};
use std::thread;

/// Struct representing fault attacks.
pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<Vec<FaultData>>,
    pub count_sum: usize,
    cycles: usize,
    workload_sender: Sender<Vec<FaultRecord>>,
    result_receiver: Receiver<Vec<FaultData>>,
    handles: Vec<thread::JoinHandle<()>>,
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
    pub fn new(path: std::path::PathBuf, cycles: usize) -> Result<Self, String> {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path)?;

        // Create a channel for sending lines to threads
        let (workload_sender, workload_receiver) = unbounded::<Vec<FaultRecord>>();
        // Create a channel for collecting results from threads
        let (result_sender, result_receiver) = unbounded();

        // Create a new thread to handle the workload
        // Shared receiver for threads
        let workload_receiver = Arc::new(Mutex::new(workload_receiver));

        let mut handles = vec![];
        for _ in 0..1 {
            // Copy data to be moved into threads
            let cycles = cycles.clone();
            let file_data = file_data.clone();
            let receiver = Arc::clone(&workload_receiver);
            let sender = result_sender.clone();
            let handle = thread::spawn(move || {
                // Create a new simulation instance
                let mut simulation = Control::new(&file_data, false);
                // Wait for workload
                // Loop until the workload receiver is closed
                while let Ok(records) = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv() {
                    // Todo: Do error handling
                    let data = simulation
                        .run_with_faults(cycles, RunType::Run, false, &records)
                        .unwrap();
                    if let Data::Fault(fault) = data {
                        sender.send(fault).expect("Unable to send result");
                    }
                }
            });
            handles.push(handle);
        }

        Ok(Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: Vec::new(),
            count_sum: 0,
            cycles,
            workload_sender,
            result_receiver,
            handles,
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
    /// * `attack_number` - The attack number to trace.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn print_trace_for_fault(&self, attack_number: usize) -> Result<(), String> {
        if !self.fault_data.is_empty() {
            let fault_records = FaultData::get_simulation_fault_records(
                self.fault_data.get(attack_number).unwrap(),
            );
            // Run full trace
            let trace_records = Some(trace_run(
                &mut Control::new(&self.file_data, false),
                self.cycles,
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
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn print_trace(&self) -> Result<(), String> {
        // Run full trace
        let trace_records = Some(trace_run(
            &mut Control::new(&self.file_data, false),
            self.cycles,
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
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn check_for_correct_behavior(&self) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data, true);
        simulation.check_program(self.cycles)
    }

    /// Runs single glitch attacks.
    ///
    /// # Arguments
    ///
    /// * `deep_analysis` - Whether to perform a deep analysis.
    /// * `groups` - An iterator over the fault groups.
    /// * `run_through` - Whether to run through all faults.
    ///
    /// # Returns
    ///
    /// * `Result<(bool, usize), String>` - Returns a tuple containing a boolean indicating success and the number of attacks.
    pub fn single(
        &mut self,
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
                    self.fault_simulation(&[fault.clone()], deep_analysis)?;

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
    /// * `deep_analysis` - Whether to perform a deep analysis.
    /// * `groups` - An iterator over the fault groups.
    /// * `run_through` - Whether to run through all faults.
    ///
    /// # Returns
    ///
    /// * `Result<(bool, usize), String>` - Returns a tuple containing a boolean indicating success and the number of attacks.
    pub fn double(
        &mut self,
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
                    self.fault_simulation(&[fault1, fault2], deep_analysis)?;

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
    /// * `faults` - The faults to inject.
    /// * `deep_analysis` - Whether to perform a deep analysis.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<Vec<FaultData>>, String>` - Returns a vector of fault data if successful, otherwise an error message.
    pub fn fault_simulation(
        &mut self,
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
            self.cycles,
            RunType::RecordTrace,
            deep_analysis,
            &[],
        )?;
        debug!("Number of trace steps: {}", records.len());

        // Split faults into first and remaining faults
        let (first_fault, remaining_faults) = faults.split_first().unwrap();
        // Filter records according to fault type
        first_fault.filter(&mut records, &self.cs);

        // Run main fault simulation loop
        let n_result: Result<usize, String> = records
            .into_iter()
            .map(|record| {
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
                        self.cycles,
                        remaining_faults,
                        &simulation_fault_records,
                        deep_analysis,
                        &mut self.workload_sender,
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
        let data: Vec<_> = self.result_receiver.iter().collect();
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
        workload_sender: &mut Sender<Vec<FaultRecord>>,
        cs: &Disassembly,
    ) -> Result<usize, String> {
        let mut n = 0;

        // Check if there are no remaining faults left
        if faults.is_empty() {
            // Run fault simulation. This is the end of the recursion
            workload_sender
                .send(simulation_fault_records.to_vec())
                .expect("Not able to send fault record to thread");
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
                        workload_sender,
                        cs,
                    )?;
                }
            }
        }

        Ok(n)
    }
}

/// Implements the `Drop` trait for `FaultAttacks`.
/// This trait is used to clean up the `FaultAttacks` instance when it goes out of scope.
/// It ensures that all threads are properly joined and that the sender channels are closed.
impl Drop for FaultAttacks {
    /// Cleans up the `FaultAttacks` instance by resetting the fault data.
    fn drop(&mut self) {
        // Drop the sender to signal threads no more data will be sent
        drop(self.workload_sender.clone());
        // Wait for all threads to finish processing
        for handle in self.handles.drain(..) {
            if let Err(e) = handle.join() {
                eprintln!("A thread panicked: {:?}", e);
            }
        }
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
