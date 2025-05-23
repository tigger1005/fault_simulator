pub mod faults;

use super::simulation::{
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    Control, Data, RunType,
};
use crate::{disassembly::Disassembly, elf_file::ElfFile};
use faults::*;
use itertools::iproduct;
// use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    slice::Iter,
    sync::{Arc, Mutex},
};

use crossbeam_channel::{unbounded, Receiver, Sender};

//use crossbeam_channel::{unbounded, Receiver, Sender};
use std::thread;

/// Type alias for the workload message sent to worker threads.
pub struct WorkloadMessage {
    pub run_type: RunType,
    pub deep_analysis: bool,
    pub fault_records: Vec<FaultRecord>,
    pub trace_sender: Option<Sender<Vec<TraceRecord>>>,
}

/// Struct representing fault attacks.
pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<Vec<FaultData>>,
    pub initial_trace: Vec<TraceRecord>,
    pub count_sum: usize,
    deep_analysis: bool,
    run_through: bool,
    cycles: usize,
    /// Channel for sending workloads to worker threads.
    workload_sender: Option<Sender<WorkloadMessage>>,
    fault_response_receiver: Receiver<Vec<FaultData>>,
    handles: Vec<thread::JoinHandle<()>>,
    work_load_counter: std::sync::Arc<std::sync::Mutex<usize>>,
}

impl FaultAttacks {
    /// Creates a new `FaultAttacks` instance from the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the ELF file.
    /// * `cycles` - Number of cycles to run the program.
    /// * `deep_analysis` - Whether to perform deep analysis.
    /// * `run_through` - Whether to run through all faults.
    /// * `threads` - Number of threads to use (must be > 0).
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` if successful, otherwise `Err(String)` with an error message.
    pub fn new(
        path: std::path::PathBuf,
        cycles: usize,
        deep_analysis: bool,
        run_through: bool,
        threads: usize,
    ) -> Result<Self, String> {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path)?;

        // Create a channel for sending lines to threads
        let (workload_sender, workload_receiver): (
            Sender<WorkloadMessage>,
            Receiver<WorkloadMessage>,
        ) = unbounded();
        // Create a channel for collecting results from threads
        let (fault_response_sender, fault_response_receiver) = unbounded();
        // Create a counter for the workload done
        let work_load_counter = Arc::new(Mutex::new(0));

        // Create a new thread to handle the workload
        // Shared receiver for threads
        let workload_receiver = workload_receiver.clone();

        if threads == 0 {
            return Err("Number of threads must be greater than 0".to_string());
        }
        // Create a vector to hold the thread handles

        let mut handles = vec![];
        for _ in 0..threads {
            // Copy data to be moved into threads
            let file = file_data.clone();
            let receiver = workload_receiver.clone();
            let fault_sender = fault_response_sender.clone();
            let workload_counter = Arc::clone(&work_load_counter);
            let handle = thread::spawn(move || {
                // Wait for workload
                // Create a new simulation instance
                let mut simulation = Control::new(&file, false);
                // Loop until the workload receiver is closed
                while let Ok(msg) = receiver.recv() {
                    let WorkloadMessage {
                        run_type,
                        deep_analysis,
                        fault_records: records,
                        trace_sender,
                    } = msg;

                    // Todo: Do error handling
                    match run_type {
                        RunType::RecordFullTrace | RunType::RecordTrace => {
                            match Control::new(&file, false)
                                .run_with_faults(cycles, run_type, deep_analysis, &records)
                                .unwrap()
                            {
                                Data::Trace(trace) => trace_sender
                                    .unwrap()
                                    .send(trace)
                                    .expect("Unable to send trace data"),
                                _ => trace_sender
                                    .unwrap()
                                    .send(vec![])
                                    .expect("Unable to send trace data"),
                            }
                        }
                        RunType::Run => {
                            if let Data::Fault(fault) = simulation
                                .run_with_faults(cycles, run_type, deep_analysis, &records)
                                .unwrap()
                            {
                                if !fault.is_empty() {
                                    fault_sender.send(fault).expect("Unable to send fault data");
                                }
                            }
                            let mut counter = workload_counter.lock().unwrap();
                            *counter += 1;
                        }
                    }
                }
            });
            handles.push(handle);
        }

        Ok(Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: Vec::new(),
            initial_trace: Vec::new(),
            count_sum: 0,
            deep_analysis,
            run_through,
            cycles,
            workload_sender: Some(workload_sender),
            fault_response_receiver,
            handles,
            work_load_counter,
        })
    }

    /// Sets the fault data for the `FaultAttacks` instance.
    ///
    /// # Arguments
    ///
    /// * `fault_data` - Fault data as a vector of vectors of `FaultData`.
    pub fn set_fault_data(&mut self, fault_data: Vec<Vec<FaultData>>) {
        self.fault_data = fault_data;
    }

    /// Prints the fault data using the disassembly context.
    pub fn print_fault_data(&self) {
        let debug_context = self.file_data.get_debug_context();

        self.cs
            .print_fault_records(&self.fault_data, &debug_context);
    }

    /// Get trace data from the fault data.
    ///
    /// # Arguments
    /// * `run_type` - The type of run to perform.
    /// * `deep_analysis` - Whether to perform a deep analysis.
    /// * `fault_data` - Fault records to process.
    ///
    /// # Returns
    /// * `Ok(Vec<TraceRecord>)` with trace records, or `Err(String)` on failure.
    pub fn get_trace_data(
        &self,
        run_type: RunType,
        deep_analysis: bool,
        fault_data: Vec<FaultRecord>,
    ) -> Result<Vec<TraceRecord>, String> {
        let (trace_response_sender, trace_response_receiver) = unbounded();
        self.workload_sender
            .as_ref()
            .unwrap()
            .send(WorkloadMessage {
                run_type,
                deep_analysis,
                fault_records: fault_data,
                trace_sender: Some(trace_response_sender),
            })
            .unwrap();
        let trace_record = trace_response_receiver
            .recv()
            .expect("Unable to receive trace data");
        Ok(trace_record)
    }

    /// Prints the trace for a specific fault.
    ///
    /// # Arguments
    ///
    /// * `attack_number` - Index of the attack to trace.
    ///
    /// # Returns
    ///
    /// * `Result<(), String>` - Returns `Ok` if successful, otherwise an error message.
    pub fn print_trace_for_fault(&self, attack_number: isize) -> Result<(), String> {
        if !self.fault_data.is_empty()
            && attack_number > 0
            && attack_number as usize <= self.fault_data.len()
        {
            let fault_records = FaultData::get_simulation_fault_records(
                self.fault_data.get(attack_number as usize - 1).unwrap(),
            );

            // Run full trace
            let trace_records = Some(self.get_trace_data(
                RunType::RecordFullTrace,
                true,
                fault_records.to_vec(),
            )?);
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            let debug_context = self.file_data.get_debug_context();

            self.cs
                .disassembly_trace_records(&trace_records, &debug_context);
        }
        Ok(())
    }

    /// Prints the trace for the program without faults.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful, otherwise `Err(String)`.
    pub fn print_trace(&self) -> Result<(), String> {
        // Run full trace
        let trace_records =
            Some(self.get_trace_data(RunType::RecordFullTrace, true, [].to_vec())?);

        let debug_context = self.file_data.get_debug_context();
        // Print trace
        self.cs
            .disassembly_trace_records(&trace_records, &debug_context);

        Ok(())
    }

    /// Checks for correct behavior of the program (no faults injected).
    ///
    /// # Returns
    ///
    /// * `Ok(())` if successful, otherwise `Err(String)`.
    pub fn check_for_correct_behavior(&self) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data, true);
        simulation.check_program(self.cycles)
    }

    /// Runs single glitch attacks.
    ///
    /// # Arguments
    ///
    /// * `groups` - Iterator over fault group names.
    ///
    /// # Returns
    ///
    /// * `Ok((bool, usize))` where bool indicates if any attack succeeded, usize is the number of attacks. Returns `Err(String)` on error.
    pub fn single(&mut self, groups: &mut Iter<String>) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        for list in lists {
            // Iterate over all faults in the list
            for fault in list {
                // Get fault type
                let fault = get_fault_from(&fault).unwrap();

                // Run simulation with fault
                let mut fault_data = self.fault_simulation(&[fault.clone()])?;

                if !fault_data.is_empty() {
                    // Push intermediate data to fault data
                    self.fault_data.append(&mut fault_data);
                    // check for run through flag
                    if !self.run_through {
                        return Ok((true, self.count_sum));
                    }
                    any_success = true;
                }
            }
        }
        Ok((any_success, self.count_sum))
    }

    /// Runs double glitch attacks (all pairs).
    ///
    /// # Arguments
    ///
    /// * `groups` - Iterator over fault group names.
    ///
    /// # Returns
    ///
    /// * `Ok((bool, usize))` where bool indicates if any attack succeeded, usize is the number of attacks. Returns `Err(String)` on error.
    pub fn double(&mut self, groups: &mut Iter<String>) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        for list in lists {
            // Iterate over all faults in the list
            let iter = iproduct!(list.clone(), list).map(|(a, b)| (a, b));
            // Iterate over all fault pairs
            for t in iter {
                let fault1 = get_fault_from(&t.0).unwrap();
                let fault2 = get_fault_from(&t.1).unwrap();

                let mut fault_data = self.fault_simulation(&[fault1, fault2])?;

                if !fault_data.is_empty() {
                    // Push intermediate data to fault data
                    self.fault_data.append(&mut fault_data);
                    // check for run through flag
                    if !self.run_through {
                        return Ok((true, self.count_sum));
                    }
                    any_success = true;
                }
            }
        }
        Ok((any_success, self.count_sum))
    }

    /// Runs the fault simulation for the given faults.
    ///
    /// # Arguments
    ///
    /// * `faults` - Slice of faults to inject.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Vec<FaultData>>)` with successful attacks, or `Err(String)` on error.
    pub fn fault_simulation(
        &mut self,
        faults: &[FaultType],
    ) -> Result<Vec<Vec<FaultData>>, String> {
        //
        println!("Running simulation for faults: {faults:?}");

        // Check if faults are empty
        if faults.is_empty() {
            return Ok(Vec::new());
        }

        // Setup the trace response channel
        if self.initial_trace.is_empty() {
            // Run full trace
            self.initial_trace =
                self.get_trace_data(RunType::RecordTrace, self.deep_analysis, [].to_vec())?;
        }

        // Split faults into first and remaining faults
        let (first_fault, remaining_faults) = faults.split_first().unwrap();
        // Filter records according to fault type
        let mut records = self.initial_trace.clone();
        first_fault.filter(&mut records, &self.cs);

        // Clear workload counter
        let mut counter = self.work_load_counter.lock().unwrap();
        *counter = 0;
        drop(counter);

        // Run main fault simulation loop
        let n_result: Result<usize, String> = records
            .into_iter()
            .map(|record| {
                let number;
                // Get index of the record
                if let TraceRecord::Instruction { index, .. } = record {
                    // Create a simulation fault record list with the first fault in the list
                    let simulation_fault_records = vec![FaultRecord {
                        index,
                        fault_type: first_fault.clone(),
                    }];

                    // Call recursive fault simulation with first simulation fault record
                    number =
                        self.fault_simulation_inner(remaining_faults, &simulation_fault_records)?;
                } else {
                    return Err("No instruction record found".to_string());
                }

                Ok(number)
            })
            .sum();

        // Sum up successful attacks
        let n = n_result?;
        self.count_sum += n;

        // Wait till the workload messegage is empty
        // while !self.workload_sender..is_empty() {
        //     std::thread::sleep(std::time::Duration::from_millis(10));
        // }

        // Wait that the workload counter is the same as the n_result
        while {
            let counter = self.work_load_counter.lock().unwrap();
            *counter != n
        } {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Return collected successful attacks to caller
        let data: Vec<_> = self.fault_response_receiver.try_iter().collect();
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
    /// * `faults` - Remaining faults to inject (slice).
    /// * `simulation_fault_records` - Current simulation fault records.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` with the number of successful attacks, or `Err(String)` on error.
    fn fault_simulation_inner(
        &self,
        faults: &[FaultType],
        simulation_fault_records: &[FaultRecord],
    ) -> Result<usize, String> {
        let mut n = 0;

        // Check if there are no remaining faults left
        if faults.is_empty() {
            // Run fault simulation. This is the end of the recursion
            self.workload_sender
                .as_ref()
                .unwrap()
                .send(WorkloadMessage {
                    run_type: RunType::Run,
                    deep_analysis: false,
                    fault_records: simulation_fault_records.to_vec(),
                    trace_sender: None,
                })
                .expect("Not able to send fault record to thread");
            n += 1;
        } else {
            // Collect trace records with simulation fault records to get new running length (time)
            // Setup the trace response channel
            let (trace_response_sender, trace_response_receiver) = unbounded();
            // Run simulation to record normal fault program flow as a base for fault injection
            self.workload_sender
                .as_ref()
                .unwrap()
                .send(WorkloadMessage {
                    run_type: RunType::RecordTrace,
                    deep_analysis: self.deep_analysis,
                    fault_records: simulation_fault_records.to_vec(),
                    trace_sender: Some(trace_response_sender),
                })
                .unwrap();

            let mut records = trace_response_receiver
                .recv()
                .expect("Unable to receive trace data");

            // Split faults into first and remaining faults
            let (first_fault, remaining_faults) = faults.split_first().unwrap();
            // Filter records according to fault type
            first_fault.filter(&mut records, &self.cs);
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
                    n += self.fault_simulation_inner(
                        remaining_faults,
                        &index_simulation_fault_records,
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
    /// Cleans up the `FaultAttacks` instance by resetting the fault data and joining threads.
    fn drop(&mut self) {
        // Drop the main workload channel
        self.workload_sender = None;

        // Wait for all threads to finish processing
        for handle in self.handles.drain(..) {
            if let Err(e) = handle.join() {
                eprintln!("A thread panicked: {:?}", e);
            }
        }
    }
}
