pub mod faults;
pub mod user_thread;

use user_thread::{start_worker_threads, WorkloadMessage};

use super::simulation::{
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    Control, RunType,
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
    handles: Vec<thread::JoinHandle<()>>,
    work_load_counter: std::sync::Arc<std::sync::Mutex<usize>>,
    success_addresses: Vec<u64>,
    failure_addresses: Vec<u64>,
    initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
}

impl FaultAttacks {
    /// Creates a new `FaultAttacks` instance from the given ELF file path.
    ///
    /// This function initializes the fault attack simulation environment by loading the ELF file,
    /// setting up worker threads for parallel execution, and configuring simulation parameters.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the ELF file containing the target program.
    /// * `cycles` - Maximum number of CPU cycles/instructions to execute during simulation.
    /// * `deep_analysis` - Enable deep analysis for repeated code patterns (e.g., loops).
    /// * `run_through` - Continue simulation without stopping at the first successful fault injection.
    /// * `threads` - Number of worker threads to use for parallel execution (must be > 0).
    /// * `success_addresses` - Memory addresses that indicate successful attack when accessed.
    /// * `failure_addresses` - Memory addresses that indicate attack failure when accessed.
    /// * `initial_registers` - Initial CPU register values to set before simulation starts.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully initialized FaultAttacks instance.
    /// * `Err(String)` - Error message if initialization fails (invalid file, thread count, etc.).
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The ELF file cannot be loaded or parsed
    /// - The thread count is zero
    /// - Worker thread initialization fails
    pub fn new(
        path: std::path::PathBuf,
        cycles: usize,
        deep_analysis: bool,
        run_through: bool,
        threads: usize,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
    ) -> Result<Self, String> {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path)?;

        // Create a channel for sending lines to threads
        let (workload_sender, workload_receiver): (
            Sender<WorkloadMessage>,
            Receiver<WorkloadMessage>,
        ) = unbounded();
        // Create a counter for the workload done
        let work_load_counter = Arc::new(Mutex::new(0));

        // Create a new thread to handle the workload
        // Shared receiver for threads
        let workload_receiver = workload_receiver.clone();

        if threads == 0 {
            return Err("Number of threads must be greater than 0".to_string());
        }

        // Generate worker threads
        let handles = start_worker_threads(
            threads,
            cycles,
            &file_data,
            &workload_receiver,
            &work_load_counter,
            success_addresses.clone(),
            failure_addresses.clone(),
            initial_registers.clone(),
        )
        .unwrap();

        // Return the FaultAttacks instance
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
            handles,
            work_load_counter,
            success_addresses,
            failure_addresses,
            initial_registers,
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

    /// Executes single fault injection attacks across specified fault groups.
    ///
    /// This method iterates through all fault types in the provided groups and tests
    /// each fault individually. It stops at the first successful attack unless
    /// `run_through` mode is enabled.
    ///
    /// # Arguments
    ///
    /// * `groups` - Iterator over fault group names (e.g., "glitch", "regbf", "regfld").
    ///
    /// # Returns
    ///
    /// * `Ok((success, count))` where:
    ///   - `success`: `true` if at least one fault injection succeeded
    ///   - `count`: Total number of attack attempts executed
    /// * `Err(String)` - Error message if simulation fails
    ///
    /// # Behavior
    ///
    /// - Sets initial program trace before starting attacks
    /// - Tests each fault type individually
    /// - Accumulates successful attacks in `self.fault_data`
    /// - Respects `run_through` flag for early termination
    pub fn single(&mut self, groups: &mut Iter<String>) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        self.set_initial_trace()?; // Set initial trace data

        for list in lists {
            // Iterate over all faults in the list
            for fault in list {
                // Get fault type
                let fault = get_fault_from(&fault).unwrap();

                // Run simulation with fault
                let mut fault_data = self.fault_simulation(std::slice::from_ref(&fault))?;

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

    /// Executes double fault injection attacks using all pairwise combinations.
    ///
    /// This method tests every possible pair of faults from the specified groups,
    /// including combinations of the same fault type. It's useful for finding
    /// vulnerabilities that require multiple coordinated fault injections.
    ///
    /// # Arguments
    ///
    /// * `groups` - Iterator over fault group names to generate pairs from.
    ///
    /// # Returns
    ///
    /// * `Ok((success, count))` where:
    ///   - `success`: `true` if at least one double fault injection succeeded
    ///   - `count`: Total number of attack pairs tested
    /// * `Err(String)` - Error message if simulation fails
    ///
    /// # Note
    ///
    /// The number of attacks grows quadratically with the fault list size.
    /// For a list of N faults, this will test N² combinations.
    pub fn double(&mut self, groups: &mut Iter<String>) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        self.set_initial_trace()?; // Set initial trace data

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

    /// Executes fault simulation for a specific sequence of fault injections.
    ///
    /// This is the core simulation engine that handles both single and multiple
    /// fault injections. It recursively builds fault combinations and distributes
    /// simulation work across worker threads.
    ///
    /// # Arguments
    ///
    /// * `faults` - Ordered sequence of faults to inject during execution.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Vec<FaultData>>)` - Vector of successful attack results, where each
    ///   inner vector contains the fault data for one successful attack scenario.
    /// * `Err(String)` - Error message if simulation setup or execution fails.
    ///
    /// # Process
    ///
    /// 1. Records initial program trace if not already available
    /// 2. Filters potential injection points based on first fault type
    /// 3. Recursively builds fault injection combinations
    /// 4. Distributes simulation work to worker threads
    /// 5. Collects and returns successful attack results
    ///
    /// # Performance
    ///
    /// Uses parallel execution across multiple worker threads for efficiency.
    /// Progress is tracked via shared counters and channels.
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

        // Setup the trace response channel if not already set
        if self.initial_trace.is_empty() {
            // Run full trace
            self.set_initial_trace()?;
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

        // Create a channel for collecting results from threads
        let (fault_response_sender, fault_response_receiver) = unbounded();

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
                    number = self.fault_simulation_inner(
                        fault_response_sender.clone(),
                        remaining_faults,
                        &simulation_fault_records,
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
        let data: Vec<_> = fault_response_receiver.try_iter().collect();
        println!("-> {} attacks executed, {} successful", n, data.len());
        if data.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(data)
        }
    }

    /// Recursively generates and executes fault injection combinations.
    ///
    /// This internal function handles the recursive fault combination logic.
    /// It either executes a final simulation (when no faults remain) or
    /// continues building fault combinations by adding the next fault type.
    ///
    /// # Arguments
    ///
    /// * `fault_response_sender` - Channel for collecting successful attack results.
    /// * `remaining_faults` - Faults still to be added to the current combination.
    /// * `simulation_fault_records` - Current fault injection sequence being built.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of simulation runs spawned from this recursion branch.
    /// * `Err(String)` - Error message if fault record creation or transmission fails.
    ///
    /// # Algorithm
    ///
    /// - Base case: If no remaining faults, submit simulation job to worker threads
    /// - Recursive case: Record trace with current faults, filter injection points,
    ///   then recurse for each valid injection point with remaining faults
    fn fault_simulation_inner(
        &self,
        fault_response_sender: Sender<Vec<FaultData>>,
        remaining_faults: &[FaultType],
        simulation_fault_records: &[FaultRecord],
    ) -> Result<usize, String> {
        let mut n = 0;

        // Check if there are no remaining faults left
        if remaining_faults.is_empty() {
            // Run fault simulation. This is the end of the recursion
            self.workload_sender
                .as_ref()
                .unwrap()
                .send(WorkloadMessage {
                    run_type: RunType::Run,
                    deep_analysis: false,
                    fault_records: simulation_fault_records.to_vec(),
                    trace_sender: None,
                    fault_sender: Some(fault_response_sender),
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
                    fault_sender: None,
                })
                .unwrap();

            let mut records = trace_response_receiver
                .recv()
                .expect("Unable to receive trace data");

            // Split faults into first and remaining faults
            let (first_fault, remaining_faults) = remaining_faults.split_first().unwrap();
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
                        fault_response_sender.clone(),
                        remaining_faults,
                        &index_simulation_fault_records,
                    )?;
                }
            }
        }

        Ok(n)
    }

    /// Retrieves execution trace data for analysis of fault injection results.
    ///
    /// This function submits a trace recording request to worker threads and
    /// returns the collected execution trace for the specified fault sequence.
    ///
    /// # Arguments
    ///
    /// * `run_type` - Type of trace recording (normal trace, full trace, or execution only).
    /// * `deep_analysis` - Enable detailed analysis of loops and repeated code patterns.
    /// * `fault_data` - Sequence of fault injections to apply during trace recording.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<TraceRecord>)` - Collected execution trace records.
    /// * `Err(String)` - Error message if trace recording fails or times out.
    ///
    /// # Usage
    ///
    /// Used for debugging successful attacks and understanding program behavior
    /// under fault injection conditions.
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
                fault_sender: None,
            })
            .unwrap();
        let trace_record = trace_response_receiver
            .recv()
            .expect("Unable to receive trace data");
        Ok(trace_record)
    }

    /// Displays disassembled execution trace for a specific successful attack.
    ///
    /// This function retrieves and prints the complete execution trace for the
    /// specified attack number, including disassembled instructions and fault
    /// injection points.
    ///
    /// # Arguments
    ///
    /// * `attack_number` - 1-based index of the attack to analyze (must be > 0).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Trace successfully printed.
    /// * `Err(String)` - Error if attack number is invalid or trace retrieval fails.
    ///
    /// # Note
    ///
    /// Requires that fault simulation has been run and successful attacks exist
    /// in `self.fault_data`.
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

    /// Set initial trace data for the `FaultAttacks` instance.
    ///
    fn set_initial_trace(&mut self) -> Result<(), String> {
        // Run full trace
        self.initial_trace =
            self.get_trace_data(RunType::RecordTrace, self.deep_analysis, [].to_vec())?;
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
        let mut simulation = Control::new(
            &self.file_data,
            true,
            self.success_addresses.clone(),
            self.failure_addresses.clone(),
            self.initial_registers.clone(),
        );
        simulation.check_program(self.cycles)
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
