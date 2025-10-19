pub mod faults;

use crate::user_thread::UserThread;

use super::simulation::{
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    Control, RunType,
};
use crate::{disassembly::Disassembly, elf_file::ElfFile};
use faults::*;
use itertools::iproduct;
// use std::time::{SystemTime, UNIX_EPOCH};
use std::slice::Iter;

use crossbeam_channel::{unbounded, Sender};
/// Struct representing fault attacks.
pub struct FaultAttacks<'a> {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<Vec<FaultData>>,
    pub initial_trace: Vec<TraceRecord>,
    pub count_sum: usize,
    user_thread: &'a UserThread,
}

impl<'a> FaultAttacks<'a> {
    /// Creates a new `FaultAttacks` instance from existing ELF file and UserThread.
    ///
    /// This function initializes the fault attack simulation environment using
    /// pre-configured ELF file data and user thread instances. The worker threads
    /// should already be started on the UserThread before calling this function.
    ///
    /// # Arguments
    ///
    /// * `file_data` - Reference to loaded ELF file containing the target program.
    /// * `user_thread` - Reference to configured UserThread with worker threads started.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully initialized FaultAttacks instance.
    /// * `Err(String)` - Error message if initialization fails.
    ///
    /// # Note
    ///
    /// This constructor clones the ELF file data and stores a reference to the UserThread.
    /// The UserThread must outlive the FaultAttacks instance due to the lifetime constraint.
    pub fn new(file_data: &ElfFile, user_thread: &'a UserThread) -> Result<Self, String> {
        // Return the FaultAttacks instance
        Ok(Self {
            cs: Disassembly::new(),
            file_data: file_data.clone(),
            fault_data: Vec::new(),
            initial_trace: Vec::new(),
            count_sum: 0,
            user_thread,
        })
    }

    /// Sets the fault data collection for the `FaultAttacks` instance.
    ///
    /// This method replaces the current fault data with the provided collection
    /// of successful attack results. Each outer vector represents a different
    /// successful attack scenario, while the inner vector contains the fault
    /// data records for that specific attack.
    ///
    /// # Arguments
    ///
    /// * `fault_data` - Collection of successful fault injection results to store.
    pub fn set_fault_data(&mut self, fault_data: Vec<Vec<FaultData>>) {
        self.fault_data = fault_data;
    }

    /// Prints all stored fault data using disassembly context for human-readable output.
    ///
    /// This method formats and displays the fault injection results with
    /// disassembled instructions and debug information from the ELF file.
    /// Useful for analyzing successful attacks and understanding their impact.
    ///
    /// # Note
    ///
    /// Requires that fault simulation has been run and fault data exists.
    /// Output includes memory addresses, instruction disassembly, and fault details.
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
    /// - Respects `config.run_through` flag for early termination
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
                    if !self.user_thread.config.run_through {
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
                    if !self.user_thread.config.run_through {
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
    /// This method delegates to the standalone fault_simulation function.
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
    pub fn fault_simulation(
        &mut self,
        faults: &[FaultType],
    ) -> Result<Vec<Vec<FaultData>>, String> {
        // Setup the trace response channel if not already set
        if self.initial_trace.is_empty() {
            // Run full trace to populate initial_trace
            self.initial_trace = get_trace_data(
                RunType::RecordTrace,
                self.user_thread.config.deep_analysis,
                vec![],
                self.user_thread,
            )?;
        }

        let (result, count) = fault_simulation(
            faults,
            self.initial_trace.clone(),
            &self.cs,
            &self.user_thread,
        )?;
        self.count_sum += count;
        Ok(result)
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
        self.user_thread.send_workload(
            run_type,
            deep_analysis,
            fault_data,
            Some(trace_response_sender),
            None,
        )?;
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

    /// Records the initial program execution trace without any fault injections.
    ///
    /// This internal method captures the baseline execution flow of the target
    /// program, which serves as the foundation for identifying valid fault
    /// injection points in subsequent attack simulations.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Initial trace successfully recorded.
    /// * `Err(String)` - Error message if trace recording fails.
    ///
    /// # Side Effects
    ///
    /// Sets `self.initial_trace` with the recorded execution trace.
    fn set_initial_trace(&mut self) -> Result<(), String> {
        // Run full trace
        self.initial_trace = self.get_trace_data(
            RunType::RecordTrace,
            self.user_thread.config.deep_analysis,
            [].to_vec(),
        )?;
        Ok(())
    }

    /// Prints the complete execution trace of the program without any fault injections.
    ///
    /// This method displays the normal program flow with full disassembly,
    /// useful for understanding the baseline behavior before fault injection.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Trace successfully printed.
    /// * `Err(String)` - Error message if trace recording or printing fails.
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

    /// Validates correct program behavior by running without fault injections.
    ///
    /// This method executes the target program in a clean environment to verify
    /// it behaves as expected. It checks against configured success/failure
    /// addresses to ensure the baseline execution is correct before attempting
    /// fault injection attacks.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Program executed correctly according to success/failure criteria.
    /// * `Err(String)` - Error message if program fails or behaves unexpectedly.
    ///
    /// # Purpose
    ///
    /// Used to validate that the target program works correctly before fault
    /// injection, ensuring that any detected vulnerabilities are due to faults
    /// rather than inherent program issues.
    pub fn check_for_correct_behavior(&self) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(
            &self.file_data,
            true,
            self.user_thread.config.success_addresses.clone(),
            self.user_thread.config.failure_addresses.clone(),
            self.user_thread.config.initial_registers.clone(),
        );
        simulation.check_program(self.user_thread.config.cycles)
    }
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
/// * `initial_trace` - Mutable reference to the initial trace data that will be populated if empty.
/// * `cs` - Reference to the disassembly engine for filtering records.
/// * `user_thread` - Reference to the user thread for workload management.
///
/// # Returns
///
/// * `Ok((Vec<Vec<FaultData>>, usize))` - Tuple containing successful attack results and execution count.
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
    faults: &[FaultType],
    mut records: Vec<TraceRecord>,
    cs: &Disassembly,
    user_thread: &UserThread,
) -> Result<(Vec<Vec<FaultData>>, usize), String> {
    println!("Running simulation for faults: {faults:?}");

    // Check if faults are empty
    if faults.is_empty() {
        return Ok((Vec::new(), 0));
    }

    // Split faults into first and remaining faults
    let (first_fault, remaining_faults) = faults.split_first().unwrap();
    first_fault.filter(&mut records, cs);

    // Clear workload counter
    user_thread.reset_workload_counter();

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
                number = fault_simulation_inner(
                    fault_response_sender.clone(),
                    remaining_faults,
                    &simulation_fault_records,
                    cs,
                    user_thread,
                )?;
            } else {
                return Err("No instruction record found".to_string());
            }

            Ok(number)
        })
        .sum();

    // Sum up successful attacks
    let n = n_result?;

    // Wait that the workload counter is the same as the n_result
    while user_thread.get_workload_counter() != n {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Return collected successful attacks to caller
    let data: Vec<_> = fault_response_receiver.try_iter().collect();
    println!("-> {} attacks executed, {} successful", n, data.len());

    Ok((data, n))
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
/// * `cs` - Reference to the disassembly engine for filtering records.
/// * `user_thread` - Reference to the user thread for workload management.
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
    fault_response_sender: Sender<Vec<FaultData>>,
    remaining_faults: &[FaultType],
    simulation_fault_records: &[FaultRecord],
    cs: &Disassembly,
    user_thread: &UserThread,
) -> Result<usize, String> {
    let mut n = 0;

    // Check if there are no remaining faults left
    if remaining_faults.is_empty() {
        // Run fault simulation. This is the end of the recursion
        user_thread.send_workload(
            RunType::Run,
            false,
            simulation_fault_records.to_vec(),
            None,
            Some(fault_response_sender),
        )?;
        n += 1;
    } else {
        // Collect trace records with simulation fault records to get new running length (time)
        // Setup the trace response channel
        let (trace_response_sender, trace_response_receiver) = unbounded();
        // Run simulation to record normal fault program flow as a base for fault injection
        user_thread.send_workload(
            RunType::RecordTrace,
            user_thread.config.deep_analysis,
            simulation_fault_records.to_vec(),
            Some(trace_response_sender),
            None,
        )?;

        let mut records = trace_response_receiver
            .recv()
            .expect("Unable to receive trace data");

        // Split faults into first and remaining faults
        let (first_fault, remaining_faults) = remaining_faults.split_first().unwrap();
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
                n += fault_simulation_inner(
                    fault_response_sender.clone(),
                    remaining_faults,
                    &index_simulation_fault_records,
                    cs,
                    user_thread,
                )?;
            }
        }
    }

    Ok(n)
}

/// Helper function to get trace data from worker threads.
///
/// This function submits a trace recording request to worker threads and
/// returns the collected execution trace for the specified fault sequence.
///
/// # Arguments
///
/// * `run_type` - Type of trace recording (normal trace, full trace, or execution only).
/// * `deep_analysis` - Enable detailed analysis of loops and repeated code patterns.
/// * `fault_data` - Sequence of fault injections to apply during trace recording.
/// * `user_thread` - Reference to the user thread for workload management.
///
/// # Returns
///
/// * `Ok(Vec<TraceRecord>)` - Collected execution trace records.
/// * `Err(String)` - Error message if trace recording fails or times out.
fn get_trace_data(
    run_type: RunType,
    deep_analysis: bool,
    fault_data: Vec<FaultRecord>,
    user_thread: &UserThread,
) -> Result<Vec<TraceRecord>, String> {
    let (trace_response_sender, trace_response_receiver) = unbounded();
    user_thread.send_workload(
        run_type,
        deep_analysis,
        fault_data,
        Some(trace_response_sender),
        None,
    )?;
    let trace_record = trace_response_receiver
        .recv()
        .expect("Unable to receive trace data");
    Ok(trace_record)
}
