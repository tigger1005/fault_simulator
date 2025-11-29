pub mod faults;

use crate::simulation::TraceElement;
use crate::simulation_thread::SimulationThread;
use crate::{fault_attack_thread::FaultAttackThread, simulation::FaultElement};

use super::simulation::{fault_data::FaultData, record::FaultRecord, Control, RunType};
use crate::{disassembly::Disassembly, elf_file::ElfFile};
use faults::*;
use itertools::iproduct;
// use std::time::{SystemTime, UNIX_EPOCH};
use std::slice::Iter;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError};
pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<FaultElement>,
    pub initial_trace: TraceElement,
    pub count_sum: usize,
    result_receiver: Option<Receiver<(Vec<FaultElement>, usize)>>,
    user_thread: Arc<SimulationThread>,
    fault_attack_thread: Option<FaultAttackThread>,
}

impl FaultAttacks {
    /// Creates a new `FaultAttacks` instance from existing ELF file and SimulationThread.
    ///
    /// This function initializes the fault attack simulation environment using
    /// pre-configured ELF file data and user thread instances. The worker threads
    /// should already be started on the SimulationThread before calling this function.
    ///
    /// # Arguments
    ///
    /// * `file_data` - Owned ELF file containing the target program.
    /// * `user_thread` - Arc-wrapped SimulationThread with worker threads started.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully initialized FaultAttacks instance.
    /// * `Err(String)` - Error message if initialization fails.
    ///
    /// # Note
    ///
    /// This constructor takes ownership of the ELF file data and stores a shared reference to the SimulationThread.
    pub fn new(file_data: ElfFile, user_thread: Arc<SimulationThread>) -> Result<Self, String> {
        // Return the FaultAttacks instance
        Ok(Self {
            cs: Disassembly::new(),
            file_data: file_data.clone(),
            fault_data: Vec::new(),
            initial_trace: Vec::new(),
            count_sum: 0,
            result_receiver: None,
            user_thread,
            fault_attack_thread: None,
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
    pub fn set_fault_data(&mut self, fault_data: Vec<FaultElement>) {
        self.fault_data = fault_data;
    }

    /// Initializes dedicated fault attack worker threads.
    ///
    /// This method creates a FaultAttackThread instance using the simulation configuration
    /// from the user_thread and starts the specified number of worker threads dedicated
    /// to fault attack execution. This provides better parallelization and isolation
    /// compared to sharing the general simulation threads.
    ///
    /// # Arguments
    ///
    /// * `number_of_threads` - Number of dedicated fault attack worker threads to spawn.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Fault attack threads successfully initialized and started.
    /// * `Err(String)` - Error message if initialization or thread startup fails.
    ///
    /// # Note
    ///
    /// This should be called before running fault attacks to enable optimized
    /// parallel execution. If not called, fault attacks will fall back to
    pub fn start_fault_attack_threads(&mut self, number_of_threads: usize) -> Result<(), String> {
        // Create a channel for collecting results
        let (result_sender, result_receiver) = unbounded();
        // Set reveiver
        self.result_receiver = Some(result_receiver);
        // Initialize fault attack thread
        let mut fault_attack_thread = FaultAttackThread::new(result_sender)?;
        fault_attack_thread
            .start_worker_threads(number_of_threads, Arc::clone(&self.user_thread))?;
        self.fault_attack_thread = Some(fault_attack_thread);
        println!(
            "Started {} dedicated fault attack worker threads",
            number_of_threads
        );
        Ok(())
    }

    /// Creates a new FaultAttacks instance with dedicated fault attack threads pre-initialized.
    ///
    /// This is a convenience constructor that combines `new()` and `start_fault_attack_threads()`
    /// to provide a ready-to-use FaultAttacks instance with optimal threading configuration.
    ///
    /// # Arguments
    ///
    /// * `file_data` - Reference to loaded ELF file containing the target program (will be cloned).
    /// * `user_thread` - Arc-wrapped SimulationThread with worker threads started.
    /// * `fault_attack_threads` - Number of dedicated fault attack worker threads to spawn.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully initialized FaultAttacks instance with fault attack threads.
    /// * `Err(String)` - Error message if initialization fails.
    ///
    /// # Usage
    ///
    /// This is the recommended way to create FaultAttacks instances when you want
    pub fn new_with_threads(
        file_data: &ElfFile,
        user_thread: Arc<SimulationThread>,
        fault_attack_threads: usize,
    ) -> Result<Self, String> {
        let mut fault_attacks = Self::new(file_data.clone(), user_thread)?;
        fault_attacks.start_fault_attack_threads(fault_attack_threads)?;
        Ok(fault_attacks)
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

        for list in lists {
            // Iterate over all faults in the list
            for fault in list {
                // Get fault type
                let fault = vec![get_fault_from(&fault).unwrap()];

                // Run simulation with fault using threaded version if available
                any_success |= self.fault_simulation(std::slice::from_ref(&fault))?;

                if any_success && !self.user_thread.config.run_through {
                    return Ok((true, self.count_sum));
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

        for list in lists {
            // Iterate over all faults in the list
            let iter_list = iproduct!(list.clone(), list)
                .map(|(a, b)| (a, b))
                .map(|fault_str| {
                    vec![
                        get_fault_from(&fault_str.0).unwrap(),
                        get_fault_from(&fault_str.1).unwrap(),
                    ]
                })
                .collect::<Vec<Vec<FaultType>>>();

            // Iterate over all fault pairs
            for chunks in iter_list.chunks(16) {
                any_success |= self.fault_simulation(chunks)?;

                if any_success && !self.user_thread.config.run_through {
                    return Ok((true, self.count_sum));
                }
            }
        }
        Ok((any_success, self.count_sum))
    }

    /// Executes fault simulation for a specific sequence of fault injections.
    ///
    /// This method coordinates with dedicated fault attack worker threads to execute
    /// the specified fault sequence and collect results. Successful attack results
    /// are automatically stored in the internal fault_data collection.
    ///
    /// # Arguments
    ///
    /// * `faults` - Ordered sequence of faults to inject during execution.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if at least one attack in the sequence succeeded, false otherwise.
    /// * `Err(String)` - Error message if simulation setup or execution fails.
    ///
    /// # Note
    ///
    /// Requires fault attack threads to be initialized via `start_fault_attack_threads()` first.
    pub fn fault_simulation(&mut self, chunks: &[Vec<FaultType>]) -> Result<bool, String> {
        let fault_attack_thread = match &mut self.fault_attack_thread {
            Some(thread) => thread,
            None => {
                return Err("Fault attack threads not initialized. Call start_fault_attack_threads() first.".to_string());
            }
        };

        let mut n_workload = 0;
        // Send all fault attack workloads to the fault attack thread
        for faults in chunks.iter() {
            //dbg!(faults);
            // Run main fault simulation loop
            fault_attack_thread.send_fault_attack_workload(faults)?;
            //
            n_workload += 1;
        }

        let mut any_success = false;
        // Collect results from worker threads
        for _ in 0..n_workload {
            match self
                .result_receiver
                .as_ref()
                .unwrap()
                .recv_timeout(Duration::from_millis(1000))
            {
                Ok((data, n)) => {
                    self.count_sum += n;
                    if !data.is_empty() {
                        // Push intermediate data to fault data
                        self.fault_data.append(&mut data.clone());
                        any_success = true;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err("Timeout while receiving fault attack results".to_string());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("Fault attack result channel disconnected".to_string());
                }
            }
        }

        Ok(any_success)
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
    /// * `Ok(TraceElement)` - Collected execution trace records.
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
    ) -> Result<TraceElement, String> {
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
