pub mod faults;

use crate::simulation::TraceElement;
use crate::simulation_thread::{RunStatisticsSnapshot, SimulationThread};
use crate::{fault_attack_thread::FaultAttackThread, simulation::FaultElement};

use super::simulation::{fault_data::FaultData, record::FaultRecord, Control, RunType};
use crate::error::SimulatorError;
use crate::{disassembly::Disassembly, elf_file::ElfFile};
use faults::*;
use itertools::iproduct;
use std::sync::Arc;

pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<FaultElement>,
    pub initial_trace: TraceElement,
    pub count_sum: usize,
    user_thread: Arc<SimulationThread>,
    fault_attack_thread: Option<FaultAttackThread>,
    number_of_threads: Option<usize>,
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
    /// * `file_data` - Reference to the ELF file containing the target program (will be cloned).
    /// * `user_thread` - Arc-wrapped SimulationThread with worker threads started.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Successfully initialized FaultAttacks instance.
    /// * `Err(String)` - Error message if initialization fails.
    ///
    /// # Note
    ///
    /// This constructor borrows the ELF file data, clones it internally, and stores a shared reference to the SimulationThread.
    pub fn new(
        file_data: &ElfFile,
        user_thread: Arc<SimulationThread>,
    ) -> Result<Self, SimulatorError> {
        // Return the FaultAttacks instance
        Ok(Self {
            cs: Disassembly::new(),
            file_data: file_data.clone(),
            fault_data: Vec::new(),
            initial_trace: Vec::new(),
            count_sum: 0,
            user_thread,
            fault_attack_thread: None,
            number_of_threads: None,
        })
    }

    /// Returns a reference to all collected fault injection results.
    ///
    /// This method returns a shared slice of the internal fault data collection,
    /// containing all successful fault injection attacks discovered during
    /// simulation runs. Each element represents a successful attack scenario
    /// with complete fault injection details and execution context.
    ///
    /// # Returns
    ///
    /// * `&[FaultElement]` - Slice reference to the successful fault injection results.
    ///   Returns an empty slice if no successful attacks have been found yet.
    ///
    /// # Usage
    ///
    /// Typically called after running `single()` or `double()` fault injection
    /// campaigns to retrieve and analyze the results. The returned data can be
    /// used for further analysis, reporting, or persistence.
    ///
    pub fn get_fault_data(&self) -> &[FaultElement] {
        &self.fault_data
    }

    /// Returns the outcome counters of all fault injection runs executed so far.
    pub fn run_statistics(&self) -> RunStatisticsSnapshot {
        self.user_thread.statistics().snapshot()
    }

    /// Clears the run outcome counters, e.g. when starting a fresh campaign.
    pub fn reset_run_statistics(&self) {
        self.user_thread.statistics().reset();
    }

    /// Number of instructions the unfaulted program executes before it reaches a verdict.
    ///
    /// A value equal to the configured instruction limit means the clean program does not
    /// even finish within the budget.
    pub fn baseline_instruction_count(&self) -> Result<usize, SimulatorError> {
        Ok(self
            .get_trace_data(RunType::RecordFullTrace, true, vec![])?
            .len())
    }

    /// Human readable diagnostic about runs that used up the instruction budget.
    ///
    /// Returns `None` when no run hit the limit. Otherwise it reports the share of
    /// affected runs and compares the limit against the instruction count of the
    /// unfaulted program to judge whether `max_instructions` is set too low.
    pub fn instruction_limit_report(&self) -> Option<String> {
        let stats = self.run_statistics();
        if stats.instruction_limit == 0 {
            return None;
        }

        let limit = self.user_thread.config.cycles;
        let ratio = stats.instruction_limit_ratio();
        let mut report = format!(
            "Instruction limit ({}) reached in {} of {} runs ({:.1}%)",
            limit, stats.instruction_limit, stats.runs, ratio
        );
        if stats.errors != 0 {
            report.push_str(&format!(", emulation errors: {}", stats.errors));
        }

        let baseline = self.baseline_instruction_count().ok();
        match baseline {
            Some(baseline) if baseline >= limit => report.push_str(&format!(
                "\n  -> The unfaulted program alone does not finish within the limit \
                 ({} instructions traced). Increase --max-instructions.",
                baseline
            )),
            Some(baseline) if limit < 2 * baseline => report.push_str(&format!(
                "\n  -> The unfaulted program needs {} instructions, so the limit leaves \
                 almost no headroom. Increase --max-instructions to at least {}.",
                baseline,
                4 * baseline
            )),
            Some(baseline) if ratio > 50.0 => report.push_str(&format!(
                "\n  -> More than half of all runs were inconclusive while the unfaulted \
                 program needs only {} instructions. This is usually caused by faults that \
                 break the control flow (endless loops), but re-running with a higher \
                 --max-instructions confirms whether the limit is the cause.",
                baseline
            )),
            _ => report.push_str(
                "\n  -> Expected for faults that break the control flow (endless loops). \
                 Increase --max-instructions if the share grows.",
            ),
        }

        Some(report)
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
    /// This must be called before running fault attacks to enable parallel execution.
    pub fn start_fault_attack_threads(
        &mut self,
        number_of_threads: usize,
    ) -> Result<(), SimulatorError> {
        // Set threads
        self.number_of_threads = Some(number_of_threads);
        // Initialize fault attack thread
        let mut fault_attack_thread = FaultAttackThread::new()?;
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
    /// parallel fault attack execution from the start.
    pub fn new_with_threads(
        file_data: &ElfFile,
        user_thread: Arc<SimulationThread>,
        fault_attack_threads: usize,
    ) -> Result<Self, SimulatorError> {
        let mut fault_attacks = Self::new(file_data, user_thread)?;
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
    /// * `groups` - Slice of fault group names (e.g., "glitch", "regbf", "regfld").
    /// * `run_through` - Continue simulation after finding successful attacks (don't stop early).
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
    pub fn single(
        &mut self,
        groups: &[String],
        run_through: bool,
    ) -> Result<(bool, usize), SimulatorError> {
        let lists = get_fault_lists(&mut groups.iter()); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        for list in lists {
            // Iterate over all faults in the list
            for fault in list {
                // Get fault type
                let fault = vec![get_fault_from(&fault).unwrap()];

                // Run simulation with fault using threaded version if available
                any_success |= self.fault_simulation(std::slice::from_ref(&fault))?;

                if any_success && !run_through {
                    println!("Early stopping single fault injection due to successful attack.");
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
    /// * `groups` - Slice of fault group names to generate pairs from.
    /// * `run_through` - Continue simulation after finding successful attacks (don't stop early).
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
    pub fn double(
        &mut self,
        groups: &[String],
        run_through: bool,
    ) -> Result<(bool, usize), SimulatorError> {
        let lists = get_fault_lists(&mut groups.iter()); // Get all faults of all lists
        let mut any_success = false; // Track if any fault was successful

        for list in lists {
            // Iterate over all faults in the list
            let iter_list = iproduct!(list.clone(), list)
                .map(|fault_str| {
                    vec![
                        get_fault_from(&fault_str.0).unwrap(),
                        get_fault_from(&fault_str.1).unwrap(),
                    ]
                })
                .collect::<Vec<Vec<FaultType>>>();

            // Iterate over all fault pairs
            for chunks in iter_list.chunks(self.number_of_threads.unwrap_or(1)) {
                any_success |= self.run_chunks(chunks, !run_through)?;

                if any_success && !run_through {
                    println!("Early stopping double fault injection due to successful attack.");
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
    /// * `chunks` - Slice of fault sequences to execute in parallel.
    ///
    /// # Returns
    ///
    /// * `Ok(bool)` - True if at least one attack in the sequence succeeded, false otherwise.
    /// * `Err(String)` - Error message if simulation setup or execution fails.
    ///
    /// # Note
    ///
    /// Requires fault attack threads to be initialized via `start_fault_attack_threads()` first.
    pub fn fault_simulation(&mut self, chunks: &[Vec<FaultType>]) -> Result<bool, SimulatorError> {
        self.run_chunks(chunks, false)
    }

    /// Runs a batch of fault sequences and collects the results in the order of `chunks`.
    ///
    /// With `stop_at_first_hit` the batch is cut off after the first fault sequence that
    /// found an attack: results and run counts of the sequences behind it are discarded.
    /// Those sequences are only executed because the batch is processed in parallel, so
    /// keeping them would make both the attack count and `Overall tests executed` depend
    /// on the number of worker threads, i.e. on the machine the campaign runs on.
    fn run_chunks(
        &mut self,
        chunks: &[Vec<FaultType>],
        stop_at_first_hit: bool,
    ) -> Result<bool, SimulatorError> {
        let fault_attack_thread = match &self.fault_attack_thread {
            Some(thread) => thread,
            None => {
                return Err(SimulatorError::thread(
                    "Fault attack threads not initialized. Call start_fault_attack_threads() first.",
                ));
            }
        };

        let outcomes = fault_attack_thread.run_batch(chunks)?;
        let mut any_success = false;
        for outcome in outcomes {
            self.count_sum += outcome.count;
            if !outcome.data.is_empty() {
                self.fault_data.extend(outcome.data);
                any_success = true;
                if stop_at_first_hit {
                    break;
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
    ) -> Result<TraceElement, SimulatorError> {
        self.user_thread
            .get_trace(run_type, deep_analysis, fault_data)
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
    pub fn print_trace_for_fault(&self, attack_number: usize) -> Result<(), SimulatorError> {
        if !self.fault_data.is_empty()
            && attack_number > 0
            && attack_number <= self.fault_data.len()
        {
            let fault_records = FaultData::get_simulation_fault_records(
                self.fault_data.get(attack_number - 1).unwrap(),
            );

            // Run full trace
            let trace_records = Some(self.get_trace_data(
                RunType::RecordFullTrace,
                true,
                fault_records.to_vec(),
            )?);
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number);

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
    pub fn print_trace(&self) -> Result<(), SimulatorError> {
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
    pub fn check_for_correct_behavior(&self) -> Result<(), SimulatorError> {
        // Get trace data from negative run
        let mut simulation = Control::new(
            &self.file_data,
            true,
            self.user_thread.config.success_addresses.clone(),
            self.user_thread.config.failure_addresses.clone(),
            self.user_thread.config.initial_registers.clone(),
            &self.user_thread.config.memory_regions,
            self.user_thread.config.result_checks.clone(),
        )?;
        simulation.check_program(self.user_thread.config.cycles)
    }
}
