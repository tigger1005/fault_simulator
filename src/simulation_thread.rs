//! # Multi-threaded Simulation Coordination
//!
//! This module provides the core infrastructure for managing parallel fault
//! injection simulations across multiple worker threads. It handles work
//! distribution, result collection, and thread lifecycle management for
//! high-performance fault injection campaigns.
//!
//! ## Key Components
//!
//! * **SimulationThread**: Main coordinator for worker thread management
//! * **SimulationConfig**: Immutable configuration shared across all workers
//! * **WorkloadMessage**: Work distribution mechanism for parallel processing
//! * **Thread Pool**: Scalable worker thread management with automatic cleanup
//!
//! ## Performance Benefits
//!
//! * **Parallel Execution**: Utilizes multiple CPU cores effectively
//! * **Load Balancing**: Automatic work distribution across available threads
//! * **Resource Management**: Efficient memory and thread resource usage
//! * **Scalability**: Adapts to available hardware resources automatically

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{/*sleep, */ spawn, JoinHandle};
use std::time::Duration;
use std::vec;

//use crate::disassembly::Disassembly;
use crate::elf_file::ElfFile;
use crate::error::SimulatorError;
use crate::simulation::{FaultElement, TraceElement};
//use crate::prelude::FaultType;

use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::simulation::{record::FaultRecord, Control, Data, RunType};

/// Counters shared by all simulation workers, tracking how fault injection runs ended.
///
/// A run either reaches a verdict (success or failure marker), uses up its instruction
/// budget, or aborts with an emulation error. A high share of budget-exhausted runs is
/// the indicator that `max_instructions` may be set too low.
#[derive(Debug, Default)]
pub struct RunStatistics {
    runs: AtomicUsize,
    instruction_limit: AtomicUsize,
    errors: AtomicUsize,
}

/// Immutable copy of [`RunStatistics`] for reporting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStatisticsSnapshot {
    /// Number of completed fault injection runs.
    pub runs: usize,
    /// Runs that used up the instruction budget without reaching a verdict.
    pub instruction_limit: usize,
    /// Runs that aborted with an emulation error.
    pub errors: usize,
}

impl RunStatisticsSnapshot {
    /// Share of runs that used up the instruction budget, in percent.
    pub fn instruction_limit_ratio(&self) -> f64 {
        if self.runs == 0 {
            0.0
        } else {
            100.0 * self.instruction_limit as f64 / self.runs as f64
        }
    }
}

impl RunStatistics {
    /// Records a run that reached a success or failure verdict.
    pub fn record_verdict(&self) {
        self.runs.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a run that used up its instruction budget without a verdict.
    pub fn record_instruction_limit(&self) {
        self.runs.fetch_add(1, Ordering::Relaxed);
        self.instruction_limit.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a run that aborted with an emulation error.
    pub fn record_error(&self) {
        self.runs.fetch_add(1, Ordering::Relaxed);
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a consistent-enough copy of the counters for reporting.
    pub fn snapshot(&self) -> RunStatisticsSnapshot {
        RunStatisticsSnapshot {
            runs: self.runs.load(Ordering::Relaxed),
            instruction_limit: self.instruction_limit.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    /// Clears all counters.
    pub fn reset(&self) {
        self.runs.store(0, Ordering::Relaxed);
        self.instruction_limit.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }
}

/// Configuration parameters for fault injection simulation execution.
///
/// This structure defines the complete execution environment and evaluation
/// criteria for fault injection simulations. It controls simulation behavior,
/// termination conditions, and success/failure detection mechanisms.
///
/// # Simulation Control
///
/// * **Execution Limits**: Maximum instruction count to prevent infinite loops
/// * **Analysis Depth**: Controls whether detailed loop analysis is performed
/// * **Continuation Policy**: Whether to stop after first success or continue
///
/// # Success Detection
///
/// The simulator uses memory access patterns to detect successful attacks:
/// * Success addresses indicate the attack achieved its goal
/// * Failure addresses indicate the attack was detected or failed
/// * Initial register state ensures consistent starting conditions
///
/// # Performance Tuning
///
/// Different configurations provide trade-offs between analysis depth and speed:
/// * Deep analysis: Slower but more comprehensive loop detection
/// * Run-through mode: Finds multiple attack vectors but takes longer
/// * Cycle limits: Prevents runaway simulations while allowing sufficient execution
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Maximum number of CPU cycles/instructions to execute per simulation.
    pub cycles: usize,
    /// Enable detailed analysis of loops and repeated code patterns.
    pub deep_analysis: bool,
    /// Memory addresses that indicate successful attack when accessed.
    pub success_addresses: Vec<u64>,
    /// Memory addresses that indicate attack failure when accessed.
    pub failure_addresses: Vec<u64>,
    /// Initial CPU register values to set before each simulation.
    pub initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
    /// Custom memory regions to initialize.
    pub memory_regions: Vec<crate::cli_args::MemoryRegion>,
    /// Log level: "off", "error", "warn", "info", "debug", "trace".
    pub log_level: String,
    /// Register-based success/failure checking configuration.
    pub result_checks: Option<crate::cli_args::ResultChecks>,
    /// Maximum time to wait for a single worker result before aborting the campaign.
    ///
    /// `None` waits indefinitely. Raise it on slow or heavily loaded machines where a
    /// single fault sequence legitimately takes longer than the default.
    pub result_timeout: Option<Duration>,
}

/// Default time to wait for a worker result, overridable via `FAULT_SIM_RESULT_TIMEOUT`
/// (seconds; `0`, `off` or `none` disables the timeout).
pub fn default_result_timeout() -> Option<Duration> {
    parse_result_timeout(std::env::var("FAULT_SIM_RESULT_TIMEOUT").ok().as_deref())
}

/// Timeout fallback used when the environment does not specify one.
const DEFAULT_RESULT_TIMEOUT: Duration = Duration::from_secs(120);

fn parse_result_timeout(value: Option<&str>) -> Option<Duration> {
    let Some(value) = value else {
        return Some(DEFAULT_RESULT_TIMEOUT);
    };
    match value.trim().to_lowercase().as_str() {
        "0" | "off" | "none" => None,
        other => match other.parse::<u64>() {
            Ok(seconds) => Some(Duration::from_secs(seconds)),
            Err(_) => {
                log::warn!("Invalid FAULT_SIM_RESULT_TIMEOUT value '{}', ignored", value);
                Some(DEFAULT_RESULT_TIMEOUT)
            }
        },
    }
}

impl SimulationConfig {
    /// Creates a new SimulationConfig with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `cycles` - Maximum number of CPU cycles/instructions to execute per simulation.
    /// * `deep_analysis` - Enable detailed analysis of loops and repeated code patterns.
    /// * `success_addresses` - Memory addresses that indicate successful attack when accessed.
    /// * `failure_addresses` - Memory addresses that indicate attack failure when accessed.
    /// * `initial_registers` - Initial CPU register values to set before each simulation.
    /// * `memory_regions` - Custom memory regions to initialize.
    /// * `log_level` - Log level: "off", "error", "warn", "info", "debug", "trace".
    /// * `result_checks` - Register-based success/failure checking configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cycles: usize,
        deep_analysis: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
        memory_regions: Vec<crate::cli_args::MemoryRegion>,
        log_level: String,
        result_checks: Option<crate::cli_args::ResultChecks>,
    ) -> Self {
        Self {
            cycles,
            deep_analysis,
            success_addresses,
            failure_addresses,
            initial_registers,
            memory_regions,
            log_level,
            result_checks,
            result_timeout: default_result_timeout(),
        }
    }

    /// Overrides the time to wait for a single worker result (`None` waits indefinitely).
    pub fn with_result_timeout(mut self, result_timeout: Option<Duration>) -> Self {
        self.result_timeout = result_timeout;
        self
    }
}

/// Represents a simulation workload message sent to worker threads.
///
/// This structure encapsulates all the information needed for a worker thread
/// to execute a specific type of simulation run, along with the channels
/// needed to return results to the coordinator. It serves as the primary
/// communication mechanism for distributing simulation work across the
/// thread pool.
///
/// # Message Types
///
/// Different combinations of fields enable various simulation modes:
/// * **Trace Recording**: Uses trace_sender for execution trace collection
/// * **Fault Injection**: Uses fault_sender for successful attack results
/// * **Mixed Analysis**: Can use both channels for comprehensive analysis
///
/// # Thread Coordination
///
/// The workload counter enables tracking of completion across the thread pool,
/// allowing the main thread to determine when all distributed work is finished.
///
/// # Fields
///
/// * `run_type` - Type of simulation to execute (trace recording or fault injection)
/// * `deep_analysis` - Enable detailed analysis for loop detection and pattern analysis
/// * `fault_records` - Sequence of fault injections to apply during simulation
/// * `trace_sender` - Optional channel for returning execution trace data
/// * `fault_sender` - Optional channel for returning successful fault injection results
pub struct WorkloadMessage {
    /// Specifies the type of simulation execution to perform.
    pub run_type: RunType,
    /// Enable detailed analysis including loop detection and pattern recognition.
    ///
    /// When true, the simulator performs comprehensive analysis of execution
    /// patterns, detecting loops and repeated code sequences for more thorough
    /// fault injection coverage at the cost of increased execution time.
    pub deep_analysis: bool,
    /// Sequence of fault injections to apply during this simulation run.
    ///
    /// Contains the complete fault injection plan with timing and parameters.
    /// Empty vector indicates a normal execution without fault injection
    /// (typically used for baseline trace collection).
    pub fault_records: Vec<FaultRecord>,
    /// Optional channel for returning execution trace data to the coordinator.
    ///
    /// Used when run_type includes trace recording. The worker thread sends
    /// the complete execution trace through this channel for analysis.
    pub trace_sender: Option<Sender<TraceElement>>,
    /// Optional channel for returning successful fault injection results.
    ///
    /// Used when run_type includes fault injection. Worker threads send
    /// successful attack results through this channel for aggregation.
    pub fault_sender: Option<Sender<FaultElement>>,
}

/// Central coordinator for multi-threaded fault injection simulation.
///
/// This structure manages a pool of worker threads that execute fault injection
/// simulations in parallel. It provides work distribution, result collection,
/// and lifecycle management for high-performance fault injection campaigns.
///
/// # Core Responsibilities
///
/// * **Thread Pool Management**: Creates and manages simulation worker threads
/// * **Work Distribution**: Distributes simulation tasks across available workers
/// * **Configuration Management**: Maintains consistent simulation parameters
/// * **Result Coordination**: Aggregates results from parallel execution
/// * **Resource Cleanup**: Ensures proper thread termination and resource release
///
/// # Architecture Benefits
///
/// * **Scalability**: Automatically scales to available CPU cores
/// * **Efficiency**: Parallel execution reduces total simulation time
/// * **Isolation**: Worker threads operate independently for fault tolerance
/// * **Flexibility**: Supports various simulation types and configurations
///
/// # Usage Workflow
///
/// 1. Initialize with simulation configuration parameters
/// 2. Start worker thread pool with desired thread count
/// 3. Submit simulation workloads through the work distribution system
/// 4. Collect results through dedicated result channels
/// 5. Automatic cleanup and resource management on drop
pub struct SimulationThread {
    /// Immutable simulation configuration shared across all worker threads.
    ///
    /// Contains execution limits, success criteria, analysis settings, and
    /// other parameters that control simulation behavior consistently
    /// across the entire thread pool.
    pub config: SimulationConfig,
    /// Channel sender for distributing simulation workloads to worker threads.
    ///
    /// Set to None after shutdown begins to prevent new work submission.
    /// Used by the coordinator to send WorkloadMessage instances to the
    /// shared worker thread pool for parallel processing.
    workload_sender: Option<Sender<WorkloadMessage>>,
    /// Channel receiver shared among all worker threads for work distribution.
    ///
    /// Each worker thread receives a clone of this receiver to participate
    /// in round-robin work distribution from the shared workload queue.
    workload_receiver: Receiver<WorkloadMessage>,
    /// Thread handles for spawned simulation worker processes.
    ///
    /// Maintained for proper cleanup during drop, ensuring all worker threads
    /// complete their current work and terminate gracefully before the
    /// coordinator is destroyed.
    handles: Option<Vec<JoinHandle<()>>>,
    /// Outcome counters of all fault injection runs, shared with the workers.
    statistics: Arc<RunStatistics>,
}

impl SimulationThread {
    /// Creates a new SimulationThread instance with comprehensive simulation configuration.
    ///
    /// Initializes the thread coordination infrastructure without starting worker
    /// threads. The configuration parameters define the execution environment
    /// and analysis criteria that will be applied consistently across all
    /// worker threads in the pool.
    ///
    /// # Configuration Impact
    ///
    /// The provided configuration affects all aspects of simulation execution:
    /// * Execution limits prevent runaway simulations
    /// * Success/failure criteria determine attack detection
    /// * Analysis depth controls performance vs. comprehensiveness trade-offs
    /// * Initial register state ensures reproducible execution conditions
    ///
    /// primitives needed for coordinating fault injection simulations across
    /// multiple worker threads. No worker threads are spawned at this stage.
    ///
    /// # Arguments
    ///
    /// * `config` - Simulation configuration containing all simulation parameters.
    ///
    /// # Returns
    ///
    /// * `Ok(SimulationThread)` - Successfully initialized SimulationThread with communication channels.
    /// * `Err(String)` - Error message if initialization fails (currently never fails).
    ///
    /// # Next Steps
    ///
    /// After creation, call `start_worker_threads()` to spawn the worker thread pool
    /// and begin accepting simulation workloads.
    ///
    /// # Communication Setup
    ///
    /// Creates unbounded channels for:
    /// - Distributing `WorkloadMessage` to worker threads
    /// - Shared workload counter for synchronizing completion
    pub fn new(config: SimulationConfig) -> Result<Self, SimulatorError> {
        // Create a channel for sending lines to threads
        let (workload_sender, workload_receiver): (
            Sender<WorkloadMessage>,
            Receiver<WorkloadMessage>,
        ) = unbounded();

        Ok(SimulationThread {
            config,
            workload_sender: Some(workload_sender),
            workload_receiver,
            handles: None,
            statistics: Arc::new(RunStatistics::default()),
        })
    }

    /// Returns the shared outcome counters of all executed fault injection runs.
    pub fn statistics(&self) -> &Arc<RunStatistics> {
        &self.statistics
    }

    pub fn new_with_threads(
        config: SimulationConfig,
        file_data: &ElfFile,
        number_of_threads: usize,
    ) -> Result<Self, SimulatorError> {
        let mut sim_thread = Self::new(config)?;
        sim_thread.start_worker_threads(file_data, number_of_threads)?;
        Ok(sim_thread)
    }

    /// Creates a new SimulationThread instance with individual simulation parameters.
    ///
    /// This is a convenience constructor that creates a SimulationConfig internally.
    /// For more control, use `new()` with a pre-configured SimulationConfig.
    ///
    /// # Arguments
    ///
    /// * `cycles` - Maximum number of CPU cycles/instructions to execute per simulation.
    /// * `deep_analysis` - Enable detailed analysis of loops and repeated code patterns.
    /// * `success_addresses` - Memory addresses that indicate successful attack when accessed.
    /// * `failure_addresses` - Memory addresses that indicate attack failure when accessed.
    /// * `initial_registers` - Initial CPU register values to set before each simulation.
    ///
    /// # Returns
    ///
    /// * `Ok(SimulationThread)` - Successfully initialized SimulationThread with communication channels.
    /// * `Err(String)` - Error message if initialization fails (currently never fails).
    pub fn with_params(
        cycles: usize,
        deep_analysis: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
    ) -> Result<Self, SimulatorError> {
        let config = SimulationConfig::new(
            cycles,
            deep_analysis,
            success_addresses,
            failure_addresses,
            initial_registers,
            Vec::new(),        // No memory regions in this test
            "off".to_string(), // Default verbose level
            None,              // No result checks
        );
        Self::new(config)
    }

    /// Starts the specified number of worker threads for parallel fault simulation.
    ///
    /// This method spawns a pool of worker threads that listen for simulation workloads
    /// and execute fault injection simulations in parallel. Each thread maintains its
    /// own simulation context and processes workload messages from the shared channel.
    ///
    /// # Arguments
    ///
    /// * `file_data` - Reference to the ELF file data that workers will simulate.
    /// * `number_of_threads` - Number of worker threads to spawn (must be > 0).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Worker threads successfully started.
    /// * `Err(String)` - Error if thread count is zero.
    ///
    /// # Worker Thread Behavior
    ///
    /// Each spawned worker thread:
    /// 1. Creates its own `Control` simulation instance with shared configuration
    /// 2. Listens for `WorkloadMessage` on the shared workload channel
    /// 3. Processes different message types:
    ///    - `RecordTrace`/`RecordFullTrace`: Records execution trace and sends via trace_sender
    /// 4. For `Run` type: Executes fault simulation and increments workload counter
    /// 5. Continues until the workload channel is closed
    ///
    /// # Thread Configuration
    ///
    /// Worker threads inherit:
    /// - ELF file data (cloned)
    /// - Success/failure address criteria
    /// - Initial register context
    /// - Cycle limit for simulation execution
    ///
    /// # Error Conditions
    ///
    /// Returns error if `number_of_threads` is 0. Thread spawning failures would panic.
    ///
    /// # Synchronization
    ///
    /// Worker threads use the shared workload channel for round-robin work
    /// distribution and result channels for returning data to the coordinator.
    pub fn start_worker_threads(
        &mut self,
        file_data: &ElfFile,
        number_of_threads: usize,
    ) -> Result<(), SimulatorError> {
        // Check that number of threads is greater than 0
        if number_of_threads == 0 {
            return Err(SimulatorError::thread(
                "Number of threads must be greater than 0",
            ));
        }

        // Create a vector to hold the thread handles
        self.handles = Some(vec![]);

        // The ELF image is read-only for the workers, so share a single copy
        // instead of giving every thread its own deep clone.
        let file = Arc::new(file_data.clone());

        // Validate the configuration once on the calling thread (e.g. catches invalid
        // memory regions) so a bad config surfaces as a clean error here instead of
        // panicking inside every worker thread.
        Control::new(
            &file,
            false,
            self.config.success_addresses.clone(),
            self.config.failure_addresses.clone(),
            self.config.initial_registers.clone(),
            &self.config.memory_regions,
            self.config.result_checks.clone(),
        )?;

        for _ in 0..number_of_threads {
            // Copy data to be moved into threads
            let file = Arc::clone(&file);
            let receiver = self.workload_receiver.clone();
            let success_addrs = self.config.success_addresses.clone();
            let failure_addrs = self.config.failure_addresses.clone();
            let init_regs = self.config.initial_registers.clone();
            let mem_regions = self.config.memory_regions.clone();
            let result_checks = self.config.result_checks.clone();
            let cycles = self.config.cycles;
            let statistics = Arc::clone(&self.statistics);
            let handle = spawn(move || {
                // Wait for workload
                // Create simulation instance for Run mode (reused across all runs)
                let mut simulation = match Control::new(
                    &file,
                    false,
                    success_addrs.clone(),
                    failure_addrs.clone(),
                    init_regs.clone(),
                    &mem_regions,
                    result_checks.clone(),
                ) {
                    Ok(simulation) => simulation,
                    Err(e) => {
                        log::error!("Failed to initialize simulation worker: {}", e);
                        return;
                    }
                };
                // Create a separate simulation instance for trace recordings (reused)
                let mut trace_simulation = match Control::new(
                    &file,
                    false,
                    success_addrs,
                    failure_addrs,
                    init_regs,
                    &mem_regions,
                    result_checks,
                ) {
                    Ok(simulation) => simulation,
                    Err(e) => {
                        log::error!("Failed to initialize trace simulation worker: {}", e);
                        return;
                    }
                };
                // Loop until the workload receiver is closed
                while let Ok(msg) = receiver.recv() {
                    let WorkloadMessage {
                        run_type,
                        deep_analysis,
                        fault_records: records,
                        trace_sender,
                        fault_sender,
                    } = msg;

                    match run_type {
                        RunType::RecordFullTrace | RunType::RecordTrace => {
                            let result = trace_simulation.run_with_faults(
                                cycles,
                                run_type,
                                deep_analysis,
                                &records,
                            );

                            let trace = match result {
                                Ok(Data::Trace(trace)) => trace,
                                _ => vec![],
                            };
                            if let Some(sender) = trace_sender {
                                let _ = sender.send(trace);
                            }
                        }
                        RunType::Run => {
                            let result = simulation.run_with_faults(
                                cycles,
                                run_type,
                                deep_analysis,
                                &records,
                            );

                            let fault = match result {
                                Ok(Data::Fault(fault)) => {
                                    statistics.record_verdict();
                                    fault
                                }
                                Ok(_) => {
                                    if simulation.instruction_limit_reached() {
                                        statistics.record_instruction_limit();
                                    } else {
                                        statistics.record_verdict();
                                    }
                                    vec![]
                                }
                                Err(_) => {
                                    statistics.record_error();
                                    vec![]
                                }
                            };
                            if let Some(sender) = fault_sender {
                                let _ = sender.send(fault);
                            }
                        }
                    }
                }
            });
            self.handles.as_mut().unwrap().push(handle);
        }
        Ok(())
    }

    /// Sends a workload message to worker threads for processing.
    ///
    /// This method creates a `WorkloadMessage` from the provided parameters and sends it
    /// to the worker thread pool via the workload channel. Worker threads will process
    /// the message based on the specified run type and configuration.
    ///
    /// # Arguments
    ///
    /// * `run_type` - Type of simulation to execute (trace recording or fault injection).
    /// * `deep_analysis` - Enable detailed analysis for loop detection and pattern analysis.
    /// * `fault_records` - Sequence of fault injections to apply during simulation.
    /// * `trace_sender` - Optional channel for returning execution trace data.
    /// * `fault_sender` - Optional channel for returning successful fault injection results.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Workload message successfully sent to worker threads.
    /// * `Err(String)` - Error message if sending fails or channel is closed.
    ///
    /// # Usage
    ///
    /// - For trace recording: provide `trace_sender`, set `fault_sender` to `None`
    /// - For fault simulation: provide `fault_sender`, set `trace_sender` to `None`
    /// - Worker threads will use the appropriate response channel based on `run_type`
    ///
    /// # Thread Communication
    ///
    /// This is the primary method for coordinating work between the main thread
    /// and the worker thread pool. The message is queued and processed asynchronously.
    pub fn send_workload(
        &self,
        run_type: RunType,
        deep_analysis: bool,
        fault_records: Vec<FaultRecord>,
        trace_sender: Option<Sender<TraceElement>>,
        fault_sender: Option<Sender<FaultElement>>,
    ) -> Result<(), SimulatorError> {
        if let Some(sender) = &self.workload_sender {
            let msg = WorkloadMessage {
                run_type,
                deep_analysis,
                fault_records,
                trace_sender,
                fault_sender,
            };
            sender.send(msg).map_err(|e| {
                let msg = format!("Failed to send workload: {}", e);
                SimulatorError::channel_with(msg, e)
            })
        } else {
            Err(SimulatorError::channel("Workload sender channel is closed"))
        }
    }

    /// Requests an execution trace and waits for the result.
    ///
    /// Convenience method that creates a one-shot channel internally,
    /// submits a trace recording workload, and blocks until the trace
    /// is returned by a worker thread.
    ///
    /// # Arguments
    ///
    /// * `run_type` - Type of trace recording to perform.
    /// * `deep_analysis` - Enable detailed loop and pattern analysis.
    /// * `fault_records` - Fault injections to apply during trace recording.
    ///
    /// # Returns
    ///
    /// * `Ok(TraceElement)` - Collected execution trace records.
    /// * `Err(String)` - Error if workload submission or trace reception fails.
    pub fn get_trace(
        &self,
        run_type: RunType,
        deep_analysis: bool,
        fault_records: Vec<FaultRecord>,
    ) -> Result<TraceElement, SimulatorError> {
        let (trace_sender, trace_receiver) = unbounded();
        self.send_workload(
            run_type,
            deep_analysis,
            fault_records,
            Some(trace_sender),
            None,
        )?;
        trace_receiver.recv().map_err(|e| {
            let msg = format!("Unable to receive trace data: {}", e);
            SimulatorError::channel_with(msg, e)
        })
    }
}

/// Gracefully shuts down the SimulationThread by closing channels and joining worker threads.
///
/// This cleanup implementation ensures proper resource management when the SimulationThread
/// is dropped, preventing any resource leaks from unjoined worker threads.
///
/// # Process
///
/// 1. Drops the workload sender channel, signaling workers to terminate
/// 2. Joins all worker threads to ensure clean shutdown
/// 3. Handles any thread panic situations gracefully
///
/// # Note
///
/// This ensures no thread handles are leaked and all system resources are
/// properly released when the SimulationThread is no longer needed.
impl Drop for SimulationThread {
    fn drop(&mut self) {
        // Drop the main workload channel to signal shutdown
        self.workload_sender = None;

        // Wait for all threads to finish processing
        if let Some(handles) = self.handles.take() {
            for handle in handles {
                if let Err(e) = handle.join() {
                    log::error!("A simulation worker thread panicked: {:?}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_statistics_counts_outcomes() {
        let stats = RunStatistics::default();
        stats.record_verdict();
        stats.record_verdict();
        stats.record_instruction_limit();
        stats.record_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.runs, 4);
        assert_eq!(snapshot.instruction_limit, 1);
        assert_eq!(snapshot.errors, 1);
        assert_eq!(snapshot.instruction_limit_ratio(), 25.0);

        stats.reset();
        assert_eq!(stats.snapshot(), RunStatisticsSnapshot::default());
        assert_eq!(stats.snapshot().instruction_limit_ratio(), 0.0);
    }

    #[test]
    fn result_timeout_parsing() {
        assert_eq!(parse_result_timeout(None), Some(DEFAULT_RESULT_TIMEOUT));
        assert_eq!(parse_result_timeout(Some("30")), Some(Duration::from_secs(30)));
        assert_eq!(parse_result_timeout(Some(" 30 ")), Some(Duration::from_secs(30)));
        assert_eq!(parse_result_timeout(Some("0")), None);
        assert_eq!(parse_result_timeout(Some("off")), None);
        assert_eq!(parse_result_timeout(Some("NONE")), None);
        assert_eq!(parse_result_timeout(Some("abc")), Some(DEFAULT_RESULT_TIMEOUT));
    }
}
