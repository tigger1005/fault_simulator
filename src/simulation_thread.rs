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

use std::thread::{/*sleep, */ spawn, JoinHandle};
use std::vec;

//use crate::disassembly::Disassembly;
use crate::elf_file::ElfFile;
use crate::simulation::{FaultElement, TraceElement};
//use crate::prelude::FaultType;

use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::simulation::{record::FaultRecord, Control, Data, RunType};

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
    /// Continue simulation after finding successful attacks (don't stop early).
    pub run_through: bool,
    /// Memory addresses that indicate successful attack when accessed.
    pub success_addresses: Vec<u64>,
    /// Memory addresses that indicate attack failure when accessed.
    pub failure_addresses: Vec<u64>,
    /// Initial CPU register values to set before each simulation.
    pub initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
}

impl SimulationConfig {
    /// Creates a new SimulationConfig with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `cycles` - Maximum number of CPU cycles/instructions to execute per simulation.
    /// * `deep_analysis` - Enable detailed analysis of loops and repeated code patterns.
    /// * `run_through` - Continue simulation after finding successful attacks (don't stop early).
    /// * `success_addresses` - Memory addresses that indicate successful attack when accessed.
    /// * `failure_addresses` - Memory addresses that indicate attack failure when accessed.
    /// * `initial_registers` - Initial CPU register values to set before each simulation.
    pub fn new(
        cycles: usize,
        deep_analysis: bool,
        run_through: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
    ) -> Self {
        Self {
            cycles,
            deep_analysis,
            run_through,
            success_addresses,
            failure_addresses,
            initial_registers,
        }
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
    pub fn new(config: SimulationConfig) -> Result<Self, String> {
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
        })
    }

    pub fn new_with_threads(
        config: SimulationConfig,
        file_data: &ElfFile,
        number_of_threads: usize,
    ) -> Result<Self, String> {
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
    /// * `run_through` - Continue simulation after finding successful attacks (don't stop early).
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
        run_through: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
    ) -> Result<Self, String> {
        let config = SimulationConfig::new(
            cycles,
            deep_analysis,
            run_through,
            success_addresses,
            failure_addresses,
            initial_registers,
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
    /// Uses shared `work_load_counter` (`Arc<Mutex<usize>>`) to track completed simulations
    /// for coordination between worker threads and the main coordination logic.
    pub fn start_worker_threads(
        &mut self,
        file_data: &ElfFile,
        number_of_threads: usize,
    ) -> Result<(), String> {
        // Check that number of threads is greater than 0
        if number_of_threads == 0 {
            return Err("Number of threads must be greater than 0".to_string());
        }

        // Create a vector to hold the thread handles
        self.handles = Some(vec![]);

        for _ in 0..number_of_threads {
            // Copy data to be moved into threads
            let file = file_data.clone();
            let receiver = self.workload_receiver.clone();
            let success_addrs = self.config.success_addresses.clone();
            let failure_addrs = self.config.failure_addresses.clone();
            let init_regs = self.config.initial_registers.clone();
            let cycles = self.config.cycles;
            let handle = spawn(move || {
                // Wait for workload
                // Create a new simulation instance
                let mut simulation = Control::new(
                    &file,
                    false,
                    success_addrs.clone(),
                    failure_addrs.clone(),
                    init_regs.clone(),
                );
                // Loop until the workload receiver is closed
                while let Ok(msg) = receiver.recv() {
                    let WorkloadMessage {
                        run_type,
                        deep_analysis,
                        fault_records: records,
                        trace_sender,
                        fault_sender,
                    } = msg;

                    // Todo: Do error handling
                    match run_type {
                        RunType::RecordFullTrace | RunType::RecordTrace => {
                            match Control::new(
                                &file,
                                false,
                                success_addrs.clone(),
                                failure_addrs.clone(),
                                init_regs.clone(),
                            )
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
                            match simulation
                                .run_with_faults(cycles, run_type, deep_analysis, &records)
                                .unwrap()
                            {
                                Data::Fault(fault) => {
                                    // Attach fault records
                                    fault_sender
                                        .unwrap()
                                        .send(fault)
                                        .expect("Unable to send fault data");
                                }
                                Data::None => {
                                    fault_sender
                                        .unwrap()
                                        .send(vec![])
                                        .expect("Unable to send empty fault data");
                                }
                                _ => {}
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
    ) -> Result<(), String> {
        if let Some(sender) = &self.workload_sender {
            let msg = WorkloadMessage {
                run_type,
                deep_analysis,
                fault_records,
                trace_sender,
                fault_sender,
            };
            sender
                .send(msg)
                .map_err(|e| format!("Failed to send workload: {}", e))
        } else {
            Err("Workload sender channel is closed".to_string())
        }
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
        // Drop the main workload channel
        self.workload_sender = None;

        // Wait for all threads to finish processing
        for handle in self.handles.as_mut().unwrap().drain(..) {
            if let Err(e) = handle.join() {
                eprintln!("A thread panicked: {:?}", e);
            }
        }
    }
}
