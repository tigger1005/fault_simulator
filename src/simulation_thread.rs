use std::sync::{Arc, Mutex};
use std::thread::{/*sleep, */ spawn, JoinHandle};

//use crate::disassembly::Disassembly;
use crate::elf_file::ElfFile;
//use crate::prelude::FaultType;
use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::simulation::{record::FaultRecord, Control, Data, FaultElement, RunType, TraceElement};

/// Configuration for fault injection simulation parameters.
///
/// This structure encapsulates all the simulation-specific parameters
/// that control how fault injection attacks are executed and evaluated.
///
/// # Fields
///
/// * `cycles` - Maximum number of CPU cycles/instructions to execute per simulation.
/// * `deep_analysis` - Enable detailed analysis of loops and repeated code patterns.
/// * `run_through` - Continue simulation after finding successful attacks (don't stop early).
/// * `success_addresses` - Memory addresses that indicate successful attack when accessed.
/// * `failure_addresses` - Memory addresses that indicate attack failure when accessed.
/// * `initial_registers` - Initial CPU register values to set before each simulation.
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
    /// Custom memory regions to initialize.
    pub memory_regions: Vec<crate::config::MemoryRegion>,
    /// Log level: "off", "error", "warn", "info", "debug", "trace".
    pub log_level: String,
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
    /// * `memory_regions` - Custom memory regions to initialize.
    /// * `log_level` - Log level: "off", "error", "warn", "info", "debug", "trace".
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cycles: usize,
        deep_analysis: bool,
        run_through: bool,
        success_addresses: Vec<u64>,
        failure_addresses: Vec<u64>,
        initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
        memory_regions: Vec<crate::config::MemoryRegion>,
        log_level: String,
    ) -> Self {
        Self {
            cycles,
            deep_analysis,
            run_through,
            success_addresses,
            failure_addresses,
            initial_registers,
            memory_regions,
            log_level,
        }
    }
}

/// Represents a simulation workload message sent to worker threads.
///
/// This structure encapsulates all the information needed for a worker thread
/// to execute a specific type of simulation run, along with the channels
/// needed to return results to the coordinator.
///
/// # Fields
///
/// * `run_type` - Type of simulation to execute (trace recording or fault injection).
/// * `deep_analysis` - Enable detailed analysis for loop detection and pattern analysis.
/// * `fault_records` - Sequence of fault injections to apply during simulation.
/// * `trace_sender` - Optional channel for returning execution trace data.
/// * `fault_sender` - Optional channel for returning successful fault injection results.
///
/// # Usage
///
/// Sent via the workload channel to coordinate simulation work across multiple
/// worker threads. The appropriate response channel is used based on `run_type`.
pub struct WorkloadMessage {
    pub run_type: RunType,
    pub deep_analysis: bool,
    pub fault_records: Vec<FaultRecord>,
    pub trace_sender: Option<Sender<TraceElement>>,
    pub fault_sender: Option<Sender<FaultElement>>,
}

/// Manages worker threads for parallel fault injection simulation.
///
/// This struct coordinates the execution of fault injection simulations across
/// multiple worker threads. It maintains simulation parameters, communication
/// channels, and synchronization primitives for distributed simulation work.
///
/// # Lifecycle
///
/// 1. Create with `new()` to establish communication channels
/// 2. Call `start_worker_threads()` to spawn worker thread pool
/// 3. Use workload channels to distribute simulation tasks
/// 4. Worker threads automatically clean up when dropped
pub struct SimulationThread {
    /// Simulation configuration parameters.
    pub config: SimulationConfig,
    /// Channel for sending workload messages to worker threads.
    workload_sender: Option<Sender<WorkloadMessage>>,
    /// Channel for receiving workload messages (shared by all worker threads).
    workload_receiver: Receiver<WorkloadMessage>,
    /// Shared counter for tracking completed simulation jobs across threads.
    work_load_counter: Arc<Mutex<usize>>,
    /// Handles for spawned worker threads (None until threads are started).
    handles: Option<Vec<JoinHandle<()>>>,
}

impl SimulationThread {
    /// Creates a new SimulationThread instance with specified simulation parameters.
    ///
    /// This constructor initializes the communication channels and synchronization
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

        // Create a counter for the workload done
        let work_load_counter = Arc::new(Mutex::new(0));

        Ok(SimulationThread {
            config,
            workload_sender: Some(workload_sender),
            workload_receiver,
            work_load_counter,
            handles: None,
        })
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
            Vec::new(),         // No memory regions in this test
            "info".to_string(), // Default verbose level
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
    /// Uses shared `work_load_counter` (Arc<Mutex<usize>>) to track completed simulations
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
            let workload_counter = Arc::clone(&self.work_load_counter);
            let success_addrs = self.config.success_addresses.clone();
            let failure_addrs = self.config.failure_addresses.clone();
            let init_regs = self.config.initial_registers.clone();
            let mem_regions = self.config.memory_regions.clone();
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
                    &mem_regions,
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
                            let mut trace_sim = Control::new(
                                &file,
                                false,
                                success_addrs.clone(),
                                failure_addrs.clone(),
                                init_regs.clone(),
                                &mem_regions,
                            );
                            match trace_sim.run_with_faults(
                                cycles,
                                run_type,
                                deep_analysis,
                                &records,
                            ) {
                                Ok(Data::Trace(trace)) => {
                                    trace_sender
                                        .unwrap()
                                        .send(trace)
                                        .expect("Unable to send trace data");
                                }
                                _ => trace_sender
                                    .unwrap()
                                    .send(vec![])
                                    .expect("Unable to send trace data"),
                            }
                        }
                        RunType::Run => {
                            match simulation.run_with_faults(
                                cycles,
                                run_type,
                                deep_analysis,
                                &records,
                            ) {
                                Ok(Data::Fault(fault)) => {
                                    if !fault.is_empty() {
                                        fault_sender
                                            .unwrap()
                                            .send(fault)
                                            .expect("Unable to send fault data");
                                    }
                                }
                                Err(_e) => {
                                    // Silently ignore errors - they're expected during fault injection
                                }
                                _ => {}
                            }
                            let mut counter = workload_counter.lock().unwrap();
                            *counter += 1;
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

    /// Gets the current value of the workload counter.
    ///
    /// This method provides thread-safe access to the shared workload counter
    /// that tracks completed simulation jobs across all worker threads.
    ///
    /// # Returns
    ///
    /// * `usize` - Current value of the workload counter.
    ///
    /// # Thread Safety
    ///
    /// Uses mutex locking to ensure atomic read access to the shared counter.
    pub fn get_workload_counter(&self) -> usize {
        let counter = self.work_load_counter.lock().unwrap();
        *counter
    }

    /// Resets the workload counter to zero.
    ///
    /// This method provides thread-safe access to reset the shared workload counter
    /// before starting a new batch of simulation jobs.
    ///
    /// # Thread Safety
    ///
    /// Uses mutex locking to ensure atomic write access to the shared counter.
    pub fn reset_workload_counter(&self) {
        let mut counter = self.work_load_counter.lock().unwrap();
        *counter = 0;
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
