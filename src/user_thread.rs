use std::sync::{Arc, Mutex};
use std::thread::{/*sleep, */ spawn, JoinHandle};

//use crate::disassembly::Disassembly;
use crate::elf_file::ElfFile;
//use crate::prelude::FaultType;
use crate::simulation::fault_data::FaultData;
use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::simulation::{
    record::{FaultRecord, TraceRecord},
    Control, Data, RunType,
};

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
    pub trace_sender: Option<Sender<Vec<TraceRecord>>>,
    pub fault_sender: Option<Sender<Vec<FaultData>>>,
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
pub struct UserThread {
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

impl UserThread {
    /// Creates a new UserThread instance with specified simulation parameters.
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
    /// * `Ok(UserThread)` - Successfully initialized UserThread with communication channels.
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

        Ok(UserThread {
            config,
            workload_sender: Some(workload_sender),
            workload_receiver,
            work_load_counter,
            handles: None,
        })
    }

    /// Creates a new UserThread instance with individual simulation parameters.
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
    /// * `Ok(UserThread)` - Successfully initialized UserThread with communication channels.
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
                            if let Data::Fault(fault) = simulation
                                .run_with_faults(cycles, run_type, deep_analysis, &records)
                                .unwrap()
                            {
                                if !fault.is_empty() {
                                    fault_sender
                                        .unwrap()
                                        .send(fault)
                                        .expect("Unable to send fault data");
                                }
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
        trace_sender: Option<Sender<Vec<TraceRecord>>>,
        fault_sender: Option<Sender<Vec<FaultData>>>,
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

/// Gracefully shuts down the UserThread by closing channels and joining worker threads.
///
/// This cleanup implementation ensures proper resource management when the UserThread
/// goes out of scope or is explicitly dropped.
///
/// # Cleanup Process
///
/// 1. **Channel Closure**: Sets `workload_sender` to `None`, which drops the sender
///    and signals all worker threads to exit their message loop
/// 2. **Thread Joining**: Waits for each worker thread to complete its current work
///    and terminate gracefully
/// 3. **Error Handling**: Prints panic information if any worker thread panicked,
///    but continues cleanup for remaining threads
///
/// # Thread Safety
///
/// Worker threads detect channel closure via `receiver.recv()` returning `Err`,
/// which causes them to exit their processing loop and terminate naturally.
///
/// # Panic Handling
///
/// If any worker thread panicked during execution, the panic information is
/// printed to stderr for debugging, but the cleanup process continues to ensure
/// all threads are properly joined.
///
/// # Note
///
/// This ensures no thread handles are leaked and all system resources are
/// properly released when the UserThread is no longer needed.
impl Drop for UserThread {
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

// pub fn start_fault_simulation_threads(
//     deep_analysis: bool,
//     number_of_threads: usize,
//     initial_trace: &Vec<TraceRecord>,
//     workload_sender: &Sender<WorkloadMessage>,
//     fault_receiver: &Receiver<Vec<FaultType>>,
// ) -> Result<Vec<JoinHandle<()>>, ()> {
//     // Create a vector to hold the thread handles
//     let mut handles: Vec<JoinHandle<()>> = vec![];

//     for _ in 0..number_of_threads {
//         // Copy data to be moved into threads
//         let receiver = fault_receiver.clone();
//         let initial_trace = initial_trace.clone();
//         let workload_sender = workload_sender.clone();
//         let handle = spawn(move || {
//             let cs = Disassembly::new();
//             let work_load_counter: Arc<Mutex<usize>> = Default::default();
//             // Create a channel for collecting results from threads
//             let (fault_response_sender, fault_response_receiver) = unbounded();
//             // Loop until the workload receiver is closed
//             while let Ok(faults) = receiver.recv() {
//                 // // Check if faults are empty
//                 // if faults.is_empty() {
//                 //     return Ok(vec![]);
//                 // }

//                 // Split faults into first and remaining faults
//                 let (first_fault, remaining_faults) = faults.split_first().unwrap();
//                 // Filter records according to fault type
//                 let mut records = initial_trace.clone();
//                 first_fault.filter(&mut records, &cs);

//                 // // Clear workload counter
//                 let mut counter = work_load_counter.lock().unwrap();
//                 *counter = 0;
//                 drop(counter);

//                 // Run main fault simulation loop
//                 let n_result: Result<usize, String> = records
//                     .into_iter()
//                     .map(|record| {
//                         let number;
//                         // Get index of the record
//                         if let TraceRecord::Instruction { index, .. } = record {
//                             // Create a simulation fault record list with the first fault in the list
//                             let simulation_fault_records = vec![FaultRecord {
//                                 index,
//                                 fault_type: first_fault.clone(),
//                             }];

//                             // Call recursive fault simulation with first simulation fault record
//                             number = fault_simulation_inner(
//                                 deep_analysis,
//                                 &cs,
//                                 remaining_faults,
//                                 &simulation_fault_records,
//                                 fault_response_sender.clone(),
//                                 workload_sender.clone(),
//                             )?;
//                         } else {
//                             return Err("No instruction record found".to_string());
//                         }

//                         Ok(number)
//                     })
//                     .sum();

//                 // Sum up successful attacks
//                 let n = n_result.unwrap();
//                 // count_sum += n;

//                 // Wait that the workload counter is the same as the n_result
//                 while {
//                     let counter = work_load_counter.lock().unwrap();
//                     *counter != n
//                 } {
//                     sleep(std::time::Duration::from_millis(10));
//                 }

//                 // Return collected successful attacks to caller
//                 let data: Vec<_> = fault_response_receiver.try_iter().collect();
//                 println!("-> {} attacks executed, {} successful", n, data.len());
//                 // if data.is_empty() {
//                 //     Ok(Vec::new())
//                 // } else {
//                 //     Ok(data)
//                 // }
//             }
//         });
//         handles.push(handle);
//     }
//     Ok(handles)
// }

// fn fault_simulation_inner(
//     deep_analysis: bool,
//     cs: &Disassembly,
//     remaining_faults: &[FaultType],
//     simulation_fault_records: &[FaultRecord],
//     fault_response_sender: Sender<Vec<FaultData>>,    //
//     workload_sender: Option<Sender<WorkloadMessage>>, //
// ) -> Result<usize, String> {
//     let mut n = 0;

//     // Check if there are no remaining faults left
//     if remaining_faults.is_empty() {
//         // Run fault simulation. This is the end of the recursion
//         workload_sender
//             .as_ref()
//             .unwrap()
//             .send(WorkloadMessage {
//                 run_type: RunType::Run,
//                 deep_analysis: false,
//                 fault_records: simulation_fault_records.to_vec(),
//                 trace_sender: None,
//                 fault_sender: None, //TODO
//             })
//             .expect("Not able to send fault record to thread");
//         n += 1;
//     } else {
//         // Collect trace records with simulation fault records to get new running length (time)
//         // Setup the trace response channel
//         let (trace_response_sender, trace_response_receiver) = unbounded();
//         // Run simulation to record normal fault program flow as a base for fault injection
//         workload_sender
//             .as_ref()
//             .unwrap()
//             .send(WorkloadMessage {
//                 run_type: RunType::RecordTrace,
//                 deep_analysis,
//                 fault_records: simulation_fault_records.to_vec(),
//                 trace_sender: Some(trace_response_sender),
//                 fault_sender: None, //TODO
//             })
//             .unwrap();

//         let mut records = trace_response_receiver
//             .recv()
//             .expect("Unable to receive trace data");

//         // Split faults into first and remaining faults
//         let (first_fault, remaining_faults) = remaining_faults.split_first().unwrap();
//         // Filter records according to fault type
//         first_fault.filter(&mut records, cs);
//         // Iterate over trace records
//         for record in records {
//             // Get index of the record
//             if let TraceRecord::Instruction { index, .. } = record {
//                 // Create a copy of the simulation fault records
//                 let mut index_simulation_fault_records = simulation_fault_records.to_vec();
//                 // Add the created simulation fault record to the list of simulation fault records
//                 index_simulation_fault_records.push(FaultRecord {
//                     index,
//                     fault_type: first_fault.clone(),
//                 });

//                 // Call recursive fault simulation with remaining faults
//                 n += fault_simulation_inner(
//                     deep_analysis,
//                     cs,
//                     remaining_faults,
//                     &index_simulation_fault_records,
//                     fault_response_sender.clone(),
//                     workload_sender.clone(),
//                 )?;
//             }
//         }
//     }

//     Ok(n)
// }

// pub fn start_fault_simulation_inner(
//     deep_analysis: bool,
//     number_of_threads: usize,
//     initial_trace: &Vec<TraceRecord>,
//     workload_sender: &Sender<WorkloadMessage>,
//     fault_receiver: &Receiver<Vec<FaultType>>,
// ) -> Result<usize, String> {
//     // Create a vector to hold the thread handles
//     let mut handles: Vec<JoinHandle<()>> = vec![];

//     for _ in 0..number_of_threads {
//         // Copy data to be moved into threads
//         let receiver = fault_receiver.clone();
//         let initial_trace = initial_trace.clone();
//         let workload_sender = workload_sender.clone();
//         let handle = spawn(move || {
//             let cs = Disassembly::new();
//             let work_load_counter: Arc<Mutex<usize>> = Default::default();
//             // Create a channel for collecting results from threads
//             let (fault_response_sender, fault_response_receiver) = unbounded();
//             // Loop until the workload receiver is closed
//             while let Ok(faults) = receiver.recv() {
//                 let mut n = 0;

//                 // Split faults into first and remaining faults
//                 let (first_fault, remaining_faults) = faults.split_first().unwrap();

//                 // Collect trace records with simulation fault records to get new running length (time)
//                 // Setup the trace response channel
//                 let (trace_response_sender, trace_response_receiver) = unbounded();
//                 // Run simulation to record normal fault program flow as a base for fault injection
//                 workload_sender
//                     .send(WorkloadMessage {
//                         run_type: RunType::RecordTrace,
//                         deep_analysis,
//                         fault_records: simulation_fault_records.to_vec(),
//                         trace_sender: Some(trace_response_sender),
//                         fault_sender: None, //TODO
//                     })
//                     .unwrap();

//                 let mut records = trace_response_receiver
//                     .recv()
//                     .expect("Unable to receive trace data");

//                 // Split faults into first and remaining faults
//                 let (first_fault, remaining_faults) = remaining_faults.split_first().unwrap();
//                 // Filter records according to fault type
//                 first_fault.filter(&mut records, cs);
//                 // Iterate over trace records
//                 for record in records {
//                     // Get index of the record
//                     if let TraceRecord::Instruction { index, .. } = record {
//                         // Create a copy of the simulation fault records
//                         let mut index_simulation_fault_records = simulation_fault_records.to_vec();
//                         // Add the created simulation fault record to the list of simulation fault records
//                         index_simulation_fault_records.push(FaultRecord {
//                             index,
//                             fault_type: first_fault.clone(),
//                         });

//                         // Run fault simulation.
//                         workload_sender
//                             .send(WorkloadMessage {
//                                 run_type: RunType::Run,
//                                 deep_analysis: false,
//                                 fault_records: index_simulation_fault_records.to_vec(),
//                                 trace_sender: None,
//                                 fault_sender: None, //TODO
//                             })
//                             .expect("Not able to send fault record to thread");
//                         n += 1;
//                     }
//                 }
//             }
//         });
//         handles.push(handle);
//     }
//     Ok(handles)
// }
