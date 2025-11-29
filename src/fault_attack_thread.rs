use std::sync::Arc;
use std::thread::{spawn, JoinHandle};

use crate::disassembly::Disassembly;
use crate::prelude::{SimulationThread, TraceRecord};

use crate::simulation::{record::FaultRecord, FaultElement, RunType, TraceElement};
use crate::simulation_thread::FaultEnum;
use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};

use crate::fault_attacks::faults::FaultType;

use std::time::Duration;

/// Represents a fault attack workload message sent to worker threads.
///
/// This structure encapsulates the information needed for a worker thread
/// to execute a specific fault attack simulation. Results are returned
/// through a shared result channel in the FaultAttackThread.
///
/// # Fields
///
/// * `fault_sequence` - Sequence of faults to apply during the attack simulation.
pub struct FaultAttackWorkload {
    pub fault_sequence: Vec<FaultType>,
}

/// Manages dedicated worker threads for parallel fault attack execution.
///
/// This structure coordinates the execution of fault injection attacks across
/// multiple worker threads, providing dedicated computational resources for
/// fault attack campaigns. It maintains communication channels for work
/// distribution and result collection, enabling efficient parallel processing
/// of large-scale fault injection scenarios.
///
/// # Architecture
///
/// * **Worker Pool**: Dedicated threads for fault attack processing
/// * **Channel-based Communication**: Thread-safe work distribution
/// * **Result Aggregation**: Centralized collection of successful attacks
/// * **Lifecycle Management**: Automatic cleanup and resource management
///
/// # Usage Pattern
///
/// 1. Create with `new()` providing a result collection channel
/// 2. Start worker threads with `start_worker_threads()` and simulation thread
/// 3. Distribute work using `send_fault_attack_workload()` for parallel processing
/// 4. Workers automatically process attacks and report results
/// 5. Automatic cleanup when dropped (workers terminate gracefully)
///
/// # Thread Safety
///
/// All operations are thread-safe and designed for concurrent access from
/// multiple coordinator threads while maintaining data consistency.
pub struct FaultAttackThread {
    /// Channel sender for distributing fault attack workloads to worker threads.
    ///
    /// Set to None after workers are started to prevent new work submission
    /// after shutdown has begun.
    workload_sender: Option<Sender<FaultAttackWorkload>>,
    /// Channel receiver shared among all worker threads for work distribution.
    ///
    /// Each worker thread clones this receiver to participate in round-robin
    /// work distribution from the shared workload queue.
    workload_receiver: Receiver<FaultAttackWorkload>,
    /// Channel sender for returning successful attack results to coordinator.
    ///
    /// Worker threads use this to report successful fault injection results
    /// back to the main analysis thread for aggregation and reporting.
    result_sender: Sender<(Vec<FaultElement>, usize)>,
    /// Thread handles for spawned worker processes.
    ///
    /// Maintained for proper cleanup during drop, ensuring all worker threads
    /// terminate gracefully before the manager is destroyed.
    handles: Option<Vec<JoinHandle<()>>>,
}

impl FaultAttackThread {
    /// Creates a new FaultAttackThread instance with a result channel.
    ///
    /// This constructor initializes the communication channels and synchronization
    /// primitives needed for coordinating fault attacks across multiple worker threads.
    /// No worker threads are spawned at this stage.
    ///
    /// # Arguments
    ///
    /// * `result_sender` - Channel for sending fault attack results back to the coordinator.
    ///
    /// # Returns
    ///
    /// * `Ok(FaultAttackThread)` - Successfully initialized FaultAttackThread with communication channels.
    /// * `Err(String)` - Error message if initialization fails (currently never fails).
    ///
    /// # Next Steps
    ///
    /// After creation, call `start_worker_threads()` to spawn the worker thread pool
    /// and begin accepting fault attack workloads.
    pub fn new(result_sender: Sender<(Vec<FaultElement>, usize)>) -> Result<Self, String> {
        // Create a channel for sending fault attack workloads to threads
        let (workload_sender, workload_receiver): (
            Sender<FaultAttackWorkload>,
            Receiver<FaultAttackWorkload>,
        ) = unbounded();

        Ok(FaultAttackThread {
            workload_sender: Some(workload_sender),
            workload_receiver,
            result_sender,
            handles: None,
        })
    }

    /// Starts the specified number of worker threads for parallel fault attack execution.
    ///
    /// This method spawns a pool of worker threads that listen for fault attack workloads
    /// and execute fault injection attacks in parallel. Each thread gets access to the
    /// simulation thread for workload processing and maintains initial trace data.
    ///
    /// # Arguments
    ///
    /// * `number_of_threads` - Number of worker threads to spawn (must be > 0).
    /// * `user_thread` - Arc-wrapped SimulationThread for workload processing.
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
    /// 2. Listens for `FaultAttackWorkload` on the shared workload channel
    /// 3. Processes fault attack workloads by executing fault sequences
    /// 4. Sends successful attack results via the fault_sender channel
    /// 5. Increments the shared workload counter on completion
    /// 6. Continues until the workload channel is closed
    pub fn start_worker_threads(
        &mut self,
        number_of_threads: usize,
        user_thread: Arc<SimulationThread>,
    ) -> Result<(), String> {
        // Check that number of threads is greater than 0
        if number_of_threads == 0 {
            return Err("Number of threads must be greater than 0".to_string());
        }

        // Create a vector to hold the thread handles
        self.handles = Some(vec![]);

        // Get initial trace data
        let initial_trace = get_initial_trace_data(Arc::clone(&user_thread))?;
        for _ in 0..number_of_threads {
            // Copy data to be moved into threads
            let receiver = self.workload_receiver.clone();
            let initial_trace = initial_trace.clone();
            let user_thread = Arc::clone(&user_thread);
            let result_sender = self.result_sender.clone();

            // Spawn worker thread
            let handle = spawn(move || {
                // Setup dissassembly engine
                let cs = Disassembly::new();

                // Loop until the workload receiver is closed
                while let Ok(msg) = receiver.recv() {
                    let FaultAttackWorkload { fault_sequence } = msg;

                    // Execute fault simulation for the given fault sequence
                    // TODO: Handle error properly
                    let (result, n) = fault_simulation(
                        &fault_sequence,
                        initial_trace.clone(),
                        &cs,
                        Arc::clone(&user_thread),
                    )
                    .unwrap();

                    result_sender.send((result, n)).unwrap();
                }
            });

            self.handles.as_mut().unwrap().push(handle);
        }

        Ok(())
    }

    /// Sends a fault attack workload to worker threads for processing.
    ///
    /// This method creates and sends a fault attack workload to the worker thread pool
    /// for parallel execution of fault injection attacks. Results are automatically
    /// sent through the shared result channel.
    ///
    /// # Arguments
    ///
    /// * `fault_sequence` - Sequence of faults to apply during the attack.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Workload successfully sent to worker threads.
    /// * `Err(String)` - Error if sending fails or channel is closed.
    pub fn send_fault_attack_workload(&self, fault_sequence: &[FaultType]) -> Result<(), String> {
        if let Some(sender) = &self.workload_sender {
            let workload = FaultAttackWorkload {
                fault_sequence: fault_sequence.to_vec(),
            };
            sender
                .send(workload)
                .map_err(|e| format!("Failed to send fault attack workload: {}", e))
        } else {
            Err("Fault attack workload sender channel is closed".to_string())
        }
    }
}

impl Drop for FaultAttackThread {
    fn drop(&mut self) {
        // Close the sender to signal worker threads to stop
        drop(self.workload_sender.take());

        // Wait for all worker threads to complete
        if let Some(handles) = self.handles.take() {
            for handle in handles {
                let _ = handle.join();
            }
        }
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
/// * `Ok((Vec<FaultElement>, usize))` - Tuple containing successful attack results and execution count.
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
fn fault_simulation(
    faults: &[FaultType],
    mut records: TraceElement,
    cs: &Disassembly,
    user_thread: Arc<SimulationThread>,
) -> Result<(Vec<FaultElement>, usize), String> {
    println!("Running simulation for faults: {faults:?}");

    // Check if faults are empty
    if faults.is_empty() {
        return Ok((Vec::new(), 0));
    }

    // Split faults into first and remaining faults
    let (first_fault, remaining_faults) = faults.split_first().unwrap();
    first_fault.filter(&mut records, cs);

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
                    &user_thread,
                )?;
            } else {
                return Err("No instruction record found".to_string());
            }

            Ok(number)
        })
        .sum();

    // Sum up successful attacks
    let n = n_result?;

    let mut data = Vec::new();
    // Collect results from worker threads
    for _ in 0..n {
        match fault_response_receiver.recv_timeout(Duration::from_millis(1000)) {
            Ok(faults) => {
                if let FaultEnum::FaultData(faults) = faults {
                    data.push(faults);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err("Timeout while receiving fault simulation results".to_string());
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err("Fault simulation result channel disconnected".to_string());
            }
        }
    }
    // TODO: Remove print or make optional
    // println!("-> {} attacks executed, {} successful", n, data.len());

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
    fault_response_sender: Sender<FaultEnum>,
    remaining_faults: &[FaultType],
    simulation_fault_records: &[FaultRecord],
    cs: &Disassembly,
    user_thread: &SimulationThread,
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

/// Helper function to get initial trace data from the simulation thread.
///
/// This function submits a trace recording request to get the baseline execution
/// trace without any fault injections, which is used by worker threads as the
/// starting point for fault attack simulations.
///
/// # Arguments
///
/// * `user_thread` - Arc-wrapped SimulationThread for workload management.
///
/// # Returns
///
/// * `Ok(TraceElement)` - Initial execution trace records without faults.
/// * `Err(String)` - Error message if trace recording fails or times out.
fn get_initial_trace_data(user_thread: Arc<SimulationThread>) -> Result<TraceElement, String> {
    // Collect trace records with simulation fault records to get new running length (time)
    // Setup the trace response channel
    let (trace_response_sender, trace_response_receiver) = unbounded();
    // Run simulation to record normal fault program flow as a base for fault injection
    user_thread.send_workload(
        RunType::RecordTrace,
        user_thread.config.deep_analysis,
        vec![],
        Some(trace_response_sender),
        None,
    )?;

    let records = trace_response_receiver
        .recv()
        .expect("Unable to receive trace data");

    Ok(records)
}
