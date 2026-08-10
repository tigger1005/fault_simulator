use std::sync::Arc;
use std::thread::{spawn, JoinHandle};

use crate::disassembly::Disassembly;
use crate::error::SimulatorError;
use crate::prelude::{SimulationThread, TraceRecord};

use crate::simulation::{record::FaultRecord, FaultElement, RunType, TraceElement};
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

/// Result of one fault attack workload: the successful attacks and the number of
/// executed runs, or the error that aborted it.
type WorkloadResult = Result<(Vec<FaultElement>, usize), SimulatorError>;

/// Receives one message, honouring an optional timeout.
///
/// A timeout means no worker produced any result within the window, which on a slow or
/// heavily loaded machine usually means the limit is simply too tight.
fn recv_result<T>(
    receiver: &Receiver<T>,
    timeout: Option<Duration>,
    context: &str,
) -> Result<T, SimulatorError> {
    let result = match timeout {
        Some(timeout) => receiver.recv_timeout(timeout),
        None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
    };

    match result {
        Ok(value) => Ok(value),
        Err(RecvTimeoutError::Timeout) => Err(SimulatorError::timeout(format!(
            "No {} arrived within {} s. Raise the limit with --result-timeout (or the \
             FAULT_SIM_RESULT_TIMEOUT environment variable, 0 waits forever) if the machine \
             is slow or heavily loaded.",
            context,
            timeout.unwrap_or_default().as_secs()
        ))),
        Err(RecvTimeoutError::Disconnected) => Err(SimulatorError::channel(format!(
            "{} channel disconnected",
            context
        ))),
    }
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
    result_sender: Sender<WorkloadResult>,
    /// Channel receiver for collecting successful attack results from workers.
    result_receiver: Receiver<WorkloadResult>,
    /// Thread handles for spawned worker processes.
    ///
    /// Maintained for proper cleanup during drop, ensuring all worker threads
    /// terminate gracefully before the manager is destroyed.
    handles: Option<Vec<JoinHandle<()>>>,
    /// Maximum time to wait for a single workload result, taken from the simulation config.
    result_timeout: Option<Duration>,
}

impl FaultAttackThread {
    /// Creates a new FaultAttackThread instance.
    ///
    /// This constructor initializes the communication channels and synchronization
    /// primitives needed for coordinating fault attacks across multiple worker threads.
    /// No worker threads are spawned at this stage.
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
    pub fn new() -> Result<Self, SimulatorError> {
        // Create a channel for sending fault attack workloads to threads
        let (workload_sender, workload_receiver): (
            Sender<FaultAttackWorkload>,
            Receiver<FaultAttackWorkload>,
        ) = unbounded();

        // Create a channel for collecting results from worker threads
        let (result_sender, result_receiver) = unbounded();

        Ok(FaultAttackThread {
            workload_sender: Some(workload_sender),
            workload_receiver,
            result_sender,
            result_receiver,
            handles: None,
            result_timeout: crate::simulation_thread::default_result_timeout(),
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
    ) -> Result<(), SimulatorError> {
        // Check that number of threads is greater than 0
        if number_of_threads == 0 {
            return Err(SimulatorError::thread(
                "Number of threads must be greater than 0",
            ));
        }

        // Create a vector to hold the thread handles
        self.handles = Some(vec![]);

        self.result_timeout = user_thread.config.result_timeout;

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
                // Setup disassembly engine
                let cs = Disassembly::new();

                // Loop until the workload receiver is closed
                while let Ok(msg) = receiver.recv() {
                    let FaultAttackWorkload { fault_sequence } = msg;

                    // Execute fault simulation for the given fault sequence
                    let result = fault_simulation(
                        &fault_sequence,
                        initial_trace.clone(),
                        &cs,
                        Arc::clone(&user_thread),
                    );
                    if let Err(e) = &result {
                        log::error!("Fault simulation error: {}", e);
                    }
                    let _ = result_sender.send(result);
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
    pub fn send_fault_attack_workload(
        &self,
        fault_sequence: &[FaultType],
    ) -> Result<(), SimulatorError> {
        if let Some(sender) = &self.workload_sender {
            let workload = FaultAttackWorkload {
                fault_sequence: fault_sequence.to_vec(),
            };
            sender.send(workload).map_err(|e| {
                let msg = format!("Failed to send fault attack workload: {}", e);
                SimulatorError::channel_with(msg, e)
            })
        } else {
            Err(SimulatorError::channel(
                "Fault attack workload sender channel is closed",
            ))
        }
    }

    /// Sends a batch of fault sequences to workers and collects all results.
    ///
    /// This method distributes fault attack workloads to the worker thread pool
    /// and waits for all results to be returned, with a timeout per result.
    ///
    /// # Arguments
    ///
    /// * `chunks` - Slice of fault sequences to execute in parallel.
    ///
    /// # Returns
    ///
    /// * `Ok((data, count))` - Successful attack results and total execution count.
    /// * `Err(SimulatorError)` - A worker failed, a result timed out, or sending failed.
    pub fn run_batch(
        &self,
        chunks: &[Vec<FaultType>],
    ) -> Result<(Vec<FaultElement>, usize), SimulatorError> {
        // Discard results left over from an aborted batch so they cannot be
        // counted towards this one.
        while self.result_receiver.try_recv().is_ok() {}

        let mut n_workload = 0;
        for faults in chunks {
            self.send_fault_attack_workload(faults)?;
            n_workload += 1;
        }

        let mut all_data = Vec::new();
        let mut total_count = 0;

        for _ in 0..n_workload {
            let result = recv_result(
                &self.result_receiver,
                self.result_timeout,
                "fault attack result",
            )?;

            match result {
                Ok((data, n)) => {
                    total_count += n;
                    if !data.is_empty() {
                        all_data.extend(data);
                    }
                }
                // A failed worker makes the campaign result incomplete, so abort
                // instead of silently reporting fewer attacks.
                Err(e) => return Err(e),
            }
        }

        Ok((all_data, total_count))
    }
}

impl Drop for FaultAttackThread {
    fn drop(&mut self) {
        // Close the sender to signal worker threads to stop
        drop(self.workload_sender.take());

        // Wait for all worker threads to complete
        if let Some(handles) = self.handles.take() {
            for handle in handles {
                if let Err(e) = handle.join() {
                    log::error!("A fault attack worker thread panicked: {:?}", e);
                }
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
/// * `initial_trace` - Initial trace data that serves as the starting point for fault injection.
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
) -> Result<(Vec<FaultElement>, usize), SimulatorError> {
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
    let n_result: Result<usize, SimulatorError> = records
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
                return Err(SimulatorError::simulation("No instruction record found"));
            }

            Ok(number)
        })
        .sum();

    // Sum up successful attacks
    let n = n_result?;

    let mut data = Vec::new();
    // Collect results from worker threads
    for _ in 0..n {
        let faults = recv_result(
            &fault_response_receiver,
            user_thread.config.result_timeout,
            "fault simulation result",
        )?;
        if !faults.is_empty() {
            data.push(faults);
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
    fault_response_sender: Sender<FaultElement>,
    remaining_faults: &[FaultType],
    simulation_fault_records: &[FaultRecord],
    cs: &Disassembly,
    user_thread: &SimulationThread,
) -> Result<usize, SimulatorError> {
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
        let mut records = user_thread.get_trace(
            RunType::RecordTrace,
            user_thread.config.deep_analysis,
            simulation_fault_records.to_vec(),
        )?;

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
fn get_initial_trace_data(
    user_thread: Arc<SimulationThread>,
) -> Result<TraceElement, SimulatorError> {
    user_thread.get_trace(
        RunType::RecordTrace,
        user_thread.config.deep_analysis,
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_result_reports_timeout_with_hint() {
        let (_sender, receiver) = unbounded::<u32>();
        let error = recv_result(&receiver, Some(Duration::from_millis(10)), "test result")
            .expect_err("expected a timeout");

        let message = error.to_string();
        assert!(matches!(error, SimulatorError::Timeout(_)), "{}", message);
        assert!(message.contains("No test result arrived within 0 s"), "{}", message);
        assert!(message.contains("--result-timeout"), "{}", message);
    }

    #[test]
    fn recv_result_reports_disconnect() {
        let (sender, receiver) = unbounded::<u32>();
        drop(sender);
        let error = recv_result(&receiver, None, "test result").expect_err("expected a disconnect");
        assert!(matches!(error, SimulatorError::Channel(_)));
    }

    #[test]
    fn recv_result_passes_value_through() {
        let (sender, receiver) = unbounded();
        sender.send(42u32).unwrap();
        assert_eq!(
            recv_result(&receiver, Some(Duration::from_secs(1)), "test result").unwrap(),
            42
        );
    }
}
