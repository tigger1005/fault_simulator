use std::sync::{Arc, Mutex};
use std::thread::{/*sleep, */spawn, JoinHandle};

//use crate::disassembly::Disassembly;
use crate::elf_file::ElfFile;
//use crate::prelude::FaultType;
use crate::simulation::fault_data::FaultData;
use crossbeam_channel::{/*nunbounded, */Receiver, Sender};

use crate::simulation::{
    record::{FaultRecord, TraceRecord},
    Control, Data, RunType,
};

pub struct WorkloadMessage {
    pub run_type: RunType,
    pub deep_analysis: bool,
    pub fault_records: Vec<FaultRecord>,
    pub trace_sender: Option<Sender<Vec<TraceRecord>>>,
    pub fault_sender: Option<Sender<Vec<FaultData>>>,
}

pub fn start_worker_threads(
    number_of_threads: usize,
    cycles: usize,
    file_data: &ElfFile,
    workload_receiver: &Receiver<WorkloadMessage>,
    work_load_counter: &Arc<Mutex<usize>>,
    success_addresses: Vec<u64>,
    failure_addresses: Vec<u64>,
    initial_registers: std::collections::HashMap<unicorn_engine::RegisterARM, u64>,
) -> Result<Vec<JoinHandle<()>>, ()> {
    // Create a vector to hold the thread handles
    let mut handles: Vec<JoinHandle<()>> = vec![];

    for _ in 0..number_of_threads {
        // Copy data to be moved into threads
        let file = file_data.clone();
        let receiver = workload_receiver.clone();
        let workload_counter = Arc::clone(work_load_counter);
        let success_addrs = success_addresses.clone();
        let failure_addrs = failure_addresses.clone();
        let init_regs = initial_registers.clone();
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
        handles.push(handle);
    }
    Ok(handles)
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
