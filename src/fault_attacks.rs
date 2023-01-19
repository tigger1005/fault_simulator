use super::*;

// Set number of threads: RAYON_NUM_THREADS="1" cargo run
use rayon::prelude::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;

use indicatif::ProgressBar;

use crate::simulation::*;

/// Run program with a single nop instruction injected as an fault attack
/// This is done in a static / cached methode
///
pub fn cached_nop_simulation(
    file_data: &ElfFile,
    records: &Vec<SimulationFaultRecord>,
) -> Vec<Vec<FaultData>> {
    // Print overview
    let n = records.len();
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: NOP (Cached)");
    // Setup sender and receiver
    let (sender, receiver) = channel();
    // Start all threads (all will execute with a single address)
    records.into_par_iter().for_each_with(sender, |s, record| {
        let mut temp_record = *record;
        temp_record.set_fault_type(FaultType::NopCached);
        let mut simulation = Simulation::new(file_data);
        if let Some(fault_data_vec) = simulation.run_with_faults(vec![temp_record]) {
            s.send(fault_data_vec).unwrap();
        }
        drop(simulation);
        bar.inc(1);
    });

    bar.finish_and_clear();
    println!("-> {n} attacks executed");
    // Return collected successful attacks to caller
    let data: Vec<_> = receiver.iter().collect();
    data
}

/// Run program with two independant nop instruction injected as an fault attack
/// This is done in a static / cached methode
///
pub fn cached_nop_simulation_2(
    file_data: &ElfFile,
    records: &Vec<SimulationFaultRecord>,
) -> Vec<Vec<FaultData>> {
    // Print overview
    let n = AtomicUsize::new(0);
    println!("Fault injection: 2 consecutive NOP (Cached)");
    let bar = ProgressBar::new(records.len() as u64);
    // Setup sender and receiver
    let (sender, receiver) = channel(); // Loop over all addresses from first round
    records.into_par_iter().for_each_with(sender, |s, record| {
        let mut temp_record = *record;
        temp_record.set_fault_type(FaultType::NopCached);
        // Get intermediate trace data from negative run with inserted nop -> new program flow
        let mut simulation = Simulation::new(file_data);
        let intermediate_records = simulation.record_code_trace(vec![temp_record]);
        drop(simulation);
        n.fetch_add(intermediate_records.len(), Ordering::Relaxed);
        // Run full test with intemediate trace data
        intermediate_records
            .into_iter()
            .for_each(|mut intermediate_record| {
                intermediate_record.set_fault_type(FaultType::NopCached);
                let mut intermediate_simulation = Simulation::new(file_data);
                if let Some(fault_data_vec) =
                    intermediate_simulation.run_with_faults(vec![temp_record, intermediate_record])
                {
                    s.send(fault_data_vec).unwrap();
                }
                drop(intermediate_simulation);
            });

        bar.inc(1);
    });
    bar.finish_and_clear();
    println!("-> {} attacks executed", n.load(Ordering::Relaxed));
    // Return collected successful attacks to caller
    let data: Vec<_> = receiver.iter().collect();
    data
}

/// Run program with single bit flip on every instruction-command-bit injected as an fault attack
/// This is done in a static / cached methode
///
pub fn cached_bit_flip_simulation(
    file_data: &ElfFile,
    records: &Vec<SimulationFaultRecord>,
) -> Vec<Vec<FaultData>> {
    // Print overview
    let mut n = 0;
    records.iter().for_each(|rec| n += rec.size * 8);
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: Bit-Flip (Cached)");
    // Setup sender and receiver
    let (sender, receiver) = channel();
    // Start all threads (all will execute with a single address)
    records.into_par_iter().for_each_with(sender, |s, record| {
        for bit_pos in 0..(record.size * 8) {
            let mut temp_record = *record;
            temp_record.set_fault_type(FaultType::BitFlipCached(bit_pos));
            let mut simulation = Simulation::new(file_data);
            if let Some(fault_data_vec) = simulation.run_with_faults(vec![temp_record]) {
                s.send(fault_data_vec).unwrap();
            }
            drop(simulation);
            bar.inc(1);
        }
    });
    bar.finish_and_clear();
    println!("-> {n} attacks executed");
    // Return collected successful attacks to caller
    let data: Vec<_> = receiver.iter().collect();
    data
}
