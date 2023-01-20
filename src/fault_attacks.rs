use super::*;

// Set number of threads: RAYON_NUM_THREADS="1" cargo run
use rayon::prelude::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};

use indicatif::ProgressBar;

use crate::simulation::*;

/// Run program with a single nop instruction injected as an fault attack
///
pub fn cached_nop_simulation_x_y(
    file_data: &ElfFile,
    records: &Vec<SimulationFaultRecord>,
    num_x: usize,
    num_y: usize,
) -> (Vec<Vec<FaultData>>, usize) {
    // Print overview
    let n = AtomicUsize::new(0);
    println!(
        "Fault injection - Insert 2 cached-NOP areas - with A: {num_x} and B: {num_y} consecutive nops"
    );
    let bar = ProgressBar::new(records.len() as u64);
    // Setup sender and receiver
    let (sender, receiver) = channel(); // Loop over all addresses from first round
    records.into_par_iter().for_each_with(sender, |s, record| {
        let mut temp_record = *record;
        temp_record.set_fault_type(FaultType::NopCached(num_x));
        if num_y == 0 {
            n.fetch_add(1, Ordering::Relaxed);
            run_simulation(file_data, vec![temp_record], s);
        } else {
            // Get intermediate trace data from negative run with inserted nop -> new program flow
            let mut simulation = Simulation::new(file_data);
            let intermediate_records = simulation.record_code_trace(vec![temp_record]);
            drop(simulation);
            n.fetch_add(intermediate_records.len(), Ordering::Relaxed);
            // Run full test with intemediate trace data
            intermediate_records
                .into_iter()
                .for_each(|mut intermediate_record| {
                    intermediate_record.set_fault_type(FaultType::NopCached(num_y));
                    run_simulation(file_data, vec![temp_record, intermediate_record], s);
                });
        }

        bar.inc(1);
    });
    bar.finish_and_clear();
    println!("-> {} attacks executed", n.load(Ordering::Relaxed));
    // Return collected successful attacks to caller
    let data: Vec<_> = receiver.iter().collect();
    (data, n.load(Ordering::Relaxed))
}

/// Run program with single bit flip on every instruction injected as an fault attack
///
pub fn cached_bit_flip_simulation(
    file_data: &ElfFile,
    records: &Vec<SimulationFaultRecord>,
) -> (Vec<Vec<FaultData>>, usize) {
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
            run_simulation(file_data, vec![temp_record], s);
            bar.inc(1);
        }
    });
    bar.finish_and_clear();
    println!("-> {n} attacks executed");
    // Return collected successful attacks to caller
    let data: Vec<_> = receiver.iter().collect();
    (data, n)
}

fn run_simulation(
    file_data: &ElfFile,
    records: Vec<SimulationFaultRecord>,
    s: &mut Sender<Vec<FaultData>>,
) {
    let mut simulation = Simulation::new(file_data);
    if let Some(fault_data_vec) = simulation.run_with_faults(records) {
        s.send(fault_data_vec).unwrap();
    }
    drop(simulation);
}
