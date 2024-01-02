mod simulation;
use simulation::*;

mod elf_file;
use elf_file::ElfFile;

// Set number of threads: RAYON_NUM_THREADS="1" cargo run
use rayon::prelude::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};

use indicatif::ProgressBar;

mod disassembly;
use disassembly::Disassembly;

use itertools::Itertools;

use log::debug;

pub struct FaultAttacks {
    cs: Disassembly,
    file_data: ElfFile,
    fault_data: Option<Vec<Vec<FaultData>>>,
    pub count_sum: usize,
}

impl FaultAttacks {
    pub fn new(path: std::path::PathBuf) -> Self {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path);

        Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: None,
            count_sum: 0,
        }
    }

    pub fn print_fault_data(&self) {
        self.cs.print_fault_records(&self.fault_data);
    }

    pub fn print_trace_for_fault(&self, attack_number: usize) {
        if let Some(fault_data) = &self.fault_data {
            let fault_records =
                FaultData::get_simulation_fault_records(fault_data.get(attack_number).unwrap());
            // Run full trace
            let trace_records = Some(trace_run(&self.file_data, true, false, fault_records));
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            self.cs.print_trace_records(&trace_records);
        }
    }

    pub fn check_for_correct_behavior(&self) {
        // Get trace data from negative run
        let mut simulation = Simulation::new(&self.file_data);
        simulation.check_program();
    }

    /// Run single glitch attacks
    ///
    /// Parameter is the range of the single glitch size in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn single_glitch(
        &mut self,
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> (bool, usize) {
        // Get trace data from negative run
        let mut records = trace_run(&self.file_data, false, low_complexity, vec![]);
        let mut count;
        debug!("Number of trace steps: {}", records.len());

        for i in range {
            (self.fault_data, count) =
                self.cached_nop_simulation_x_y(&mut records, low_complexity, i, 0);
            self.count_sum += count;

            if self.fault_data.is_some() {
                break;
            }
        }

        (self.fault_data.is_some(), self.count_sum)
    }

    pub fn double_glitch(
        &mut self,
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> (bool, usize) {
        // Get trace data from negative run
        let mut records = trace_run(&self.file_data, false, low_complexity, vec![]);
        let mut count;

        // Run cached double nop simulation
        let it = range.clone().cartesian_product(range);
        for t in it {
            (self.fault_data, count) =
                self.cached_nop_simulation_x_y(&mut records, low_complexity, t.0, t.1);
            self.count_sum += count;

            if self.fault_data.is_some() {
                break;
            }
        }

        (self.fault_data.is_some(), self.count_sum)
    }

    /// Run program with single bit flip on every instruction injected as an fault attack
    ///
    // pub fn single_bit_flip(&mut self) -> (bool, usize) {
    //     let mut count = 0;
    //     // Get trace data from negative run
    //     let records = trace_run(&self.file_data, vec![]);
    //     // Print overview
    //     records.iter().for_each(|rec| count += rec.size * 8);
    //     let bar = ProgressBar::new(count as u64);
    //     println!("Fault injection: Bit-Flip (Cached)");
    //     // Setup sender and receiver
    //     let (sender, receiver) = channel();
    //     // Start all threads (all will execute with a single address)
    //     records.into_par_iter().for_each_with(sender, |s, record| {
    //         for bit_pos in 0..(record.size * 8) {
    //             let mut temp_record = record;
    //             temp_record.set_fault_type(FaultType::BitFlipCached(bit_pos));
    //             simulation_run(&self.file_data, &[temp_record], s);
    //             bar.inc(1);
    //         }
    //     });
    //     bar.finish_and_clear();
    //     println!("-> {count} attacks executed");
    //     // Return collected successful attacks to caller
    //     let data: Vec<_> = receiver.iter().collect();
    //     self.cs.print_fault_records(&data);

    //     self.count_sum += count;

    //     if data.is_empty() {
    //         return (false, self.count_sum);
    //     }
    //     (true, self.count_sum)
    // }

    /// Run program with a single nop instruction injected as an fault attack
    ///
    pub fn cached_nop_simulation_x_y(
        &self,
        records: &Vec<TraceRecord>,
        low_complexity: bool,
        num_x: usize,
        num_y: usize,
    ) -> (Option<Vec<Vec<FaultData>>>, usize) {
        // Print overview
        let n = AtomicUsize::new(0);
        println!(
            "Fault injection - Insert {} cached-NOP areas - with A: {} and B: {} consecutive nops",
            if num_x == 0 || num_y == 0 { 1 } else { 2 },
            num_x,
            num_y
        );
        let bar = ProgressBar::new(records.len() as u64);
        // Setup sender and receiver
        let (sender, receiver) = channel();
        let temp_file_data = &self.file_data;

        records
            .into_par_iter()
            .enumerate()
            .for_each_with(sender, |s, (index, record)| {
                let fault_record = record.get_fault_record(index, FaultType::Glitch(num_x));

                bar.inc(1);

                if num_y == 0 {
                    n.fetch_add(1, Ordering::Relaxed);
                    simulation_run(temp_file_data, &[fault_record.clone()], s);
                } else {
                    // Get intermediate trace data from negative run with inserted nop -> new program flow
                    let intermediate_trace_records = trace_run(
                        temp_file_data,
                        false,
                        low_complexity,
                        vec![fault_record.clone()],
                    );

                    n.fetch_add(intermediate_trace_records.len(), Ordering::Relaxed);
                    // Run full test with intemediate trace data
                    intermediate_trace_records.into_iter().enumerate().for_each(
                        |(index, intermediate_trace_records)| {
                            let intermediate_fault_record = intermediate_trace_records
                                .get_fault_record(index, FaultType::Glitch(num_y));
                            simulation_run(
                                temp_file_data,
                                &[fault_record.clone(), intermediate_fault_record],
                                s,
                            );
                        },
                    );
                }
            });
        bar.finish_and_clear();
        println!("-> {} attacks executed", n.load(Ordering::Relaxed));
        // Return collected successful attacks to caller
        let data: Vec<_> = receiver.iter().collect();
        if data.is_empty() {
            (None, n.load(Ordering::Relaxed))
        } else {
            (Some(data), n.load(Ordering::Relaxed))
        }
    }
}

fn trace_run(
    file_data: &ElfFile,
    full_trace: bool,
    low_complexity: bool,
    records: Vec<SimulationFaultRecord>,
) -> Vec<TraceRecord> {
    let mut simulation = Simulation::new(file_data);
    simulation.record_code_trace(full_trace, low_complexity, records)
}

fn simulation_run(
    file_data: &ElfFile,
    records: &[SimulationFaultRecord],
    s: &mut Sender<Vec<FaultData>>,
) {
    let mut simulation = Simulation::new(file_data);
    if let Some(fault_data_vec) = simulation.run_with_faults(records) {
        s.send(fault_data_vec).unwrap();
    }
}

// Check for repeated loop
// let last = intermediate_records.last().unwrap();
// let mut int_rec = intermediate_records.clone();
// int_rec.reverse();
// let found = int_rec
//     .iter()
//     .find_position(|rec| rec.address != last.address);
// if let Some(found) = found {
//     if found.0 != 1 {
//         println!("{:?}", found);
//     }
// }
