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

pub struct FaultAttacks {
    cs: Disassembly,
    file_data: ElfFile,
    pub count_sum: usize,
    success: bool,
}

impl FaultAttacks {
    pub fn new(path: std::path::PathBuf) -> Self {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path);

        Self {
            cs: Disassembly::new(),
            file_data,
            count_sum: 0,
            success: false,
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
    pub fn single_glitch(&mut self, range: std::ops::RangeInclusive<usize>) -> (bool, usize) {
        // Get trace data from negative run
        let mut records = trace_run(&self.file_data, &[]);

        for i in range {
            let (nop_1, count) = self.cached_nop_simulation_x_y(&mut records, i, 0);
            self.count_sum += count;
            if self.cs.print_fault_records(&nop_1) != 0 {
                self.success = true;
                break;
            }
        }
        (self.success, self.count_sum)
    }

    pub fn double_glitch(&mut self, range: std::ops::RangeInclusive<usize>) -> (bool, usize) {
        // Get trace data from negative run
        let mut records = trace_run(&self.file_data, &[]);

        // Run cached double nop simulation
        let it = range.combinations_with_replacement(2);
        for t in it {
            let (nop, count) = self.cached_nop_simulation_x_y(&mut records, t[0], t[1]);
            self.count_sum += count;
            if self.cs.print_fault_records(&nop) != 0 {
                self.success = true;
                break;
            }
        }

        (self.success, self.count_sum)
    }

    /// Run program with single bit flip on every instruction injected as an fault attack
    ///
    pub fn single_bit_flip(&mut self) -> (bool, usize) {
        let mut count = 0;
        // Get trace data from negative run
        let records = trace_run(&self.file_data, &[]);
        // Print overview
        records.iter().for_each(|rec| count += rec.size * 8);
        let bar = ProgressBar::new(count as u64);
        println!("Fault injection: Bit-Flip (Cached)");
        // Setup sender and receiver
        let (sender, receiver) = channel();
        // Start all threads (all will execute with a single address)
        records.into_par_iter().for_each_with(sender, |s, record| {
            for bit_pos in 0..(record.size * 8) {
                let mut temp_record = record;
                temp_record.set_fault_type(FaultType::BitFlipCached(bit_pos));
                simulation_run(&self.file_data, &[temp_record], s);
                bar.inc(1);
            }
        });
        bar.finish_and_clear();
        println!("-> {count} attacks executed");
        // Return collected successful attacks to caller
        let data: Vec<_> = receiver.iter().collect();
        self.cs.print_fault_records(&data);

        self.count_sum += count;

        if data.is_empty() {
            return (false, self.count_sum);
        }
        (true, self.count_sum)
    }

    /// Run program with a single nop instruction injected as an fault attack
    ///
    pub fn cached_nop_simulation_x_y(
        &self,
        records: &mut Vec<SimulationFaultRecord>,
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
        let (sender, receiver) = channel();
        let temp_file_data = &self.file_data;

        records.into_par_iter().for_each_with(sender, |s, record| {
            record.set_fault_type(FaultType::NopCached(num_x));

            if num_y == 0 {
                n.fetch_add(1, Ordering::Relaxed);
                simulation_run(temp_file_data, &[*record], s);
            } else {
                // Get intermediate trace data from negative run with inserted nop -> new program flow
                let intermediate_records = trace_run(temp_file_data, &[*record]);

                n.fetch_add(intermediate_records.len(), Ordering::Relaxed);
                // Run full test with intemediate trace data
                intermediate_records
                    .into_iter()
                    .for_each(|mut intermediate_record| {
                        intermediate_record.set_fault_type(FaultType::NopCached(num_y));
                        simulation_run(temp_file_data, &[*record, intermediate_record], s);
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
}

fn trace_run(file_data: &ElfFile, records: &[SimulationFaultRecord]) -> Vec<SimulationFaultRecord> {
    let mut simulation = Simulation::new(file_data);
    simulation.record_code_trace(records)
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
    drop(simulation);
}
