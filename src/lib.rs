use addr2line::gimli;

mod simulation;
use simulation::*;

mod elf_file;
use elf_file::ElfFile;

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
    pub file_data: ElfFile,
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

    pub fn print_fault_data(
        &self,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        self.cs.print_fault_records(&self.fault_data, debug_context);
    }

    pub fn print_trace_for_fault(&self, attack_number: usize) {
        if let Some(fault_data) = &self.fault_data {
            let fault_records =
                FaultData::get_simulation_fault_records(fault_data.get(attack_number).unwrap());
            // Run full trace
            let trace_records = Some(trace_run(
                &self.file_data,
                RunType::RecordFullTrace,
                false,
                &fault_records,
            ));
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            self.cs.print_trace_records(&trace_records);
        }
    }

    pub fn check_for_correct_behavior(&self) {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data);
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
        let records = trace_run(&self.file_data, RunType::RecordTrace, low_complexity, &[]);
        let mut count;
        debug!("Number of trace steps: {}", records.len());

        for i in range {
            (self.fault_data, count) =
                self.fault_simulation(&[FaultType::Glitch(i)], low_complexity);
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
        let mut count;

        // Run cached double nop simulation
        let it = range.clone().cartesian_product(range);
        for t in it {
            (self.fault_data, count) = self.fault_simulation(
                &[FaultType::Glitch(t.0), FaultType::Glitch(t.1)],
                low_complexity,
            );
            self.count_sum += count;

            if self.fault_data.is_some() {
                break;
            }
        }

        (self.fault_data.is_some(), self.count_sum)
    }

    fn fault_simulation(
        &self,
        faults: &[FaultType],
        low_complexity: bool,
    ) -> (Option<Vec<Vec<FaultData>>>, usize) {
        if faults.is_empty() {
            return (None, 0);
        }
        let n = AtomicUsize::new(0);
        let records = trace_run(&self.file_data, RunType::RecordTrace, low_complexity, &[]);
        let bar = ProgressBar::new(records.len() as u64);
        let (sender, receiver) = channel();
        let temp_file_data = &self.file_data;

        let (&fault_type, remaining_faults) = faults.split_first().unwrap();
        (0..records.len())
            .into_par_iter()
            .for_each_with(sender, |s, index| {
                let fault_record = SimulationFaultRecord { index, fault_type };

                bar.inc(1);

                if remaining_faults.is_empty() {
                    n.fetch_add(1, Ordering::Relaxed);
                    simulation_run(temp_file_data, &[fault_record], s);
                } else {
                    n.fetch_add(
                        Self::fault_simulation_inner(
                            temp_file_data,
                            remaining_faults,
                            &[fault_record],
                            low_complexity,
                            s,
                        ),
                        Ordering::Relaxed,
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

    fn fault_simulation_inner(
        file_data: &ElfFile,
        faults: &[FaultType],
        fixed_fault_records: &[SimulationFaultRecord],
        low_complexity: bool,
        s: &mut Sender<Vec<FaultData>>,
    ) -> usize {
        let mut n = 0;
        let records = trace_run(
            file_data,
            RunType::RecordTrace,
            low_complexity,
            fixed_fault_records,
        );

        let (&fault_type, remaining_faults) = faults.split_first().unwrap();
        for index in 0..records.len() {
            let fault_record = SimulationFaultRecord { index, fault_type };

            if remaining_faults.is_empty() {
                n += 1;
                simulation_run(file_data, &[fault_record], s);
            } else {
                let mut fault_records = fixed_fault_records.to_vec();
                fault_records.push(fault_record);
                n += Self::fault_simulation_inner(
                    file_data,
                    remaining_faults,
                    &fault_records,
                    low_complexity,
                    s,
                );
            }
        }
        n
    }
}

fn trace_run(
    file_data: &ElfFile,
    run_type: RunType,
    low_complexity: bool,
    records: &[SimulationFaultRecord],
) -> Vec<TraceRecord> {
    let mut simulation = Control::new(file_data);
    simulation
        .run_with_faults(run_type, low_complexity, records)
        .1
        .unwrap()
        .to_vec()
}

fn simulation_run(
    file_data: &ElfFile,
    records: &[SimulationFaultRecord],
    s: &mut Sender<Vec<FaultData>>,
) {
    let mut simulation = Control::new(file_data);
    if let Some(fault_data_vec) = simulation.run_with_faults(RunType::Run, false, records).0 {
        s.send(fault_data_vec).unwrap();
    }
}
