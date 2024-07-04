pub mod faults;

use super::simulation::{
    fault_data::FaultData,
    record::{FaultRecord, TraceRecord},
    Control, Data, RunType,
};
use crate::{disassembly::Disassembly, elf_file::ElfFile};
use addr2line::gimli;
use faults::*;
use indicatif::ProgressBar;
use itertools::iproduct;
use log::debug;
use rayon::prelude::*;
use std::sync::mpsc::{channel, Sender};

pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    pub fault_data: Vec<Vec<FaultData>>,
    pub count_sum: usize,
}

impl FaultAttacks {
    pub fn new(path: std::path::PathBuf) -> Result<Self, String> {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path)?;

        Ok(Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: Vec::new(),
            count_sum: 0,
        })
    }

    pub fn set_fault_data(&mut self, fault_data: Vec<Vec<FaultData>>) {
        self.fault_data = fault_data;
    }
    pub fn print_fault_data(
        &self,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        self.cs.print_fault_records(&self.fault_data, debug_context);
    }

    pub fn print_trace_for_fault(&self, cycles: usize, attack_number: usize) -> Result<(), String> {
        if !self.fault_data.is_empty() {
            let fault_records = FaultData::get_simulation_fault_records(
                self.fault_data.get(attack_number).unwrap(),
            );
            // Run full trace
            let trace_records = Some(trace_run(
                &self.file_data,
                cycles,
                RunType::RecordFullTrace,
                true,
                &fault_records,
            )?);
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            self.cs.disassembly_trace_records(&trace_records);
        }
        Ok(())
    }

    pub fn check_for_correct_behavior(&self, cycles: usize) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data);
        simulation.check_program(cycles)
    }

    /// Run single glitch attacks
    ///
    /// Parameter is the range of the single glitch size in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn single(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        prograss_bar: bool,
        groups: Option<&&str>,
    ) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
                                             // Iterate over all lists
        for list in lists {
            // Iterate over all faults in the list
            for fault in list {
                // Get fault type
                let fault = get_fault_from(&fault).unwrap();
                // Run simulation with fault
                self.fault_data =
                    self.fault_simulation(cycles, &[fault.clone()], deep_analysis, prograss_bar)?;

                if !self.fault_data.is_empty() {
                    break;
                }
            }
            if !self.fault_data.is_empty() {
                break;
            }
        }
        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    /// Run double glitch attacks
    ///
    /// Parameter is the range of the double glitch size in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn double(
        &mut self,
        cycles: usize,
        deep_analysis: bool,
        prograss_bar: bool,
        groups: Option<&&str>,
    ) -> Result<(bool, usize), String> {
        let lists = get_fault_lists(groups); // Get all faults of all lists
                                             // Iterate over all lists
        for list in lists {
            // Iterate over all faults in the list
            let iter = iproduct!(list.clone(), list).map(|(a, b)| (a, b));
            // Iterate over all fault pairs
            for t in iter {
                let fault1 = get_fault_from(&t.0).unwrap();
                let fault2 = get_fault_from(&t.1).unwrap();

                self.fault_data =
                    self.fault_simulation(cycles, &[fault1, fault2], deep_analysis, prograss_bar)?;

                if !self.fault_data.is_empty() {
                    break;
                }
            }
            if !self.fault_data.is_empty() {
                break;
            }
        }
        Ok((!self.fault_data.is_empty(), self.count_sum))
    }

    pub fn fault_simulation(
        &mut self,
        cycles: usize,
        faults: &[FaultType],
        deep_analysis: bool,
        prograss_bar: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        //
        println!("Running simulation for faults: {faults:?}");

        // Check if faults are empty
        if faults.is_empty() {
            return Ok(Vec::new());
        }

        // Run simulation to record normal fault program flow as a base for fault injection
        let mut records = trace_run(
            &self.file_data,
            cycles,
            RunType::RecordTrace,
            deep_analysis,
            &[],
        )?;
        debug!("Number of trace steps: {}", records.len());

        let mut bar: Option<ProgressBar> = None;
        // Setup progress bar and channel for fault data
        if prograss_bar {
            bar = Some(ProgressBar::new(records.len() as u64));
        }
        let (sender, receiver) = channel();

        // Split faults into first and remaining faults
        let (first_fault, remaining_faults) = faults.split_first().unwrap();
        // Filter records according to fault type
        first_fault.filter(&mut records, &self.cs);

        // Run main fault simulation loop
        let n_result: Result<usize, String> = records
            .into_par_iter()
            .map_with(sender, |s, record| -> Result<usize, String> {
                if let Some(bar) = &bar {
                    bar.inc(1);
                }

                let number;
                // Get index of the record
                if let TraceRecord::Instruction { index, .. } = record {
                    // Create a simulation fault record list with the first fault in the list
                    let simulation_fault_records = vec![FaultRecord {
                        index,
                        fault_type: first_fault.clone(),
                    }];

                    // Call recursive fault simulation with first simulation fault record
                    number = Self::fault_simulation_inner(
                        &self.file_data,
                        cycles,
                        remaining_faults,
                        &simulation_fault_records,
                        deep_analysis,
                        s,
                        &Disassembly::new(),
                    )?;
                } else {
                    return Err("No instruction record found".to_string());
                }

                Ok(number)
            })
            .sum();

        if let Some(bar) = bar {
            bar.finish_and_clear();
        }

        // Sum up successful attacks
        let n = n_result?;
        self.count_sum += n;

        // Return collected successful attacks to caller
        let data: Vec<_> = receiver.iter().collect();
        println!("-> {} attacks executed, {} successful", n, data.len());
        if data.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(data)
        }
    }

    fn fault_simulation_inner(
        file_data: &ElfFile,
        cycles: usize,
        faults: &[FaultType],
        simulation_fault_records: &[FaultRecord],
        deep_analysis: bool,
        s: &mut Sender<Vec<FaultData>>,
        cs: &Disassembly,
    ) -> Result<usize, String> {
        let mut n = 0;

        // Check if there are no remaining faults left
        if faults.is_empty() {
            // Run fault simulation. This is the end of the recursion
            simulation_run(file_data, cycles, simulation_fault_records, s)?;
            n += 1;
        } else {
            // Collect trace records with simulation fault records to get new running length (time)
            let mut records = trace_run(
                file_data,
                cycles,
                RunType::RecordTrace,
                deep_analysis,
                simulation_fault_records,
            )?;

            // Split faults into first and remaining faults
            let (first_fault, remaining_faults) = faults.split_first().unwrap();
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
                    n += Self::fault_simulation_inner(
                        file_data,
                        cycles,
                        remaining_faults,
                        &index_simulation_fault_records,
                        deep_analysis,
                        s,
                        cs,
                    )?;
                }
            }
        }

        Ok(n)
    }
}

/// Run the simulation with faults and return a trace of the program flow
///
/// If the simulation fails, return an empty vector
///
fn trace_run(
    file_data: &ElfFile,
    cycles: usize,
    run_type: RunType,
    deep_analysis: bool,
    records: &[FaultRecord],
) -> Result<Vec<TraceRecord>, String> {
    let mut simulation = Control::new(file_data);
    let data = simulation.run_with_faults(cycles, run_type, deep_analysis, records)?;
    match data {
        Data::Trace(trace) => Ok(trace),
        _ => Ok(Vec::new()),
    }
}

fn simulation_run(
    file_data: &ElfFile,
    cycles: usize,
    records: &[FaultRecord],
    s: &mut Sender<Vec<FaultData>>,
) -> Result<(), String> {
    let mut simulation = Control::new(file_data);
    let data = simulation.run_with_faults(cycles, RunType::Run, false, records)?;
    if let Data::Fault(fault) = data {
        if !fault.is_empty() {
            s.send(fault).unwrap();
        }
    }

    Ok(())
}
