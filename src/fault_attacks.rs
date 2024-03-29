use crate::disassembly::Disassembly;
pub use crate::simulation::FaultType;
use crate::simulation::*;

use addr2line::gimli;

use rayon::prelude::*;

use std::sync::mpsc::{channel, Sender};

use indicatif::ProgressBar;

use itertools::Itertools;

use log::debug;

pub struct FaultAttacks {
    cs: Disassembly,
    pub file_data: ElfFile,
    fault_data: Vec<Vec<FaultData>>,
    pub count_sum: usize,
}

impl FaultAttacks {
    pub fn new(path: std::path::PathBuf) -> Self {
        // Load victim data
        let file_data: ElfFile = ElfFile::new(path);

        Self {
            cs: Disassembly::new(),
            file_data,
            fault_data: Vec::new(),
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
                false,
                &fault_records,
            )?);
            // Print trace
            println!("\nAssembler trace of attack number {}", attack_number + 1);

            self.cs.print_trace_records(&trace_records);
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
    pub fn single_glitch(
        &mut self,
        cycles: usize,
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached single nop simulation
        for i in range {
            self.fault_data =
                self.fault_simulation(cycles, &[FaultType::Glitch(i)], low_complexity)?;

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
    pub fn double_glitch(
        &mut self,
        cycles: usize,
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached double nop simulation
        let it = range.clone().cartesian_product(range);
        for t in it {
            self.fault_data = self.fault_simulation(
                cycles,
                &[FaultType::Glitch(t.0), FaultType::Glitch(t.1)],
                low_complexity,
            )?;

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
        low_complexity: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        println!("Running simulation for faults: {faults:?}");
        if faults.is_empty() {
            return Ok(Vec::new());
        }
        // Run simulation to record normal fault program flow as a base for fault injection
        let records = trace_run(
            &self.file_data,
            cycles,
            RunType::RecordTrace,
            low_complexity,
            &[],
        )?;
        debug!("Number of trace steps: {}", records.len());

        let bar = ProgressBar::new(records.len() as u64);
        let (mut sender, receiver) = channel();
        let temp_file_data = &self.file_data;

        simulation_run(temp_file_data, cycles, &[], &mut sender)?; // Run once without any fault
        let (&fault_type, remaining_faults) = faults.split_first().unwrap();
        let n_result: Result<usize, String> = (0..records.len())
            .into_par_iter()
            .map_with(sender, |s, index| -> Result<usize, String> {
                let fault_record = SimulationFaultRecord { index, fault_type };

                bar.inc(1);

                if remaining_faults.is_empty() {
                    simulation_run(temp_file_data, cycles, &[fault_record], s)?;
                    Ok(1)
                } else {
                    let number = Self::fault_simulation_inner(
                        temp_file_data,
                        cycles,
                        remaining_faults,
                        &[fault_record],
                        low_complexity,
                        s,
                    )?;
                    Ok(number)
                }
            })
            .sum();
        bar.finish_and_clear();
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
        fixed_fault_records: &[SimulationFaultRecord],
        low_complexity: bool,
        s: &mut Sender<Vec<FaultData>>,
    ) -> Result<usize, String> {
        let mut n = 0;
        let records = trace_run(
            file_data,
            cycles,
            RunType::RecordTrace,
            low_complexity,
            fixed_fault_records,
        )?;

        let (&fault_type, remaining_faults) = faults.split_first().unwrap();
        // Run without this fault
        if remaining_faults.is_empty() {
            n += 1;
            simulation_run(file_data, cycles, fixed_fault_records, s)?;
        } else {
            n += Self::fault_simulation_inner(
                file_data,
                cycles,
                remaining_faults,
                fixed_fault_records,
                low_complexity,
                s,
            )?;
        }
        for index in 0..records.len() {
            let fault_record = SimulationFaultRecord { index, fault_type };
            let mut fault_records = fixed_fault_records.to_vec();
            fault_records.push(fault_record);

            if remaining_faults.is_empty() {
                n += 1;
                simulation_run(file_data, cycles, &fault_records, s)?;
            } else {
                n += Self::fault_simulation_inner(
                    file_data,
                    cycles,
                    remaining_faults,
                    &fault_records,
                    low_complexity,
                    s,
                )?;
            }
        }
        Ok(n)
    }
}

fn trace_run(
    file_data: &ElfFile,
    cycles: usize,
    run_type: RunType,
    low_complexity: bool,
    records: &[SimulationFaultRecord],
) -> Result<Vec<TraceRecord>, String> {
    let mut simulation = Control::new(file_data);
    let data = simulation.run_with_faults(cycles, run_type, low_complexity, records)?;
    match data {
        Data::Trace(trace) => Ok(trace),
        _ => Ok(Vec::new()),
    }
}

fn simulation_run(
    file_data: &ElfFile,
    cycles: usize,
    records: &[SimulationFaultRecord],
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
