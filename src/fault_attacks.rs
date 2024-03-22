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

    pub fn print_trace_for_fault(&self, attack_number: usize) -> Result<(), String> {
        if let Some(fault_data) = &self.fault_data {
            let fault_records =
                FaultData::get_simulation_fault_records(fault_data.get(attack_number).unwrap());
            // Run full trace
            let trace_records = Some(trace_run(
                &self.file_data,
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

    pub fn check_for_correct_behavior(&self) -> Result<(), String> {
        // Get trace data from negative run
        let mut simulation = Control::new(&self.file_data);
        simulation.check_program()
    }

    /// Run single glitch attacks
    ///
    /// Parameter is the range of the single glitch size in commands
    /// Return (success: bool, number_of_attacks: usize)
    pub fn single_glitch(
        &mut self,
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Get trace data from negative run
        let records = trace_run(&self.file_data, RunType::RecordTrace, low_complexity, &[])?;
        debug!("Number of trace steps: {}", records.len());

        for i in range {
            self.fault_data = Some(self.fault_simulation(&[FaultType::Glitch(i)], low_complexity)?);

            if self.fault_data.is_some() {
                break;
            }
        }

        Ok((self.fault_data.is_some(), self.count_sum))
    }

    pub fn double_glitch(
        &mut self,
        low_complexity: bool,
        range: std::ops::RangeInclusive<usize>,
    ) -> Result<(bool, usize), String> {
        // Run cached double nop simulation
        let it = range.clone().cartesian_product(range);
        for t in it {
            self.fault_data = Some(self.fault_simulation(
                &[FaultType::Glitch(t.0), FaultType::Glitch(t.1)],
                low_complexity,
            )?);

            if self.fault_data.is_some() {
                break;
            }
        }

        Ok((self.fault_data.is_some(), self.count_sum))
    }

    pub fn fault_simulation(
        &mut self,
        faults: &[FaultType],
        low_complexity: bool,
    ) -> Result<Vec<Vec<FaultData>>, String> {
        println!("Running simulation for faults: {faults:?}");
        if faults.is_empty() {
            return Ok(Vec::new());
        }
        let records = trace_run(&self.file_data, RunType::RecordTrace, low_complexity, &[])?;
        let bar = ProgressBar::new(records.len() as u64);
        let (mut sender, receiver) = channel();
        let temp_file_data = &self.file_data;

        simulation_run(temp_file_data, &[], &mut sender)?; // Run once without any fault
        let (&fault_type, remaining_faults) = faults.split_first().unwrap();
        let n_result: Result<usize, String> = (0..records.len())
            .into_par_iter()
            .map_with(sender, |s, index| -> Result<usize, String> {
                let fault_record = SimulationFaultRecord { index, fault_type };

                bar.inc(1);

                if remaining_faults.is_empty() {
                    simulation_run(temp_file_data, &[fault_record], s)?;
                    Ok(1)
                } else {
                    let number = Self::fault_simulation_inner(
                        temp_file_data,
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
        faults: &[FaultType],
        fixed_fault_records: &[SimulationFaultRecord],
        low_complexity: bool,
        s: &mut Sender<Vec<FaultData>>,
    ) -> Result<usize, String> {
        let mut n = 0;
        let records = trace_run(
            file_data,
            RunType::RecordTrace,
            low_complexity,
            fixed_fault_records,
        )?;

        let (&fault_type, remaining_faults) = faults.split_first().unwrap();
        // Run without this fault
        if remaining_faults.is_empty() {
            n += 1;
            simulation_run(file_data, fixed_fault_records, s)?;
        } else {
            n += Self::fault_simulation_inner(
                file_data,
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
                simulation_run(file_data, &fault_records, s)?;
            } else {
                n += Self::fault_simulation_inner(
                    file_data,
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
    run_type: RunType,
    low_complexity: bool,
    records: &[SimulationFaultRecord],
) -> Result<Vec<TraceRecord>, String> {
    let mut simulation = Control::new(file_data);
    let result = simulation.run_with_faults(run_type, low_complexity, records)?;
    Ok(result.1)
}

fn simulation_run(
    file_data: &ElfFile,
    records: &[SimulationFaultRecord],
    s: &mut Sender<Vec<FaultData>>,
) -> Result<(), String> {
    let mut simulation = Control::new(file_data);
    let fault_data_vec = simulation.run_with_faults(RunType::Run, false, records)?.0;
    if !fault_data_vec.is_empty() {
        s.send(fault_data_vec).unwrap();
    }
    Ok(())
}
