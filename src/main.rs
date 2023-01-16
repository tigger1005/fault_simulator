//#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

mod disassembly;
use disassembly::Disassembly;

mod simulation;
use simulation::{ExternalRecord, FaultData, Simulation};

use indicatif::ProgressBar;

use rayon::prelude::*;
use std::sync::mpsc::channel;

use std::process::Command;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

fn main() {
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    println!("- Fault injection simulator: {GIT_VERSION}\n");
    // Compile victim
    println!("Compile victim if necessary:");
    let output = Command::new("make")
        .current_dir("./Content")
        .output()
        .expect("failed to execute process");
    if !output.status.success() {
        println!("status: {}", output.status);
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        println!("Compiled: OK\n")
    }
    assert!(output.status.success());

    // Load victim data
    let file_data: ElfFile = ElfFile::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));
    let cs: Disassembly = Disassembly::new();

    println!("Check for correct program behavior:");
    // Check for correct program behavior
    let mut simulation = Simulation::new(&file_data);
    simulation.check();

    println!("\nRun fault simulations:");
    // Get trace data from negative run
    let mut simulation = Simulation::new(&file_data);
    let external_records = simulation.get_address_list(vec![]);

    // Run cached nop simulation
    if cached_nop_simulation(&file_data, external_records.clone(), &cs) == 0 {
        // Run cached double nop simulation
        cached_nop_simulation_2(&file_data, external_records.clone(), &cs);
    }
    // Run cached bit-flip simulation
    cached_bit_flip_simulation(&file_data, external_records, &cs);
}

fn cached_nop_simulation(
    file_data: &ElfFile,
    records: Vec<ExternalRecord>,
    cs: &Disassembly,
) -> usize {
    // Print overview
    let n = records.len();
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: NOP (Cached)");
    // Setup sender and receiver
    let (sender, receiver) = channel();
    // Start all threads (all will execute with a single address)
    records.into_par_iter().for_each_with(sender, |s, record| {
        let mut simulation = Simulation::new(&file_data);
        if let Some(fault_data_vec) = simulation.run_with_nop(vec![record]) {
            s.send(fault_data_vec[0]).unwrap();
        }
        drop(simulation);
        bar.inc(1);
    });

    bar.finish_and_clear();
    println!("-> {} attacks executed", n);

    let res: Vec<_> = receiver.iter().collect();
    let count = res.len();
    print(cs, Some(res));
    count
}

fn cached_bit_flip_simulation(
    file_data: &ElfFile,
    records: Vec<ExternalRecord>,
    cs: &Disassembly,
) -> usize {
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
            let mut simulation = Simulation::new(&file_data);
            if let Some(fault_data_vec) = simulation.run_with_bit_flip(vec![record], bit_pos) {
                s.send(fault_data_vec[0]).unwrap();
            }
            drop(simulation);
        }
        bar.inc(1);
    });
    bar.finish_and_clear();
    println!("-> {} attacks executed", n);

    let res: Vec<_> = receiver.iter().collect();
    let count = res.len();
    print(cs, Some(res));
    count
}

fn cached_nop_simulation_2(
    file_data: &ElfFile,
    records: Vec<ExternalRecord>,
    cs: &Disassembly,
) -> usize {
    // Print overview
    let mut count = 0;
    let mut n = 0;
    println!("Fault injection: 2 consecutive NOP (Cached)");
    let bar = ProgressBar::new(records.len() as u64);
    // Loop over all addresses from first round
    records.iter().for_each(|record| {
        // Get intermediate trace data from negative run with inserted nop -> new program flow
        let mut simulation = Simulation::new(&file_data);
        let intermediate_records = simulation.get_address_list(vec![*record]);
        drop(simulation);
        // Setup sender and receiver
        let (sender, receiver) = channel();
        n += intermediate_records.len();
        // Run full test with intemediate trace data
        intermediate_records
            .into_par_iter()
            .for_each_with(sender, |s, intermediate_record| {
                let mut intermediate_simulation = Simulation::new(&file_data);
                // Run test with specific intermediate record
                if let Some(fault_data_vec) =
                    intermediate_simulation.run_with_nop(vec![*record, intermediate_record])
                {
                    fault_data_vec
                        .iter()
                        .for_each(|fault_data| s.send(*fault_data).unwrap());
                };
                drop(intermediate_simulation);
            });

        let res: Vec<_> = receiver.iter().collect();
        count += res.len();
        print(cs, Some(res));
        bar.inc(1);
    });
    bar.finish();
    println!("-> {} attacks executed", n);
    count
}

fn print(cs: &Disassembly, ret_data: Option<Vec<FaultData>>) -> usize {
    match ret_data {
        Some(data) => {
            data.iter().for_each(|fault_data| {
                println!(
                    "0x{:X}:  {} -> {}",
                    fault_data.address,
                    cs.bin2asm(&fault_data.data, fault_data.address),
                    cs.bin2asm(&fault_data.data_changed, fault_data.address)
                );
            });
            println!("");
            1
        }
        _ => 0,
    }
}
