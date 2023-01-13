#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

mod disassembly;
use disassembly::Disassembly;

mod simulation;
use simulation::{ExternalRecord, FaultData, Simulation};

use std::thread;

use indicatif::ProgressBar;

use std::process::Command;

fn main() {
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run
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
    let external_records = simulation.get_address_list();

    // Run cached nop simulation
    if cached_nop_simulation(&file_data, external_records.clone(), &cs) == 0 {
        // Run cached double nop simulation
        cached_nop_simulation_2(&file_data, external_records.clone(), &cs);
    }
    // Run cached bit-flip simulation
    cached_bit_flip_simulation(&file_data, external_records.clone(), &cs);
}

fn cached_nop_simulation(
    file_data: &ElfFile,
    external_records: Vec<ExternalRecord>,
    cs: &Disassembly,
) -> usize {
    // Print overview
    let n = external_records.len();
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: NOP (Cached)");
    // Test loop over all addresses (steps)
    let mut handles = Vec::new();
    // Start all threads (all will execute with a single address)
    for record in external_records {
        let fd = file_data.clone();
        let handle = thread::spawn(move || {
            let mut simulation = Simulation::new(&fd);
            // Run test with specific address
            let result = simulation.run_with_nop(vec![record]);
            drop(simulation);
            result
        });
        bar.inc(1);
        handles.push(handle);
    }
    bar.finish();

    let mut count = 0;
    // wait for each thread to finish
    for handle in handles {
        count += print(cs, handle.join().expect("Cannot fault result"));
    }
    count
}

fn cached_bit_flip_simulation(
    file_data: &ElfFile,
    external_records: Vec<ExternalRecord>,
    cs: &Disassembly,
) -> usize {
    // Print overview
    let mut n = 0;
    external_records.iter().for_each(|rec| n += rec.size * 8);
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: Bit-Flip (Cached)");
    // Test loop over all addresses (steps)
    let mut handles = Vec::new();
    // Start all threads (all will execute with a single address)
    for record in external_records {
        for bit_pos in 0..(record.size * 8) {
            let fd = file_data.clone();
            let handle = thread::spawn(move || {
                let mut simulation = Simulation::new(&fd);
                // Run test with specific address
                let result = simulation.run_with_bit_flip(vec![record], bit_pos);
                drop(simulation);
                result
            });
            bar.inc(1);
            handles.push(handle);
        }
    }
    bar.finish();

    let mut count = 0;
    // wait for each thread to finish
    for handle in handles {
        count += print(cs, handle.join().expect("Cannot fault result"));
    }
    count
}

fn cached_nop_simulation_2(
    file_data: &ElfFile,
    external_records: Vec<ExternalRecord>,
    cs: &Disassembly,
) -> usize {
    // Print overview
    let n = ((external_records.len() - 1) / 2) * external_records.len();
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: 2 consecutive NOP (Cached)");
    // Test loop over all addresses (steps)
    let mut handles = Vec::new();
    // Start all threads (all will execute with a single address)
    external_records
        .iter()
        .enumerate()
        .for_each(|(i, record_1)| {
            external_records[(i + 1)..].iter().for_each(|record_2| {
                let temp_rec_1 = *record_1;
                let temp_rec_2 = *record_2;
                let fd = file_data.clone();
                let handle = thread::spawn(move || {
                    let mut simulation = Simulation::new(&fd);
                    // Run test with specific address
                    let result = simulation.run_with_nop(vec![temp_rec_1, temp_rec_2]);
                    drop(simulation);
                    result
                });
                bar.inc(1);
                handles.push(handle);
            });
        });
    bar.finish();

    let mut count = 0;
    // wait for each thread to finish
    for handle in handles {
        count += print(cs, handle.join().expect("Cannot fault result"));
    }
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
            1
        }
        _ => 0,
    }
}
