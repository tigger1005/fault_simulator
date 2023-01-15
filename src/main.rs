//#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

mod disassembly;
use disassembly::Disassembly;

mod simulation;
use simulation::{ExternalRecord, FaultData, Simulation};

use std::thread;

use indicatif::{MultiProgress, ProgressBar};

use git_version::git_version;
use std::process::Command;
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
        handles.push(thread::spawn(move || {
            let mut simulation = Simulation::new(&fd);
            // Run test with specific address
            let result = simulation.run_with_nop(vec![record]);
            drop(simulation);
            result
        }));
        bar.inc(1);
    }
    bar.finish_and_clear();
    println!("-> {} attacks executed", n);

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
    let mut count = 0;
    external_records.iter().for_each(|rec| n += rec.size * 8);
    let bar = ProgressBar::new(n as u64);
    println!("Fault injection: Bit-Flip (Cached)");
    // Start all threads (all will execute with a single address)
    for record in external_records {
        let mut handles = Vec::new();
        for bit_pos in 0..(record.size * 8) {
            let fd = file_data.clone();
            handles.push(thread::spawn(move || {
                let mut simulation = Simulation::new(&fd);
                // Run test with specific address
                let result = simulation.run_with_bit_flip(vec![record], bit_pos);
                drop(simulation);
                result
            }));
            bar.inc(1);
        }
        // wait for each thread to finish
        for handle in handles {
            count += print(cs, handle.join().expect("Cannot fault result"));
        }
    }
    bar.finish_and_clear();
    println!("-> {} attacks executed", n);

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
    let progress = MultiProgress::new();
    progress.add(bar.clone());
    // Loop over all addresses from first round
    records.iter().for_each(|record| {
        // Get intermediate trace data from negative run with inserted nop -> new program flow
        let mut simulation = Simulation::new(&file_data);
        let intermediate_records = simulation.get_address_list(vec![*record]);
        drop(simulation);
        let intermediate_bar = ProgressBar::new(intermediate_records.len() as u64);
        progress.add(intermediate_bar.clone());
        // Run full test with intemediate trace data
        let mut handles = Vec::new();
        intermediate_records.iter().for_each(|intermediate_record| {
            let temp_record = *record;
            let temp_intermediate_record = *intermediate_record;
            let fd = file_data.clone();
            handles.push(thread::spawn(move || {
                let mut intermediate_simulation = Simulation::new(&fd);
                // Run test with specific intermediate record
                let result = intermediate_simulation
                    .run_with_nop(vec![temp_record, temp_intermediate_record]);
                drop(intermediate_simulation);
                result
            }));
            intermediate_bar.inc(1);
            n += 1;
        });
        intermediate_bar.finish();
        progress.remove(&intermediate_bar);
        bar.inc(1);
        // wait for each intermediate thread to finish
        for handle in handles {
            let result = handle.join().expect("Cannot fault result");
            if result.is_some() {
                bar.suspend(|| count += print(cs, result));
            }
        }
    });
    bar.finish_and_clear();
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
