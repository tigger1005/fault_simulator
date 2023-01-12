#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

mod disassembly;
use disassembly::Disassembly;

mod simulation;
use simulation::{FaultData, Simulation};

use std::thread;

fn main() {
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    // Load elf file
    let file_data: ElfFile = ElfFile::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));
    let cs: Disassembly = Disassembly::new();
    // Run cached nop simulation
    if cached_nop_simulation(&file_data, &cs) != 0 {
        cached_nop_simulation_2(&file_data, &cs);
    }
}

fn cached_nop_simulation(file_data: &ElfFile, cs: &Disassembly) -> usize {
    // Load and parse elf file
    let mut simulation = Simulation::new(&file_data);
    // Setup simulation
    simulation.setup();

    // Get trace data from negative run
    let external_records = simulation.get_address_list();
    drop(simulation);

    // # NOP run
    // - Loop from Count 0..Steps
    //     - Prepare system
    //     - Set state to negative run
    //     - Set NOP at specific address
    //     - Run till Success/Failed state
    //         If Success add to found list
    // - Repeat till end of loop

    // Test loop over all addresses (steps)
    let mut handles = Vec::new();

    // Start all threads (all will execute with a single address)
    for record in external_records {
        let fd = file_data.clone();
        let handle = thread::spawn(move || {
            let mut simulation = Simulation::new(&fd);
            // Setup
            simulation.setup();
            // Run test with specific address
            let result = simulation.run_with_nop(vec![record]);
            drop(simulation);
            result
        });
        handles.push(handle);
    }

    println!("Fault injection: NOP (Cached)");
    let mut count = 0;
    // wait for each thread to finish
    for handle in handles {
        count += print(cs, handle.join().expect("Cannot fault result"));
    }
    count
}

fn cached_nop_simulation_2(file_data: &ElfFile, cs: &Disassembly) -> usize {
    // Load and parse elf file
    let mut simulation = Simulation::new(&file_data);
    // Setup simulation
    simulation.setup();

    // Get trace data from negative run
    let external_records = simulation.get_address_list();
    drop(simulation);

    // # NOP run
    // - Loop from Count 0..Steps
    //     - Prepare system
    //     - Set state to negative run
    //     - Set NOP at specific address
    //     - Run till Success/Failed state
    //         If Success add to found list
    // - Repeat till end of loop

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
                    // Setup
                    simulation.setup();
                    // Run test with specific address
                    let result = simulation.run_with_nop(vec![temp_rec_1, temp_rec_2]);
                    drop(simulation);
                    result
                });
                handles.push(handle);
            });
        });

    println!("Fault injection: 2 consecutive NOP (Cached)");
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
            println!("Success with:");
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

/*
# Glitch run
- Loop from Count 0..Steps
    - Loop (16/32) according to cmd size
        - Prepare system
        - Set state to negative run
        - Run (Count)
            Check for ASM Cmd - 16/32 Bit
            Change (xor) bit in cmd
        - Run (1/2)
            Change back
        - Run till Success/Failed state
            If Success add to found list
- Repeat till end of loop

*/
