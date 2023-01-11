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
    cached_nop_simulation(&file_data, &cs);
    cached_nop_simulation_2(&file_data, &cs);
}

fn cached_nop_simulation(file_data: &ElfFile, cs: &Disassembly) -> () {
    // Load and parse elf file
    let mut simulation = Simulation::new(&file_data);
    // Setup simulation
    simulation.setup();

    // Get trace data from negative run
    let address_list = simulation.get_address_list();
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
    for address in address_list {
        let fd = file_data.clone();
        let handle = thread::spawn(move || {
            let mut simulation = Simulation::new(&fd);
            // Setup
            simulation.setup();
            // Run test with specific address
            let result = simulation.run_with_nop(address);
            drop(simulation);
            result
        });
        handles.push(handle);
    }

    println!("Fault injection: NOP (Cached)");
    // wait for each thread to finish
    for handle in handles {
        print(cs, handle.join().expect("Cannot fault result"));
    }
}

fn cached_nop_simulation_2(file_data: &ElfFile, cs: &Disassembly) -> () {
    // Load and parse elf file
    let mut simulation = Simulation::new(&file_data);
    // Setup simulation
    simulation.setup();

    // Get trace data from negative run
    let address_list = simulation.get_address_list();
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
    let array_len = address_list.len();

    // Start all threads (all will execute with a single address)
    for index in 0..array_len - 1 {
        for index_2 in (index + 1)..array_len {
            let address = address_list[index];
            let address_2 = address_list[index_2];
            let fd = file_data.clone();
            let handle = thread::spawn(move || {
                let mut simulation = Simulation::new(&fd);
                // Setup
                simulation.setup();
                // Run test with specific address
                let result = simulation.run_with_nop_2(address, address_2);
                drop(simulation);
                result
            });
            handles.push(handle);
        }
    }

    println!("Fault injection: 2 consecutive NOP (Cached)");
    // wait for each thread to finish
    for handle in handles {
        print(cs, handle.join().expect("Cannot fault result"));
    }
}

fn print(cs: &Disassembly, ret_data: Option<Vec<FaultData>>) {
    match ret_data {
        Some(data) => {
            println!("Success with:");
            data.iter().for_each(|fault_data| {
                println!(
                    "{} -> NOP",
                    cs.bin2asm(&fault_data.data, fault_data.address)
                )
            })
        }
        _ => {}
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
