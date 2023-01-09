#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

mod disassembly;
use disassembly::Disassembly;
//use log::debug;

mod simulation;
use simulation::Simulation;

fn main() {
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    // Load elf file
    let file_data: ElfFile = ElfFile::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));
    let cs: Disassembly = Disassembly::new();
    // Run cached nop simulation
    cached_nop_simulation(&file_data, &cs);
}

fn cached_nop_simulation(file_data: &ElfFile, cs: &Disassembly) -> () {
    // Load and parse elf file
    let mut simulation = Simulation::new(file_data);
    // Setup simulation
    simulation.setup();

    // Get trace data from negative run
    let address_list = simulation.get_address_list();
    drop(simulation);

    // # NOP run
    // - Loop from Count 0..Steps
    //     - Prepare system
    //     - Set state to negative run
    //         Change to NOP
    //     - Run till Success/Failed state
    //         If Success add to found list
    // - Repeat till end of loop

    // Test loop over all addresses (steps)
    for address in address_list {
        let mut simulation = Simulation::new(file_data);
        // Setup simulation
        simulation.setup();
        // Run test with specific address
        if let Some(fault_data) = simulation.run_with_nop(address) {
            println!(
                "Successfull: {} -> NOP",
                cs.bin2asm(&fault_data.data, fault_data.address)
            );
        };
        drop(simulation);
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
