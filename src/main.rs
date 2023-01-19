//#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

mod disassembly;
use disassembly::Disassembly;

mod fault_attacks;

mod simulation;
use simulation::Simulation;

use std::env;
use std::process::Command;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

fn main() {
    env::set_var("RAYON_NUM_THREADS", "40");

    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run
    println!("--- Fault injection simulator: {GIT_VERSION} ---\n");
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
    println!("Check for correct program behavior:");
    // Get disassembly
    let cs = Disassembly::new();
    // Check for correct program behavior
    let mut simulation = Simulation::new(&file_data);
    simulation.check_program();

    println!("\nRun fault simulations:");
    // Get trace data from negative run
    let mut simulation = Simulation::new(&file_data);
    let external_records = simulation.record_code_trace(vec![]);

    // Run cached nop simulation
    let nop_1 = fault_attacks::cached_nop_simulation(&file_data, &external_records);
    let entries = nop_1.len();
    cs.print_fault_records(nop_1);
    if entries == 0 {
        // Run cached double nop simulation
        let nop_2 = fault_attacks::cached_nop_simulation_2(&file_data, &external_records);
        cs.print_fault_records(nop_2);
    }
    // Run cached bit-flip simulation
    let flip = fault_attacks::cached_bit_flip_simulation(&file_data, &external_records);
    cs.print_fault_records(flip);
}
