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

use itertools::Itertools;

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

    let mut success = false;
    let mut count_sum = 0;
    // Run cached nop simulation
    for i in 1..=10 {
        let (nop_1, count) =
            fault_attacks::cached_nop_simulation_x_y(&file_data, &external_records, i, 0);
        count_sum += count;
        if cs.print_fault_records(nop_1) != 0 {
            success = true;
            break;
        }
    }
    if success == false {
        // Run cached double nop simulation
        let it = (1..=10).combinations_with_replacement(2);
        for t in it.into_iter() {
            let (nop, count) =
                fault_attacks::cached_nop_simulation_x_y(&file_data, &external_records, t[0], t[1]);
            count_sum += count;
            if cs.print_fault_records(nop) != 0 {
                break;
            }
        }
    }
    // Run cached bit-flip simulation
    let (flip, sum) = fault_attacks::cached_bit_flip_simulation(&file_data, &external_records);
    count_sum += sum;
    cs.print_fault_records(flip);

    ////////////////////////////////
    println!("Overall tests executed {count_sum}");
}
