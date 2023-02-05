//#![allow(dead_code)]
mod elf_file;
use elf_file::ElfFile;

use clap::Parser;

mod disassembly;
use disassembly::Disassembly;

mod fault_attacks;

mod simulation;

use simulation::Simulation;
use std::env;

mod compile;
use itertools::Itertools;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

/// Program to simulate fault injections on ARMv8-M processors (e.g. M33)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of threads started in parallel
    #[arg(short, long, default_value_t = 1)]
    threads: u16,

    /// Suppress re-compilation of target program
    #[arg(short, long, default_value_t = false)]
    no_compilation: bool,
}

fn main() {
    // Get parameter from command line
    let args = Args::parse();
    // Set parameter from cli
    env::set_var("RAYON_NUM_THREADS", args.threads.to_string());
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    println!("--- Fault injection simulator: {GIT_VERSION} ---\n");

    // Compilation according cli parameter
    if !args.no_compilation {
        compile::compile();
    }

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
    if !success {
        // Run cached double nop simulation
        let it = (1..=10).combinations_with_replacement(2);
        for t in it {
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
