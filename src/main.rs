//#![allow(dead_code)]
use clap::Parser;

mod fault_attacks;
use fault_attacks::FaultAttacks;

use std::env;

mod compile;

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

    /// Attacks to be executed. Possible values are: all, single, double, bit_flip
    #[arg(long, default_value_t = String::from("all"))]
    attack: String,
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

    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));
    println!("Check for correct program behavior:");
    // Check for correct program behavior
    attack.check_for_correct_behavior();

    println!("\nRun fault simulations:");

    // Run attack simulation
    match args.attack.as_str() {
        "all" => {
            if !attack.single_glitch(1..=10).0 {
                attack.double_glitch(1..=10);
            }
            attack.single_bit_flip();
        }
        "single" => {
            attack.single_glitch(1..=10);
        }
        "double" => {
            attack.double_glitch(1..=10);
        }
        "bit_flip" => {
            attack.single_bit_flip();
        }
        _ => println!("No attack selected!"),
    }

    ////////////////////////////////
    println!("Overall tests executed {}", attack.count_sum);
}
