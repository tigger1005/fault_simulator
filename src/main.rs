use clap::Parser;
use std::io::stdout;
use std::io::{self, Write};

use fault_simulator::prelude::*;

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

    /// Run a command line defined sequence of faults. Alternative to --attack
    #[arg(long, value_delimiter = ',')]
    faults: Vec<FaultType>,

    /// Activate trace analysis of picked fault
    #[arg(short, long, default_value_t = false)]
    analysis: bool,

    /// Switch on low complexity attack-scan (same addresses are discarded)
    #[arg(short, long, default_value_t = false)]
    low_complexity: bool,
}

fn main() -> Result<(), String> {
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
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("content/bin/aarch32/bl1.elf"));
    println!("Check for correct program behavior:");
    // Check for correct program behavior
    attack.check_for_correct_behavior()?;

    println!("\nRun fault simulations:");

    // Run attack simulation
    if args.faults.is_empty() {
        match args.attack.as_str() {
            "all" => {
                if !attack.single_glitch(args.low_complexity, 1..=10)?.0 {
                    attack.double_glitch(args.low_complexity, 1..=10)?;
                }
                //            attack.single_bit_flip();
            }
            "single" => {
                attack.single_glitch(args.low_complexity, 1..=10)?;
            }
            "double" => {
                attack.double_glitch(args.low_complexity, 1..=10)?;
            }
            // "bit_flip" => {
            //     attack.single_bit_flip();
            // }
            _ => println!("No attack selected!"),
        }
    } else {
        attack.fault_simulation(&args.faults, args.low_complexity)?;
    }

    let debug_context = attack.file_data.get_debug_context();
    attack.print_fault_data(&debug_context);

    println!("Overall tests executed {}", attack.count_sum);

    if args.analysis {
        loop {
            {
                print!("\nList trace for attack number : (Return for no list): ");
                stdout().flush().unwrap();
                let mut buffer = String::new();
                if io::stdin().read_line(&mut buffer).is_ok() {
                    if let Ok(number) = buffer.trim().parse::<usize>() {
                        attack.print_trace_for_fault(number - 1)?;
                        continue;
                    }
                }
                break;
            }
        }
    }
    Ok(())
}
