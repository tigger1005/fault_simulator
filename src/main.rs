use clap::Parser;
use std::io::stdout;
use std::io::{self, Write};
use std::path::PathBuf;

use fault_simulator::prelude::*;

use std::env;

mod compile;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

/// Command line parameter structure
///
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of threads started in parallel
    #[arg(short, long, default_value_t = 1)]
    threads: u16,

    /// Suppress re-compilation of target program
    #[arg(short, long, default_value_t = false)]
    no_compilation: bool,

    /// Attacks class to be executed. Possible values are: all, single, double
    #[arg(long, default_value_t = String::from("all"))]
    class: String,

    /// Run a command line defined sequence of faults. Alternative to --attack
    #[arg(long, value_delimiter = ',')]
    faults: Vec<String>,

    /// Activate trace analysis of picked fault
    #[arg(short, long, default_value_t = false)]
    analysis: bool,

    /// Switch on deep analysis scan. Repeated code (e.g. loops) are fully analysed
    #[arg(short, long, default_value_t = false)]
    deep_analysis: bool,

    /// Maximum number of instructions to be executed
    #[arg(short, long, default_value_t = 2000)]
    max_instructions: usize,

    /// Load elf file w/o compilation step
    #[arg(short, long)]
    elf: Option<PathBuf>,

    /// Trace failure run w/o fault injection for analysis
    #[arg(long, default_value_t = false)]
    trace: bool,
}

/// Program to simulate fault injections on ARMv8-M processors (e.g. M33)
///
fn main() -> Result<(), String> {
    // Get parameter from command line
    let args = Args::parse();
    // Set parameter from cli
    env::set_var("RAYON_NUM_THREADS", args.threads.to_string());
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    println!("--- Fault injection simulator: {GIT_VERSION} ---\n");

    // Check for compilation flag and provided elf file
    let path = match args.elf.is_some() {
        false => {
            // Compilation according cli parameter
            if !args.no_compilation {
                compile::compile();
            }
            std::path::PathBuf::from("content/bin/aarch32/victim.elf")
        }
        true => {
            println!(
                "Provided elf file: {}\n",
                &args.elf.as_ref().unwrap().display()
            );
            args.elf.unwrap()
        }
    };

    // Load victim data for attack simulation
    let mut attack_sim = FaultAttacks::new(path)?;

    println!("Check for correct program behavior:");
    // Check for correct program behavior
    attack_sim.check_for_correct_behavior(args.max_instructions)?;

    // Check if trace is selected
    if args.trace {
        attack_sim.print_trace(args.max_instructions)?;
        return Ok(());
    }

    println!("\nRun fault simulations:");

    // Run attack simulation
    if args.faults.is_empty() {
        let class: Vec<&str> = args.class.splitn(2, ',').collect();
        match class[0] {
            "all" => {
                if !attack_sim
                    .single(
                        args.max_instructions,
                        args.deep_analysis,
                        true,
                        class.get(1),
                    )?
                    .0
                {
                    attack_sim.double(
                        args.max_instructions,
                        args.deep_analysis,
                        true,
                        class.get(1),
                    )?;
                }
            }
            "single" => {
                attack_sim.single(
                    args.max_instructions,
                    args.deep_analysis,
                    true,
                    class.get(1),
                )?;
            }
            "double" => {
                attack_sim.double(
                    args.max_instructions,
                    args.deep_analysis,
                    true,
                    class.get(1),
                )?;
            }
            _ => println!("No attack type selected!"),
        }
    } else {
        // Get fault type and numbers
        let faults: Vec<FaultType> = args
            .faults
            .iter()
            .filter_map(|argument| get_fault_from(argument).ok())
            .collect();

        let result = attack_sim.fault_simulation(
            args.max_instructions,
            &faults,
            args.deep_analysis,
            true,
        )?;
        // Save result to attack struct
        attack_sim.set_fault_data(result);
    }

    // Pretty print fault data
    attack_sim.print_fault_data();

    println!("Overall tests executed {}", attack_sim.count_sum);

    if args.analysis {
        loop {
            {
                if attack_sim.fault_data.is_empty() {
                    println!("No successful attacks!");
                    break;
                }
                print!("\nList trace for attack number : (Return for no list): ");
                stdout().flush().unwrap();
                let mut buffer = String::new();
                if io::stdin().read_line(&mut buffer).is_ok() {
                    if let Ok(number) = buffer.trim().parse::<usize>() {
                        attack_sim.print_trace_for_fault(args.max_instructions, number - 1)?;
                        continue;
                    }
                }
                break;
            }
        }
    }
    Ok(())
}
