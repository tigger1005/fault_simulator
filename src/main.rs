use clap::Parser;
use std::io::stdout;
use std::io::{self, Write};
use std::path::PathBuf;

use fault_simulator::prelude::*;

mod compile;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

/// Parse hex address strings to u64 values
fn parse_hex(s: &str) -> Result<u64, String> {
    let cleaned = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(cleaned, 16)
        .map_err(|e| format!("'{}' is not a valid hex number: {}", s, e))
}

/// Command line parameter structure for configuring the fault injection simulator.
///
/// # Fields
///
/// * `threads` - Number of threads started in parallel.
/// * `no_compilation` - Suppress re-compilation of the target program.
/// * `class` - Specifies the attack class to execute. Options include `all`, `single`, `double`, and optional subtypes like `glitch`, `regbf`, `regfld`, `cmdbf`.
/// * `faults` - Defines a sequence of faults to simulate, e.g., `regbf_r1_0100` or `glitch_1`.
/// * `analysis` - Activates trace analysis of the selected fault.
/// * `deep_analysis` - Enables a deep scan of repeated code (e.g., loops).
/// * `max_instructions` - Maximum number of instructions to execute.
/// * `elf` - Path to the ELF file to load without compilation.
/// * `trace` - Enables tracing of failure runs without fault injection.
/// * `no_check` - Disables program flow checks.
/// * `run_through` - Continues simulation without stopping at the first successful fault injection.
/// * `success_addresses` - List of memory addresses that indicate success when accessed.
/// * `failure_addresses` - List of memory addresses that indicate failure when accessed.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of threads started in parallel
    #[arg(short, long, default_value_t = 15)]
    threads: usize,

    /// Suppress re-compilation of target program
    #[arg(short, long, default_value_t = false)]
    no_compilation: bool,

    /// Attacks class to be executed:
    ///   --class [all, single, double] [optional: glitch, regbf, regfld, cmdbf]
    ///     E.g.: --class single glitch
    #[arg(long,  value_delimiter = ' ', num_args = 1.., verbatim_doc_comment)]
    class: Vec<String>,

    /// Run a command line defined sequence of faults.
    ///   --faults [specific_attack] [optional: specific_attack2 specific_attack3 ...]
    ///     E.g.: --faults regbf_r1_0100 glitch_1
    #[arg(long, value_delimiter = ' ', num_args = 1.., verbatim_doc_comment)]
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

    /// Disable program flow check
    #[arg(long, default_value_t = false)]
    no_check: bool,

    /// Don't stop on first successful fault injection
    #[arg(short, long, default_value_t = false)]
    run_through: bool,

    /// List of memory addresses that indicate success when accessed
    /// Format: --success-addresses 0x8000123 0x8000456
    #[arg(long, value_parser = parse_hex, num_args = 0..)]
    success_addresses: Vec<u64>,

    /// List of memory addresses that indicate failure when accessed
    /// Format: --failure-addresses 0x8000789 0x8000abc
    #[arg(long, value_parser = parse_hex, num_args = 0..)]
    failure_addresses: Vec<u64>,
}

/// Program to simulate fault injections on ARMv8-M processors (e.g. M33)
///
fn main() -> Result<(), String> {
    // Get parameter from command line
    let args = Args::parse();
    // Set parameter from cli
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
    let mut attack_sim = FaultAttacks::new(
        path,
        args.max_instructions,
        args.deep_analysis,
        args.run_through,
        args.threads,
        args.success_addresses,
        args.failure_addresses,
    )?;

    // Check for correct program behavior
    if !args.no_check {
        println!("Check for correct program behavior:");
        attack_sim.check_for_correct_behavior()?;
    }

    // Check if trace is selected
    if args.trace {
        attack_sim.print_trace()?;
        return Ok(());
    }

    println!("\nRun fault simulations:");

    // Run attack simulation
    if args.faults.is_empty() {
        let mut class = args.class.iter();
        match class.next().as_ref().map(|s| s.as_str()) {
            Some("all") | None => {
                if !attack_sim.single(&mut class)?.0 {
                    attack_sim.double(&mut class)?;
                }
            }
            Some("single") => {
                attack_sim.single(&mut class)?;
            }
            Some("double") => {
                attack_sim.double(&mut class)?;
            }
            _ => println!("Unknown attack class!"),
        }
    } else {
        // Get fault type and numbers
        let faults: Vec<FaultType> = args
            .faults
            .iter()
            .filter_map(|argument| get_fault_from(argument).ok())
            .collect();

        let result = attack_sim.fault_simulation(&faults)?;
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
                print!("\nList trace for attack number : (Return for exit): ");
                stdout().flush().unwrap();
                let mut buffer = String::new();
                if io::stdin().read_line(&mut buffer).is_ok() {
                    if let Ok(number) = buffer.trim().parse::<isize>() {
                        attack_sim.print_trace_for_fault(number)?;
                        continue;
                    }
                }
                break;
            }
        }
    }
    Ok(())
}
