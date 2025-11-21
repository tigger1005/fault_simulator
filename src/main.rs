use clap::Parser;
use std::io::stdout;
use std::io::{self, Write};

use fault_simulator::config::{Args, Config};
use fault_simulator::prelude::*;

mod compile;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

/// Command line parameter structure for configuring the fault injection simulator.
///
/// # Fields
///
/// * `config` - Load configuration from JSON file.
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
///
/// Program to simulate fault injections on ARMv8-M processors (e.g. M33)
///
fn main() -> Result<(), String> {
    // Get parameter from command line
    let args = Args::parse();
    // Set parameter from cli
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    println!("--- Fault injection simulator: {GIT_VERSION} ---\n");

    // Load configuration
    let config = match &args.config {
        Some(config_path) => {
            println!("Loading configuration from: {}", config_path.display());
            let mut config = Config::from_file(config_path)?;
            config.override_with_args(&args);
            config
        }
        None => Config::from_args(&args),
    };

    // Check for compilation flag and provided elf file
    let path = match config.elf.is_some() {
        false => {
            // Compilation according cli parameter
            if !config.no_compilation {
                compile::compile();
            }
            std::path::PathBuf::from("content/bin/aarch32/victim.elf")
        }
        true => {
            println!(
                "Provided elf file: {}\n",
                &config.elf.as_ref().unwrap().display()
            );
            config.elf.unwrap()
        }
    };

    // Print initial register context if provided
    if !config.initial_registers.is_empty() {
        println!("Using custom initial register context:");
        for (reg, value) in &config.initial_registers {
            println!("  {:?}: 0x{:08X}", reg, value);
        }
        println!();
    }

    // Print code patches if provided
    if !config.code_patches.is_empty() {
        println!("Code patches configured: {}", config.code_patches.len());
    }

    // Print memory regions if provided
    if !config.memory_regions.is_empty() {
        println!(
            "Custom memory regions configured: {}",
            config.memory_regions.len()
        );
    }

    // Load victim data
    let mut file_data: ElfFile = ElfFile::new(path)?;

    // Apply patches immediately after loading
    if !config.code_patches.is_empty() {
        file_data.apply_patches(&config.code_patches)?;
    }
    // Create simulation configuration
    let sim_config = SimulationConfig::new(
        config.max_instructions,
        config.deep_analysis,
        config.run_through,
        config.success_addresses,
        config.failure_addresses,
        config.initial_registers,
        config.memory_regions,
        config.print_unicorn_errors,
    );
    // Create user thread for simulation
    let mut user_thread = SimulationThread::new(sim_config)?;
    // Start worker threads
    user_thread.start_worker_threads(&file_data, config.threads)?;

    // Load victim data for attack simulation
    let mut attack_sim = FaultAttacks::new(&file_data, &user_thread)?;

    // Check for correct program behavior
    if !config.no_check {
        println!("Check for correct program behavior:");
        attack_sim.check_for_correct_behavior()?;
    }

    // Check if trace is selected
    if config.trace {
        attack_sim.print_trace()?;
        return Ok(());
    }

    println!("\nRun fault simulations:");

    // Run attack simulation
    if config.faults.is_empty() {
        let mut class = config.class.iter();
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
        let faults: Vec<FaultType> = config
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

    if config.analysis {
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
