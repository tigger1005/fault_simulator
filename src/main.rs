use clap::Parser;

use fault_simulator::config::{Args, Config};
use fault_simulator::error::SimulatorError;
use fault_simulator::prelude::*;

mod attack;
mod compile;
mod report;

use git_version::git_version;
const GIT_VERSION: &str = git_version!();

// Fault Injection Simulator for ARM Cortex-M Processors
//
// This is the main entry point for the fault injection simulator targeting
// ARMv8-M processors (e.g., Cortex-M33). The simulator provides comprehensive
// fault injection capabilities for security research and vulnerability assessment.
//
// Key Features:
// * Multi-threaded Execution: Parallel fault injection for performance
// * Multiple Attack Types: Glitch, register corruption, instruction modification
// * Configurable Campaigns: JSON configuration and command-line control
// * Debug Integration: Source-level fault correlation and analysis
// * Comprehensive Reporting: Detailed attack success analysis
//
// Supported Fault Types:
// * Glitch Attacks: Clock/voltage glitching causing instruction skipping
// * Register Bit Flips: Single-bit errors in processor registers
// * Register Flooding: Complete register corruption attacks
// * Command Bit Flips: Instruction stream corruption
//
// Attack Classes:
// * all - Test all available fault types systematically
// * single - Single fault injection per execution
// * double - Two-fault combination attacks
// * Specific types: glitch, regbf, regfld, cmdbf
//
// Configuration Options:
// The simulator accepts both command-line arguments and JSON configuration
// files, with command-line parameters taking precedence for flexible usage
// in automated testing environments.

/// Main entry point for the fault injection simulator.
///
/// Orchestrates the complete fault injection simulation workflow including:
/// * Configuration loading and validation
/// * Target program compilation (if needed)
/// * ELF file loading and analysis
/// * Multi-threaded simulation setup
/// * Fault injection campaign execution
/// * Results analysis and reporting
///
/// # Configuration Hierarchy
///
/// 1. **Default values**: Sensible defaults for all parameters
/// 2. **JSON configuration**: Structured configuration from file
/// 3. **Command-line overrides**: CLI arguments override file settings
///
/// # Error Handling
///
/// Returns descriptive error messages for:
/// * Configuration parsing failures
/// * ELF file loading errors
/// * Thread initialization problems
/// * Simulation execution failures
///
/// # Performance Considerations
///
/// * Automatically determines optimal thread count
/// * Balances fault attack threads with general simulation threads
/// * Provides progress reporting for long-running campaigns
///
/// # Returns
///
/// * `Ok(())` - Simulation completed successfully
/// * `Err(String)` - Detailed error message describing the failure
fn main() -> Result<(), SimulatorError> {
    // Get parameter from command line
    let args = Args::parse();

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

    // Initialize logger with level from config (or use RUST_LOG env var if set)
    if std::env::var("RUST_LOG").is_err() {
        let log_level = match config.log_level.as_str() {
            "off" => "off",
            "error" => "error",
            "warn" => "warn",
            "info" => "info",
            "debug" => "debug",
            "trace" => "trace",
            _ => "off", // default
        };
        std::env::set_var("RUST_LOG", log_level);
    }
    env_logger::init();

    // Check for compilation flag and provided elf file
    let path = match &config.elf {
        None => {
            // Compilation according cli parameter
            if !config.no_compilation {
                compile::compile();
            }
            std::path::PathBuf::from("content/bin/aarch32/victim.elf")
        }
        Some(elf_path) => {
            println!("Provided elf file: {}\n", elf_path.display());
            elf_path.clone()
        }
    };

    // Log initial register context if provided
    if !config.initial_registers.is_empty() {
        log::info!("Using custom initial register context:");
        for (reg, value) in &config.initial_registers {
            log::info!("  {:?}: 0x{:08X}", reg, value);
        }
    }

    // Log code patches if provided
    if !config.code_patches.is_empty() {
        log::info!("Code patches configured: {}", config.code_patches.len());
    }

    // Log memory regions if provided
    if !config.memory_regions.is_empty() {
        log::info!(
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

    // Run attack campaign (setup threads, validate, execute attacks, report)
    attack::run(config, &file_data)?;

    Ok(())
}
