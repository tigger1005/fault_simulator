use clap::Parser;
use serde::{Deserialize, Deserializer, Serialize};
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

/// Custom deserializer for hex addresses that can handle both strings and numbers
// Wasn't able to find any other crate that could do Vec<u64>.
fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct HexAddressesVisitor;

    impl<'de> Visitor<'de> for HexAddressesVisitor {
        type Value = Vec<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of hex addresses (strings like \"0x123\" or numbers)")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<u64>, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut addresses = Vec::new();
            
            while let Some(value) = seq.next_element::<serde_json::Value>()? {
                match value {
                    serde_json::Value::String(s) => {
                        let addr = parse_hex(&s).map_err(de::Error::custom)?;
                        addresses.push(addr);
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(addr) = n.as_u64() {
                            addresses.push(addr);
                        } else {
                            return Err(de::Error::custom("Invalid number for address"));
                        }
                    }
                    _ => return Err(de::Error::custom("Address must be a string or number")),
                }
            }
            
            Ok(addresses)
        }
    }

    deserializer.deserialize_seq(HexAddressesVisitor)
}

/// Configuration structure that can be loaded from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    #[serde(default = "Config::default_threads")]
    threads: usize,
    #[serde(default)]
    no_compilation: bool,
    #[serde(default)]
    class: Vec<String>,
    #[serde(default)]
    faults: Vec<String>,
    #[serde(default)]
    analysis: bool,
    #[serde(default)]
    deep_analysis: bool,
    #[serde(default = "Config::default_max_instructions")]
    max_instructions: usize,
    #[serde(default)]
    elf: Option<PathBuf>,
    #[serde(default)]
    trace: bool,
    #[serde(default)]
    no_check: bool,
    #[serde(default)]
    run_through: bool,
    #[serde(default, deserialize_with = "deserialize_hex")]
    success_addresses: Vec<u64>,
    #[serde(default, deserialize_with = "deserialize_hex")]
    failure_addresses: Vec<u64>,
}

impl Config {
    // Keep defaults in sync with CLI defaults
    fn default_threads() -> usize { 15 }
    fn default_max_instructions() -> usize { 2000 }

    /// Load configuration from JSON file
    fn from_file(path: &PathBuf) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;
        
        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON config: {}", e))
    }

    /// Create config from CLI args (for when no JSON file is provided)
    fn from_args(args: &Args) -> Self {
        Self {
            threads: args.threads,
            no_compilation: args.no_compilation,
            class: args.class.clone(),
            faults: args.faults.clone(),
            analysis: args.analysis,
            deep_analysis: args.deep_analysis,
            max_instructions: args.max_instructions,
            elf: args.elf.clone(),
            trace: args.trace,
            no_check: args.no_check,
            run_through: args.run_through,
            success_addresses: args.success_addresses.clone(),
            failure_addresses: args.failure_addresses.clone(),
        }
    }

    /// Override config values with CLI args (CLI takes precedence)
    fn override_with_args(&mut self, args: &Args) {
        // Always apply CLI values since they include defaults
        self.threads = args.threads;
        self.no_compilation = args.no_compilation;
        if !args.class.is_empty() {
            self.class = args.class.clone();
        }
        if !args.faults.is_empty() {
            self.faults = args.faults.clone();
        }
        self.analysis = args.analysis;
        self.deep_analysis = args.deep_analysis;
        self.max_instructions = args.max_instructions;
        if args.elf.is_some() {
            self.elf = args.elf.clone();
        }
        self.trace = args.trace;
        self.no_check = args.no_check;
        self.run_through = args.run_through;
        if !args.success_addresses.is_empty() {
            self.success_addresses = args.success_addresses.clone();
        }
        if !args.failure_addresses.is_empty() {
            self.failure_addresses = args.failure_addresses.clone();
        }
    }
}

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
/// * `failure_addresses` - List of memory addresses that indicate failure when accessed.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Load configuration from JSON file
    #[arg(short = 'c', long)]
    config: Option<PathBuf>,

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

    // Load victim data for attack simulation
    let mut attack_sim = FaultAttacks::new(
        path,
        config.max_instructions,
        config.deep_analysis,
        config.run_through,
        config.threads,
        config.success_addresses,
        config.failure_addresses,
    )?;

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
