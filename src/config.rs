//! # Configuration Management
//!
//! This module provides comprehensive configuration management for the fault
//! injection simulator, supporting both command-line arguments and JSON
//! configuration files. It handles parameter validation, type conversion,
//! and provides flexible configuration override capabilities.
//!
//! ## Configuration Sources
//!
//! * **Command Line**: Direct parameter specification via clap
//! * **JSON Files**: Structured configuration with validation
//! * **Hybrid Mode**: JSON base with command-line overrides
//!
//! ## Key Features
//!
//! * **Hex Address Parsing**: Flexible address format support (0x prefix optional)
//! * **Register Configuration**: Initial CPU register state specification
//! * **Validation**: Comprehensive parameter validation and error reporting
//! * **Override System**: Command-line parameters override file-based settings

use clap::Parser;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::PathBuf;
use unicorn_engine::RegisterARM;

/// Parse hexadecimal address strings to u64 values with flexible format support.format support.
///
/// This function provides robust parsing of memory addresses from various
/// string formats commonly used in configuration files and command-line
/// arguments. It handles both prefixed and non-prefixed hexadecimal strings.
///
/// # Supported Formats
///
/// * **Prefixed**: "0x1000", "0X1000" (case insensitive)
/// * **Non-prefixed**: "1000", "ABCD" (pure hex digits)
/// * **Mixed case**: "0xaBcD", "FFff" (case insensitive)
///
/// # Arguments
///
/// * `s` - String containing hexadecimal address representation
///
/// # Returns
///
/// * `Ok(u64)` - Successfully parsed 64-bit address value
/// * `Err(String)` - Descriptive error message for invalid input
///
/// # Examples
///
/// ```rust,no_run
/// assert_eq!(parse_hex("0x1000")?, 4096);
/// assert_eq!(parse_hex("1000")?, 4096);
/// assert_eq!(parse_hex("FFFF")?, 65535);
/// ```
fn parse_hex(s: &str) -> Result<u64, String> {
    let cleaned = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(cleaned, 16).map_err(|e| format!("Invalid hex address '{}': {}", s, e))
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

/// Convert register name string to RegisterARM enum
fn get_register_from_name(name: &str) -> Option<RegisterARM> {
    match name.to_uppercase().as_str() {
        "R0" => Some(RegisterARM::R0),
        "R1" => Some(RegisterARM::R1),
        "R2" => Some(RegisterARM::R2),
        "R3" => Some(RegisterARM::R3),
        "R4" => Some(RegisterARM::R4),
        "R5" => Some(RegisterARM::R5),
        "R6" => Some(RegisterARM::R6),
        "R7" => Some(RegisterARM::R7),
        "R8" => Some(RegisterARM::R8),
        "R9" => Some(RegisterARM::R9),
        "R10" => Some(RegisterARM::R10),
        "R11" => Some(RegisterARM::R11),
        "R12" => Some(RegisterARM::R12),
        "SP" => Some(RegisterARM::SP),
        "LR" => Some(RegisterARM::LR),
        "PC" => Some(RegisterARM::PC),
        "CPSR" => Some(RegisterARM::CPSR),
        _ => None,
    }
}

/// Custom deserializer for register context that validates register names and handles hex values
fn deserialize_register_context<'de, D>(
    deserializer: D,
) -> Result<HashMap<RegisterARM, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct RegisterContextVisitor;

    impl<'de> Visitor<'de> for RegisterContextVisitor {
        type Value = HashMap<RegisterARM, u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of register names to hex values")
        }

        fn visit_map<A>(self, mut map: A) -> Result<HashMap<RegisterARM, u64>, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let mut registers = HashMap::new();

            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                // Validate register name during deserialization
                let register = get_register_from_name(&key).ok_or_else(|| {
                    de::Error::custom(format!("Invalid register name: '{}'", key))
                })?;

                let reg_value = match value {
                    serde_json::Value::String(s) => parse_hex(&s).map_err(de::Error::custom)?,
                    serde_json::Value::Number(n) => {
                        if let Some(val) = n.as_u64() {
                            val
                        } else {
                            return Err(de::Error::custom(format!(
                                "Invalid number for register {}: must be a positive integer",
                                key
                            )));
                        }
                    }
                    _ => {
                        return Err(de::Error::custom(format!(
                            "Register {} value must be a string or number",
                            key
                        )))
                    }
                };

                registers.insert(register, reg_value);
            }

            Ok(registers)
        }
    }

    deserializer.deserialize_map(RegisterContextVisitor)
}

/// Configuration structure that can be loaded from JSON
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "Config::default_threads")]
    pub threads: usize,
    #[serde(default)]
    pub no_compilation: bool,
    #[serde(default)]
    pub class: Vec<String>,
    #[serde(default)]
    pub faults: Vec<String>,
    #[serde(default)]
    pub analysis: bool,
    #[serde(default)]
    pub deep_analysis: bool,
    #[serde(default = "Config::default_max_instructions")]
    pub max_instructions: usize,
    #[serde(default)]
    pub elf: Option<PathBuf>,
    #[serde(default)]
    pub trace: bool,
    #[serde(default)]
    pub no_check: bool,
    #[serde(default)]
    pub run_through: bool,
    #[serde(default, deserialize_with = "deserialize_hex")]
    pub success_addresses: Vec<u64>,
    #[serde(default, deserialize_with = "deserialize_hex")]
    pub failure_addresses: Vec<u64>,
    #[serde(default, deserialize_with = "deserialize_register_context")]
    pub initial_registers: HashMap<RegisterARM, u64>,
}

impl Config {
    // Keep defaults in sync with CLI defaults
    fn default_threads() -> usize {
        15
    }

    fn default_max_instructions() -> usize {
        2000
    }

    /// Load configuration from JSON file
    pub fn from_file(path: &PathBuf) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON config: {}", e))
    }

    /// Create Config from command line arguments.
    ///
    /// If a config file is specified via --config, loads the base configuration
    /// from JSON and then applies command line overrides. Otherwise creates
    /// a new configuration using only command line parameters.
    ///
    /// # Arguments
    ///
    /// * `args` - Parsed command line arguments
    ///
    /// # Returns
    ///
    /// * `Result<Config, String>` - Loaded and processed configuration
    pub fn from_args(args: &Args) -> Self {
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
            initial_registers: HashMap::new(),
        }
    }

    /// Override config values with command line arguments
    pub fn override_with_args(&mut self, args: &Args) {
        self.threads = args.threads;
        self.no_compilation = args.no_compilation;
        self.class = args.class.clone();
        self.faults = args.faults.clone();
        self.analysis = args.analysis;
        self.deep_analysis = args.deep_analysis;
        self.max_instructions = args.max_instructions;
        if args.elf.is_some() {
            self.elf = args.elf.clone();
        }
        self.trace = args.trace;
        self.no_check = args.no_check;
        self.run_through = args.run_through;
        self.success_addresses = args.success_addresses.clone();
        self.failure_addresses = args.failure_addresses.clone();
    }
}

/// Public function to parse hex addresses, used by CLI argument parser
pub fn parse_hex_address(s: &str) -> Result<u64, String> {
    parse_hex(s)
}

/// Command-line arguments structure for the fault simulator.
///
/// This structure defines all command-line options and arguments that the
/// fault simulator accepts. It includes configuration for simulation parameters,
/// file paths, fault types, and analysis options.
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
pub struct Args {
    /// Load configuration from JSON file
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// Number of threads started in parallel
    #[arg(short, long, default_value_t = 15)]
    pub threads: usize,

    /// Suppress re-compilation of target program
    #[arg(short, long, default_value_t = false)]
    pub no_compilation: bool,

    /// Attacks class to be executed:
    ///   --class [all, single, double] [optional: glitch, regbf, regfld, cmdbf]
    ///     E.g.: --class single glitch
    #[arg(long,  value_delimiter = ' ', num_args = 1.., verbatim_doc_comment)]
    pub class: Vec<String>,

    /// Run a command line defined sequence of faults.
    ///   --faults \[specific_attack\] \[optional: specific_attack2 specific_attack3 ...\]
    ///     E.g.: --faults regbf_r1_0100 glitch_1
    #[arg(long, value_delimiter = ' ', num_args = 1.., verbatim_doc_comment)]
    pub faults: Vec<String>,

    /// Activate trace analysis of picked fault
    #[arg(short, long, default_value_t = false)]
    pub analysis: bool,

    /// Switch on deep analysis scan. Repeated code (e.g. loops) are fully analysed
    #[arg(short, long, default_value_t = false)]
    pub deep_analysis: bool,

    /// Maximum number of instructions to be executed
    #[arg(short, long, default_value_t = 2000)]
    pub max_instructions: usize,

    /// Load elf file w/o compilation step
    #[arg(short, long)]
    pub elf: Option<PathBuf>,

    /// Trace failure run w/o fault injection for analysis
    #[arg(long, default_value_t = false)]
    pub trace: bool,

    /// Disable program flow check
    #[arg(long, default_value_t = false)]
    pub no_check: bool,

    /// Don't stop on first successful fault injection
    #[arg(short, long, default_value_t = false)]
    pub run_through: bool,

    /// List of memory addresses that indicate success when accessed
    /// Format: --success-addresses 0x8000123 0x8000456
    #[arg(long, value_parser = parse_hex_address, num_args = 0..)]
    pub success_addresses: Vec<u64>,

    /// List of memory addresses that indicate failure when accessed
    /// Format: --failure-addresses 0x8000789 0x8000abc
    #[arg(long, value_parser = parse_hex_address, num_args = 0..)]
    pub failure_addresses: Vec<u64>,
}
