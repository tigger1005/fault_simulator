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

use crate::error::SimulatorError;

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
fn parse_hex(s: &str) -> Result<u64, String> {
    let cleaned = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(cleaned, 16).map_err(|e| format!("Invalid hex address '{}': {}", s, e))
}

/// Parse a hex string of arbitrary length into raw bytes.
///
/// The string is read as a single big-endian number and returned in
/// little-endian byte order, so `"0x47702001"` (interpreted as the 32-bit
/// value `0x47702001`) yields `[0x01, 0x20, 0x70, 0x47]`. Unlike parsing into
/// a `u64`, this has no fixed-width limit — any number of bytes is supported.
pub fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned = s.strip_prefix("0x").unwrap_or(s);
    if cleaned.is_empty() {
        return Err(format!("Invalid hex data '{}': empty value", s));
    }

    // Odd digit counts pad with a leading zero nibble, matching u64::from_str_radix.
    let padded;
    let digits = if !cleaned.len().is_multiple_of(2) {
        padded = format!("0{}", cleaned);
        padded.as_str()
    } else {
        cleaned
    };

    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for i in (0..digits.len()).step_by(2) {
        let byte = u8::from_str_radix(&digits[i..i + 2], 16)
            .map_err(|e| format!("Invalid hex data '{}': {}", s, e))?;
        bytes.push(byte);
    }

    bytes.reverse();
    Ok(bytes)
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

/// An initial register value: either a direct value, or a symbol name
/// (with optional offset) resolved against the ELF symbol table once it is
/// loaded, in the same manner as `MemoryPatch` and `RegisterCheck`.
///
/// This lets e.g. `PC` be pointed at a function by name instead of a raw
/// address: `PC: { symbol: "my_function" }`.
#[derive(Debug, Clone, PartialEq)]
pub enum RegisterValue {
    Direct(u64),
    Symbol { name: String, offset: u64 },
}

/// Custom deserializer for `initial_registers`.
///
/// Mirrors `deserialize_register_context`, but additionally accepts an object
/// value of the form `{"symbol": "name"}` or `{"symbol": "name", "offset": "0x4"}`
/// in place of a raw hex/number value, resolved later against the ELF symbol
/// table once it becomes available.
fn deserialize_initial_registers<'de, D>(
    deserializer: D,
) -> Result<HashMap<RegisterARM, RegisterValue>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct InitialRegistersVisitor;

    impl<'de> Visitor<'de> for InitialRegistersVisitor {
        type Value = HashMap<RegisterARM, RegisterValue>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of register names to hex values or symbol references")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            let mut registers = HashMap::new();

            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                let register = get_register_from_name(&key).ok_or_else(|| {
                    de::Error::custom(format!("Invalid register name: '{}'", key))
                })?;

                let reg_value = match value {
                    serde_json::Value::String(s) => {
                        RegisterValue::Direct(parse_hex(&s).map_err(de::Error::custom)?)
                    }
                    serde_json::Value::Number(n) => {
                        let val = n.as_u64().ok_or_else(|| {
                            de::Error::custom(format!(
                                "Invalid number for register {}: must be a positive integer",
                                key
                            ))
                        })?;
                        RegisterValue::Direct(val)
                    }
                    serde_json::Value::Object(obj) => {
                        let symbol = obj
                            .get("symbol")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                de::Error::custom(format!(
                                    "Register {} object value must specify a string 'symbol'",
                                    key
                                ))
                            })?
                            .to_string();

                        let offset = match obj.get("offset") {
                            None => 0,
                            Some(serde_json::Value::String(s)) => {
                                parse_hex(s).map_err(de::Error::custom)?
                            }
                            Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
                                de::Error::custom(format!(
                                    "Invalid offset for register {}: must be a positive integer",
                                    key
                                ))
                            })?,
                            Some(_) => {
                                return Err(de::Error::custom(format!(
                                    "Register {} offset must be a string or number",
                                    key
                                )))
                            }
                        };

                        RegisterValue::Symbol {
                            name: symbol,
                            offset,
                        }
                    }
                    _ => {
                        return Err(de::Error::custom(format!(
                            "Register {} value must be a string, number, or {{\"symbol\": ...}} object",
                            key
                        )))
                    }
                };

                registers.insert(register, reg_value);
            }

            Ok(registers)
        }
    }

    deserializer.deserialize_map(InitialRegistersVisitor)
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
    #[serde(default)]
    pub print_analysis: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_hex")]
    pub success_addresses: Vec<u64>,
    #[serde(default, deserialize_with = "deserialize_hex")]
    pub failure_addresses: Vec<u64>,
    #[serde(default, deserialize_with = "deserialize_initial_registers")]
    pub initial_registers: HashMap<RegisterARM, RegisterValue>,
    #[serde(default, deserialize_with = "deserialize_memory_patches")]
    pub memory_patches: Vec<MemoryPatch>,
    #[serde(default, deserialize_with = "deserialize_memory_regions")]
    pub memory_regions: Vec<MemoryRegion>,
    #[serde(default)]
    pub log_level: String,
    #[serde(default)]
    pub result_checks: Option<ResultChecks>,
    /// Seconds to wait for a worker result before aborting a campaign (0 = wait forever).
    #[serde(default = "Config::default_result_timeout")]
    pub result_timeout: u64,
    /// Enumerate injection points outside the executable image (slow, see `--no-injection-filter`).
    #[serde(default)]
    pub no_injection_filter: bool,
}

impl Config {
    // Keep defaults in sync with CLI defaults
    fn default_threads() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }

    fn default_max_instructions() -> usize {
        2000
    }

    fn default_result_timeout() -> u64 {
        crate::simulation_thread::default_result_timeout()
            .map(|timeout| timeout.as_secs())
            .unwrap_or(0)
    }

    /// Load configuration from JSON5 file
    pub fn from_file(path: &PathBuf) -> Result<Self, SimulatorError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SimulatorError::config_with(format!("Failed to read config file: {}", e), e)
        })?;

        json5::from_str(&content).map_err(|e| {
            SimulatorError::config_with(format!("Failed to parse JSON5 config: {}", e), e)
        })
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
            print_analysis: args.print_analysis,
            success_addresses: args.success_addresses.clone(),
            failure_addresses: args.failure_addresses.clone(),
            initial_registers: HashMap::new(),
            memory_patches: Vec::new(),
            memory_regions: Vec::new(),
            log_level: "off".to_string(),
            result_checks: None,
            result_timeout: args
                .result_timeout
                .unwrap_or_else(Self::default_result_timeout),
            no_injection_filter: args.no_injection_filter,
        }
    }

    /// Override config values with command line arguments
    /// Override config values with command line arguments
    pub fn override_with_args(&mut self, args: &Args) {
        // Always apply CLI values since they include defaults
        self.threads = args.threads;
        self.max_instructions = args.max_instructions;

        // Only override boolean flags if they're true (explicitly set by user)
        if args.no_compilation {
            self.no_compilation = true;
        }
        if args.analysis {
            self.analysis = true;
        }
        if args.deep_analysis {
            self.deep_analysis = true;
        }
        if args.trace {
            self.trace = true;
        }
        if args.no_check {
            self.no_check = true;
        }
        if args.run_through {
            self.run_through = true;
        }
        if args.no_injection_filter {
            self.no_injection_filter = true;
        }
        if args.print_analysis.is_some() {
            self.print_analysis = args.print_analysis;
        }
        if let Some(result_timeout) = args.result_timeout {
            self.result_timeout = result_timeout;
        }

        // Override vectors/options only if provided
        if !args.class.is_empty() {
            self.class = args.class.clone();
        }
        if !args.faults.is_empty() {
            self.faults = args.faults.clone();
        }
        if args.elf.is_some() {
            self.elf = args.elf.clone();
        }
        if !args.success_addresses.is_empty() {
            self.success_addresses = args.success_addresses.clone();
        }
        if !args.failure_addresses.is_empty() {
            self.failure_addresses = args.failure_addresses.clone();
        }
        // Note: initial_registers, memory_patches, memory_regions, and log_level from JSON config are preserved
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
/// * `config` - Load configuration from JSON5 file.
/// * `threads` - Number of threads started in parallel.
/// * `no_compilation` - Suppress re-compilation of the target program.
/// * `class` - Specifies the attack class to execute. Options include `all`, `single`, `double`, and optional subtypes like `glitch`, `regbf`, `regfld`, `cmdbf`.
/// * `faults` - Defines one coordinated fault sequence to simulate, e.g., `regbf_r1_0100 glitch_1`.
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
    /// Load configuration from JSON5 file
    #[arg(short = 'c', long)]
    pub config: Option<PathBuf>,

    /// Number of threads started in parallel
    #[arg(short, long, default_value_t =  std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1))]
    pub threads: usize,

    /// Suppress re-compilation of target program
    #[arg(short, long, default_value_t = false)]
    pub no_compilation: bool,

    /// Attacks class to be executed:
    ///   --class [all, single, double] [optional: glitch, regbf, regfld, cmdbf]
    ///     E.g.: --class single glitch
    #[arg(long,  value_delimiter = ' ', num_args = 1.., verbatim_doc_comment)]
    pub class: Vec<String>,

    /// Run one command line defined, coordinated sequence of faults.
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

    /// Print analysis trace for a specific attack number and exit.
    /// Useful for automated analysis of successful attacks.
    #[arg(long, value_name = "NUMBER")]
    pub print_analysis: Option<usize>,

    /// List of memory addresses that indicate success when accessed
    /// Format: --success-addresses 0x8000123 0x8000456
    #[arg(long, value_parser = parse_hex_address, num_args = 0..)]
    pub success_addresses: Vec<u64>,

    /// List of memory addresses that indicate failure when accessed
    /// Format: --failure-addresses 0x8000789 0x8000abc
    #[arg(long, value_parser = parse_hex_address, num_args = 0..)]
    pub failure_addresses: Vec<u64>,

    /// Seconds to wait for a worker result before aborting a campaign (0 = wait forever).
    /// Raise it on slow or heavily loaded machines.
    /// Defaults to the FAULT_SIM_RESULT_TIMEOUT environment variable, or 120.
    #[arg(long, value_name = "SECONDS")]
    pub result_timeout: Option<u64>,

    /// Also place follow-up faults on addresses outside the executable image.
    /// By default they are skipped: a preceding fault can desynchronize the
    /// instruction decoder, and enumerating the data the program then executes
    /// as code dominates the runtime without describing a real target.
    #[arg(long, default_value_t = false, verbatim_doc_comment)]
    pub no_injection_filter: bool,
}

/// Custom deserializer for memory patches
pub fn deserialize_memory_patches<'de, D>(deserializer: D) -> Result<Vec<MemoryPatch>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;
    use std::fs;

    #[derive(Deserialize)]
    struct MemoryPatchHelper {
        address: Option<String>,
        symbol: Option<String>,
        offset: Option<String>,
        data: Option<String>,
        file: Option<String>, // Optional binary file providing the patch bytes
    }

    let patches: Vec<MemoryPatchHelper> = Deserialize::deserialize(deserializer)?;

    patches
        .into_iter()
        .map(|patch| {
            // Validate that exactly one of address or symbol is provided
            match (&patch.address, &patch.symbol) {
                (None, None) => {
                    return Err(de::Error::custom(
                        "Memory patch must specify either 'address' or 'symbol'",
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(de::Error::custom(
                        "Memory patch cannot specify both 'address' and 'symbol'",
                    ));
                }
                _ => {}
            }

            // Parse address if provided
            let address = if let Some(addr_str) = patch.address {
                Some(parse_hex(&addr_str).map_err(de::Error::custom)?)
            } else {
                None
            };

            // Parse offset if provided
            let offset = if let Some(offset_str) = patch.offset {
                parse_hex(&offset_str).map_err(de::Error::custom)?
            } else {
                0
            };

            // The patch bytes come either from an inline hex value or a binary file
            let data = match (patch.file, patch.data) {
                (Some(_), Some(_)) => {
                    return Err(de::Error::custom(
                        "Memory patch: use either 'file' or 'data', not both",
                    ))
                }
                (Some(file_path), None) => fs::read(file_path).map_err(de::Error::custom)?,
                (None, Some(data_str)) => parse_hex_bytes(&data_str).map_err(de::Error::custom)?,
                (None, None) => {
                    return Err(de::Error::custom(
                        "Memory patch must specify either 'data' or 'file'",
                    ))
                }
            };

            Ok(MemoryPatch {
                address,
                symbol: patch.symbol,
                offset,
                data,
            })
        })
        .collect()
}

/// Custom deserializer for memory regions
pub fn deserialize_memory_regions<'de, D>(deserializer: D) -> Result<Vec<MemoryRegion>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;
    use std::fs;

    #[derive(Deserialize)]
    struct MemoryRegionHelper {
        address: String,
        size: String,
        file: Option<String>, // Optional binary file to load
        data: Option<String>, // Optional hex value the region is initialized with
        #[serde(default)]
        force_overwrite: bool, // If true, merge ELF segments to allow overwriting
    }

    let regions: Vec<MemoryRegionHelper> = Deserialize::deserialize(deserializer)?;

    regions
        .into_iter()
        .map(|region| {
            let address = parse_hex(&region.address).map_err(de::Error::custom)?;
            let size = parse_hex(&region.size).map_err(de::Error::custom)?;

            // A region is initialized either from a binary file or from an inline value
            let data = match (region.file, region.data) {
                (Some(_), Some(_)) => {
                    return Err(de::Error::custom(format!(
                        "Memory region 0x{:08X}: use either 'file' or 'data', not both",
                        address
                    )))
                }
                (Some(file_path), None) => Some(fs::read(file_path).map_err(de::Error::custom)?),
                (None, Some(value)) => {
                    let value = parse_hex(&value).map_err(de::Error::custom)?;
                    Some(value.to_le_bytes().to_vec())
                }
                (None, None) => None,
            };

            Ok(MemoryRegion {
                address,
                size,
                data,
                force_overwrite: region.force_overwrite,
            })
        })
        .collect()
}

/// Custom deserializer for result check lists (success_checks/failure_checks)
///
/// Mirrors `deserialize_memory_patches`: each check specifies either 'address' or
/// 'symbol' (with an optional 'offset'), resolved later against the ELF symbol
/// table once it becomes available.
fn deserialize_register_checks<'de, D>(deserializer: D) -> Result<Vec<RegisterCheck>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    struct RegisterCheckHelper {
        address: Option<String>,
        symbol: Option<String>,
        offset: Option<String>,
        #[serde(deserialize_with = "deserialize_register_context")]
        expected_registers: HashMap<RegisterARM, u64>,
    }

    let checks: Vec<RegisterCheckHelper> = Deserialize::deserialize(deserializer)?;

    checks
        .into_iter()
        .map(|check| {
            // Validate that exactly one of address or symbol is provided
            match (&check.address, &check.symbol) {
                (None, None) => {
                    return Err(de::Error::custom(
                        "Result check must specify either 'address' or 'symbol'",
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(de::Error::custom(
                        "Result check cannot specify both 'address' and 'symbol'",
                    ));
                }
                _ => {}
            }

            let address = if let Some(addr_str) = check.address {
                Some(parse_hex(&addr_str).map_err(de::Error::custom)?)
            } else {
                None
            };

            let offset = if let Some(offset_str) = check.offset {
                parse_hex(&offset_str).map_err(de::Error::custom)?
            } else {
                0
            };

            Ok(RegisterCheck {
                address,
                symbol: check.symbol,
                offset,
                expected_registers: check.expected_registers,
            })
        })
        .collect()
}
/// A patch applied directly to the loaded ELF image before simulation starts.
///
/// Despite the name, this is not limited to code/flash: any address within a
/// loadable segment's address range can be patched, including RAM backed by
/// `.bss` (zero-initialized data), as long as it fits within the segment.
/// The address can be given directly, or as a symbol name (with an optional
/// offset) resolved against the ELF symbol table once it is loaded. The patch
/// bytes come either from an inline hex value or from a binary file.
#[derive(Debug, Clone)]
pub struct MemoryPatch {
    pub address: Option<u64>,
    pub symbol: Option<String>,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub address: u64,
    pub size: u64,
    pub data: Option<Vec<u8>>, // Optional: data to initialize the region with
    pub force_overwrite: bool, // If true, merge ELF segments to allow overwriting
}

/// Configuration for register value checking at a specific address
///
/// The address can be given directly, or as a symbol name (with an optional
/// offset) that is resolved against the ELF symbol table once it is loaded,
/// in the same manner as `MemoryPatch`.
#[derive(Debug, Clone)]
pub struct RegisterCheck {
    /// Direct address where register values should be checked
    pub address: Option<u64>,
    /// Symbol name to resolve the address from
    pub symbol: Option<String>,
    /// Offset added to the resolved symbol address
    pub offset: u64,
    /// Expected register values (e.g., {"R0": "0x00000001", "R1": "0x00000000"})
    pub expected_registers: HashMap<RegisterARM, u64>,
}

/// Configuration for register-based success/failure checking
#[derive(Debug, Clone, Deserialize)]
pub struct ResultChecks {
    /// List of register checks that indicate success
    #[serde(default, deserialize_with = "deserialize_register_checks")]
    pub success_checks: Vec<RegisterCheck>,
    /// List of register checks that indicate failure
    #[serde(default, deserialize_with = "deserialize_register_checks")]
    pub failure_checks: Vec<RegisterCheck>,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_with_prefix() {
        assert_eq!(parse_hex("0x1000"), Ok(0x1000));
    }

    #[test]
    fn parse_hex_without_prefix() {
        assert_eq!(parse_hex("ABCD"), Ok(0xABCD));
    }

    #[test]
    fn parse_hex_mixed_case() {
        assert_eq!(parse_hex("0xaBcD"), Ok(0xABCD));
    }

    #[test]
    fn parse_hex_invalid_returns_error() {
        assert!(parse_hex("ZZZZ").is_err());
    }

    #[test]
    fn parse_hex_empty_returns_error() {
        assert!(parse_hex("").is_err());
    }

    #[test]
    fn parse_hex_bytes_matches_legacy_u64_conversion() {
        // 4-byte value, matches the previous u64-based little-endian conversion
        assert_eq!(
            parse_hex_bytes("0x47702001"),
            Ok(vec![0x01, 0x20, 0x70, 0x47])
        );
    }

    #[test]
    fn parse_hex_bytes_beyond_u64_width() {
        // 20 bytes, far beyond what fits in a u64
        let value = "0x1122334455667788990011223344556677889900";
        let bytes = parse_hex_bytes(value).unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes.first(), Some(&0x00));
        assert_eq!(bytes.last(), Some(&0x11));
    }

    #[test]
    fn parse_hex_bytes_preserves_leading_zero_bytes() {
        // Previously the u64-based conversion collapsed "0x0001" to a single byte.
        assert_eq!(parse_hex_bytes("0x0001"), Ok(vec![0x01, 0x00]));
    }

    #[test]
    fn parse_hex_bytes_odd_digit_count_is_padded() {
        assert_eq!(parse_hex_bytes("0x1"), Ok(vec![0x01]));
    }

    #[test]
    fn parse_hex_bytes_empty_returns_error() {
        assert!(parse_hex_bytes("0x").is_err());
    }

    #[test]
    fn get_register_from_name_r0() {
        assert_eq!(get_register_from_name("R0"), Some(RegisterARM::R0));
    }

    #[test]
    fn get_register_from_name_sp() {
        assert_eq!(get_register_from_name("SP"), Some(RegisterARM::SP));
    }

    #[test]
    fn get_register_from_name_lowercase() {
        assert_eq!(get_register_from_name("pc"), Some(RegisterARM::PC));
    }

    #[test]
    fn get_register_from_name_unknown() {
        assert_eq!(get_register_from_name("XYZ"), None);
    }

    #[test]
    fn config_from_json_string() {
        let json = r#"{"elf": "test.elf", "class": ["single", "glitch"], "max_instructions": 500}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_instructions, 500);
        assert_eq!(config.class, vec!["single", "glitch"]);
        assert_eq!(config.elf, Some(PathBuf::from("test.elf")));
    }

    #[test]
    fn config_defaults_applied() {
        let json = r#"{}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_instructions, 2000);
        assert!(config.threads > 0);
        assert!(!config.analysis);
    }

    #[test]
    fn config_hex_addresses() {
        let json = r#"{"success_addresses": ["0x1000", "0x2000"], "failure_addresses": [4096]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.success_addresses, vec![0x1000, 0x2000]);
        assert_eq!(config.failure_addresses, vec![4096]);
    }

    #[test]
    fn config_initial_registers() {
        let json = r#"{"initial_registers": {"R0": "0xFF", "SP": "0x20000000"}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.initial_registers.len(), 2);
        assert_eq!(
            config.initial_registers[&RegisterARM::R0],
            RegisterValue::Direct(0xFF)
        );
        assert_eq!(
            config.initial_registers[&RegisterARM::SP],
            RegisterValue::Direct(0x20000000)
        );
    }

    #[test]
    fn config_initial_registers_symbol() {
        let json = r#"{"initial_registers": {"PC": {"symbol": "my_function"}}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.initial_registers[&RegisterARM::PC],
            RegisterValue::Symbol {
                name: "my_function".to_string(),
                offset: 0
            }
        );
    }

    #[test]
    fn config_initial_registers_symbol_with_offset() {
        let json =
            r#"{"initial_registers": {"PC": {"symbol": "my_function", "offset": "0x4"}}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.initial_registers[&RegisterARM::PC],
            RegisterValue::Symbol {
                name: "my_function".to_string(),
                offset: 0x4
            }
        );
    }

    #[test]
    fn config_initial_registers_symbol_object_requires_symbol_key() {
        let json = r#"{"initial_registers": {"PC": {"offset": "0x4"}}}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn config_invalid_register_name() {
        let json = r#"{"initial_registers": {"INVALID": "0xFF"}}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn result_checks_address() {
        let json = r#"{"success_checks": [{"address": "0x08000490", "expected_registers": {"R0": "0x0"}}]}"#;
        let result_checks: ResultChecks = serde_json::from_str(json).unwrap();
        let check = &result_checks.success_checks[0];
        assert_eq!(check.address, Some(0x08000490));
        assert_eq!(check.symbol, None);
        assert_eq!(check.offset, 0);
    }

    #[test]
    fn result_checks_symbol() {
        let json = r#"{"success_checks": [{"symbol": "start_success_handling", "expected_registers": {"R0": "0x0"}}]}"#;
        let result_checks: ResultChecks = serde_json::from_str(json).unwrap();
        let check = &result_checks.success_checks[0];
        assert_eq!(check.address, None);
        assert_eq!(check.symbol.as_deref(), Some("start_success_handling"));
        assert_eq!(check.offset, 0);
    }

    #[test]
    fn result_checks_symbol_with_offset() {
        let json = r#"{"success_checks": [{"symbol": "fih_memcmp", "offset": "0x204", "expected_registers": {"R0": "0x0"}}]}"#;
        let result_checks: ResultChecks = serde_json::from_str(json).unwrap();
        let check = &result_checks.success_checks[0];
        assert_eq!(check.symbol.as_deref(), Some("fih_memcmp"));
        assert_eq!(check.offset, 0x204);
    }

    #[test]
    fn result_checks_requires_address_or_symbol() {
        let json = r#"{"success_checks": [{"expected_registers": {"R0": "0x0"}}]}"#;
        let result: Result<ResultChecks, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn result_checks_rejects_both_address_and_symbol() {
        let json = r#"{"success_checks": [{"address": "0x08000490", "symbol": "start_success_handling", "expected_registers": {"R0": "0x0"}}]}"#;
        let result: Result<ResultChecks, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn memory_patch_address_with_long_data() {
        let json = r#"{"memory_patches": [{"address": "0x08000100", "data": "0x1122334455667788990011223344556677889900"}]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.memory_patches[0].address, Some(0x08000100));
        assert_eq!(config.memory_patches[0].data.len(), 20);
    }

    #[test]
    fn memory_patch_symbol_with_offset() {
        let json = r#"{"memory_patches": [{"symbol": "check_secret", "offset": "0x4", "data": "0x2001"}]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        let patch = &config.memory_patches[0];
        assert_eq!(patch.symbol.as_deref(), Some("check_secret"));
        assert_eq!(patch.offset, 0x4);
        assert_eq!(patch.data, vec![0x01, 0x20]);
    }

    #[test]
    fn memory_patch_from_file() {
        let json = r#"{"memory_patches": [{"address": "0x20000100", "file": "tests/bin/patch_data.bin"}]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        // Read verbatim, no byte reversal (unlike inline hex `data`)
        assert_eq!(config.memory_patches[0].data, b"0123456789ABCDEFGHIJ");
    }

    #[test]
    fn memory_patch_requires_address_or_symbol() {
        let json = r#"{"memory_patches": [{"data": "0x01"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn memory_patch_rejects_both_address_and_symbol() {
        let json = r#"{"memory_patches": [{"address": "0x08000100", "symbol": "check_secret", "data": "0x01"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn memory_patch_requires_data_or_file() {
        let json = r#"{"memory_patches": [{"address": "0x08000100"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn memory_patch_rejects_both_data_and_file() {
        let json = r#"{"memory_patches": [{"address": "0x08000100", "data": "0x01", "file": "tests/bin/patch_data.bin"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_hex_address_public() {
        assert_eq!(parse_hex_address("0x8000123"), Ok(0x8000123));
    }

    #[test]
    fn cli_faults_form_one_coordinated_sequence() {
        let args = Args::try_parse_from([
            "fault_simulator",
            "--faults",
            "cmdbf_00000800",
            "cmdbf_00000002",
            "--no-check",
        ])
        .unwrap();

        assert_eq!(
            Config::from_args(&args).faults,
            vec!["cmdbf_00000800", "cmdbf_00000002"]
        );
    }
}
