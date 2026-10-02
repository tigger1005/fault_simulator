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

/// Splits a trailing `+<offset>` or `-<offset>` suffix off a symbol/address string.
///
/// Returns the base string (everything before the sign) and the signed offset,
/// or `(s, 0)` if no valid offset suffix is present. The offset may be written
/// in hex (`0x`/`0X` prefix) or decimal.
fn split_trailing_offset(s: &str) -> (&str, i64) {
    if let Some(idx) = s.rfind(['+', '-']) {
        // idx > 0 so a leading sign (which would make the base empty) is ignored.
        if idx > 0 {
            let (base, rest) = s.split_at(idx);
            let sign = &rest[..1];
            let magnitude_str = &rest[1..];
            if !magnitude_str.is_empty() {
                let magnitude = match magnitude_str
                    .strip_prefix("0x")
                    .or_else(|| magnitude_str.strip_prefix("0X"))
                {
                    Some(hex) => u64::from_str_radix(hex, 16).ok(),
                    None => magnitude_str.parse::<u64>().ok(),
                };
                if let Some(magnitude) = magnitude {
                    let offset = if sign == "-" {
                        -(magnitude as i64)
                    } else {
                        magnitude as i64
                    };
                    return (base, offset);
                }
            }
        }
    }
    (s, 0)
}

/// Whether a bare string looks like a hex address literal (as opposed to a symbol name).
fn is_hex_literal(s: &str) -> bool {
    s.starts_with("0x") || s.starts_with("0X")
}

/// A memory location: either a concrete address, or a symbol name with an
/// optional signed offset (e.g. `check_secret+0x10`, `check_secret-100`).
///
/// This is the unified representation used for every address-like value in
/// the JSON5 configuration (`success_addresses`, `failure_addresses`,
/// register values, code patch and result-check locations). Resolution to a
/// concrete `u64` address happens once, right after the ELF file is loaded
/// (see [`AddressExpr::resolve`]); everything downstream deals only with
/// plain addresses, never with symbol names.
#[derive(Debug, Clone, PartialEq)]
pub enum AddressExpr {
    /// A concrete memory address.
    Address(u64),
    /// A symbol name with a signed byte offset (0 if none was given).
    Symbol { name: String, offset: i64 },
}

impl AddressExpr {
    /// Parses a string that may be a plain address or a symbol name, auto-detecting
    /// which it is: strings starting with `0x`/`0X` are addresses, everything else
    /// is a symbol name. Both forms may carry a trailing `+offset`/`-offset`
    /// (hex or decimal), e.g. `"0x1000+4"` or `"check_secret+0x10"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("Address/symbol string must not be empty".to_string());
        }
        let (base, offset) = split_trailing_offset(s);
        if is_hex_literal(base) {
            let addr = parse_hex(base)?;
            Ok(AddressExpr::Address(addr.wrapping_add_signed(offset)))
        } else {
            Ok(AddressExpr::Symbol {
                name: base.to_string(),
                offset,
            })
        }
    }

    /// Parses a string that is already known to name a symbol (used where
    /// `symbol` is a dedicated JSON key), so no address/symbol auto-detection
    /// is needed. May carry a trailing `+offset`/`-offset` (hex or decimal).
    pub fn parse_symbol(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("Symbol name must not be empty".to_string());
        }
        let (name, offset) = split_trailing_offset(s);
        Ok(AddressExpr::Symbol {
            name: name.to_string(),
            offset,
        })
    }

    /// Resolves this expression to a concrete address, looking up the symbol
    /// table when needed. The Thumb LSB is cleared from resolved symbol
    /// addresses (the actual code/data lives at the even address).
    pub fn resolve(
        &self,
        symbol_map: &HashMap<String, elf::symbol::Symbol>,
    ) -> Result<u64, SimulatorError> {
        match self {
            AddressExpr::Address(addr) => Ok(*addr),
            AddressExpr::Symbol { name, offset } => {
                let symbol = symbol_map.get(name).ok_or_else(|| {
                    SimulatorError::elf(format!("Symbol '{}' not found in ELF file", name))
                })?;
                let base = symbol.st_value & !1;
                Ok(base.wrapping_add_signed(*offset))
            }
        }
    }
}

impl std::fmt::Display for AddressExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressExpr::Address(addr) => write!(f, "0x{:08X}", addr),
            AddressExpr::Symbol { name, offset } => match offset.cmp(&0) {
                std::cmp::Ordering::Equal => write!(f, "{}", name),
                std::cmp::Ordering::Greater => write!(f, "{}+0x{:X}", name, offset),
                std::cmp::Ordering::Less => write!(f, "{}-0x{:X}", name, -offset),
            },
        }
    }
}

impl<'de> Deserialize<'de> for AddressExpr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Visitor};
        use std::fmt;

        struct AddressExprVisitor;

        impl<'de> Visitor<'de> for AddressExprVisitor {
            type Value = AddressExpr;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "an address (\"0x1234\"), a number, a symbol name, \
                     or \"symbol+offset\"/\"symbol-offset\"",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<AddressExpr, E>
            where
                E: de::Error,
            {
                AddressExpr::parse(value).map_err(de::Error::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<AddressExpr, E>
            where
                E: de::Error,
            {
                Ok(AddressExpr::Address(value))
            }
        }

        deserializer.deserialize_any(AddressExprVisitor)
    }
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

/// Custom deserializer for register context that validates register names and
/// handles hex/decimal values as well as symbol (+ offset) expressions.
fn deserialize_register_context<'de, D>(
    deserializer: D,
) -> Result<HashMap<RegisterARM, AddressExpr>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct RegisterContextVisitor;

    impl<'de> Visitor<'de> for RegisterContextVisitor {
        type Value = HashMap<RegisterARM, AddressExpr>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of register names to hex values, symbols, or symbol+offset")
        }

        fn visit_map<A>(self, mut map: A) -> Result<HashMap<RegisterARM, AddressExpr>, A::Error>
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
                    serde_json::Value::String(s) => {
                        AddressExpr::parse(&s).map_err(de::Error::custom)?
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(val) = n.as_u64() {
                            AddressExpr::Address(val)
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
    #[serde(default)]
    pub print_analysis: Option<usize>,
    #[serde(default)]
    pub success_addresses: Vec<AddressExpr>,
    #[serde(default)]
    pub failure_addresses: Vec<AddressExpr>,
    #[serde(default, deserialize_with = "deserialize_register_context")]
    pub initial_registers: HashMap<RegisterARM, AddressExpr>,
    #[serde(default, deserialize_with = "deserialize_code_patches")]
    pub code_patches: Vec<CodePatch>,
    #[serde(default, deserialize_with = "deserialize_memory_regions")]
    pub memory_regions: Vec<MemoryRegionSpec>,
    #[serde(default)]
    pub log_level: String,
    #[serde(default)]
    pub result_checks: Option<ResultChecksSpec>,
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
            success_addresses: args
                .success_addresses
                .iter()
                .map(|&a| AddressExpr::Address(a))
                .collect(),
            failure_addresses: args
                .failure_addresses
                .iter()
                .map(|&a| AddressExpr::Address(a))
                .collect(),
            initial_registers: HashMap::new(),
            code_patches: Vec::new(),
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
            self.success_addresses = args
                .success_addresses
                .iter()
                .map(|&a| AddressExpr::Address(a))
                .collect();
        }
        if !args.failure_addresses.is_empty() {
            self.failure_addresses = args
                .failure_addresses
                .iter()
                .map(|&a| AddressExpr::Address(a))
                .collect();
        }
        // Note: initial_registers, code_patches, memory_regions, and log_level from JSON config are preserved
    }

    /// Resolves every symbol/offset expression in the configuration against
    /// the loaded ELF file's symbol table, producing the plain addresses the
    /// simulation engine consumes. Call this once, right after the ELF file
    /// is loaded (and after `code_patches` have been applied, since those are
    /// resolved separately by [`crate::elf_file::ElfFile::apply_patches`]).
    pub fn resolve_addresses(
        &self,
        elf: &crate::elf_file::ElfFile,
    ) -> Result<ResolvedAddresses, SimulatorError> {
        let symbol_map = &elf.symbol_map;

        let success_addresses = self
            .success_addresses
            .iter()
            .map(|a| a.resolve(symbol_map))
            .collect::<Result<_, _>>()?;
        let failure_addresses = self
            .failure_addresses
            .iter()
            .map(|a| a.resolve(symbol_map))
            .collect::<Result<_, _>>()?;
        let initial_registers = self
            .initial_registers
            .iter()
            .map(|(reg, value)| Ok((*reg, value.resolve(symbol_map)?)))
            .collect::<Result<_, SimulatorError>>()?;
        let memory_regions = self
            .memory_regions
            .iter()
            .map(|region| region.resolve(symbol_map))
            .collect::<Result<_, _>>()?;
        let result_checks = self
            .result_checks
            .as_ref()
            .map(|checks| checks.resolve(symbol_map))
            .transpose()?;

        Ok(ResolvedAddresses {
            success_addresses,
            failure_addresses,
            initial_registers,
            memory_regions,
            result_checks,
        })
    }
}

/// Every address/symbol expression in a [`Config`] resolved to a plain
/// address, ready to hand to [`crate::simulation_thread::SimulationConfig`].
pub struct ResolvedAddresses {
    pub success_addresses: Vec<u64>,
    pub failure_addresses: Vec<u64>,
    pub initial_registers: HashMap<RegisterARM, u64>,
    pub memory_regions: Vec<MemoryRegion>,
    pub result_checks: Option<ResultChecks>,
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

/// Parse a `data_u8` hex byte-stream string into raw bytes.
///
/// The string lists the patch bytes in increasing-address order: the first
/// byte pair is the value stored at the lowest address. Whitespace between
/// byte pairs is optional and ignored, so `"0102030A0B"` and
/// `"01 02 03 0A 0B"` are equivalent. An optional leading `0x`/`0X` is
/// stripped before decoding.
pub fn parse_data_u8(s: &str) -> Result<Vec<u8>, String> {
    let no_ws: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let hex = no_ws
        .strip_prefix("0x")
        .or_else(|| no_ws.strip_prefix("0X"))
        .unwrap_or(&no_ws);
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(format!(
            "data_u8 value '{}' must contain a non-empty, even number of hex digits",
            s
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| format!("Invalid data_u8 value '{}': {}", s, e))
}

/// Parse a `data_u16` hex value string into its 2-byte little-endian ARM
/// representation.
pub fn parse_data_u16(s: &str) -> Result<Vec<u8>, String> {
    let val = parse_hex(s)?;
    let val = u16::try_from(val).map_err(|_| format!("data_u16 value '{}' exceeds 16 bits", s))?;
    Ok(val.to_le_bytes().to_vec())
}

/// Parse a `data_u32` hex value string into its 4-byte little-endian ARM
/// representation.
pub fn parse_data_u32(s: &str) -> Result<Vec<u8>, String> {
    let val = parse_hex(s)?;
    let val = u32::try_from(val).map_err(|_| format!("data_u32 value '{}' exceeds 32 bits", s))?;
    Ok(val.to_le_bytes().to_vec())
}

/// Resolve exactly one of the three typed patch data fields (`data_u8`,
/// `data_u16`, `data_u32`) into raw patch bytes.
///
/// Returns an error if none or more than one of the fields is provided.
/// Shared by the JSON5 `code_patches`/`memory_regions` deserializers and the
/// MCP `load_elf` tool's ad-hoc `code_patches` parameter, so both paths patch
/// memory with identical, unambiguous semantics.
pub fn resolve_patch_data(
    data_u8: Option<&str>,
    data_u16: Option<&str>,
    data_u32: Option<&str>,
) -> Result<Vec<u8>, String> {
    match (data_u8, data_u16, data_u32) {
        (Some(v), None, None) => parse_data_u8(v),
        (None, Some(v), None) => parse_data_u16(v),
        (None, None, Some(v)) => parse_data_u32(v),
        (None, None, None) => {
            Err("Specify exactly one of 'data_u8', 'data_u16', or 'data_u32'".to_string())
        }
        _ => Err("Specify only one of 'data_u8', 'data_u16', or 'data_u32'".to_string()),
    }
}

/// Custom deserializer for code patches
pub fn deserialize_code_patches<'de, D>(deserializer: D) -> Result<Vec<CodePatch>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    struct CodePatchHelper {
        address: Option<String>,
        symbol: Option<String>,
        data_u8: Option<String>,
        data_u16: Option<String>,
        data_u32: Option<String>,
    }

    let patches: Vec<CodePatchHelper> = Deserialize::deserialize(deserializer)?;

    patches
        .into_iter()
        .map(|patch| {
            // Validate that exactly one of address or symbol is provided
            let address = match (&patch.address, &patch.symbol) {
                (None, None) => {
                    return Err(de::Error::custom(
                        "Code patch must specify either 'address' or 'symbol'",
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(de::Error::custom(
                        "Code patch cannot specify both 'address' and 'symbol'",
                    ));
                }
                (Some(addr_str), None) => {
                    AddressExpr::parse(addr_str).map_err(de::Error::custom)?
                }
                (None, Some(symbol_str)) => {
                    AddressExpr::parse_symbol(symbol_str).map_err(de::Error::custom)?
                }
            };

            let bytes = resolve_patch_data(
                patch.data_u8.as_deref(),
                patch.data_u16.as_deref(),
                patch.data_u32.as_deref(),
            )
            .map_err(de::Error::custom)?;

            Ok(CodePatch {
                address,
                data: bytes,
            })
        })
        .collect()
}

/// Custom deserializer for memory regions
pub fn deserialize_memory_regions<'de, D>(
    deserializer: D,
) -> Result<Vec<MemoryRegionSpec>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;
    use std::fs;

    #[derive(Deserialize)]
    struct MemoryRegionHelper {
        address: String,
        size: String,
        file: Option<String>,     // Optional binary file to load
        data_u8: Option<String>,  // Optional hex byte stream the region is initialized with
        data_u16: Option<String>, // Optional 16-bit LE value the region is initialized with
        data_u32: Option<String>, // Optional 32-bit LE value the region is initialized with
        #[serde(default)]
        force_overwrite: bool, // If true, merge ELF segments to allow overwriting
    }

    let regions: Vec<MemoryRegionHelper> = Deserialize::deserialize(deserializer)?;

    regions
        .into_iter()
        .map(|region| {
            let address = AddressExpr::parse(&region.address).map_err(de::Error::custom)?;
            let size = parse_hex(&region.size).map_err(de::Error::custom)?;

            let inline_data = if region.data_u8.is_some()
                || region.data_u16.is_some()
                || region.data_u32.is_some()
            {
                Some(
                    resolve_patch_data(
                        region.data_u8.as_deref(),
                        region.data_u16.as_deref(),
                        region.data_u32.as_deref(),
                    )
                    .map_err(de::Error::custom)?,
                )
            } else {
                None
            };

            // A region is initialized either from a binary file or from an inline value
            let data = match (region.file, inline_data) {
                (Some(_), Some(_)) => {
                    return Err(de::Error::custom(
                        "Memory region: use either 'file' or one of 'data_u8'/'data_u16'/'data_u32', not both",
                    ))
                }
                (Some(file_path), None) => Some(fs::read(file_path).map_err(de::Error::custom)?),
                (None, Some(bytes)) => Some(bytes),
                (None, None) => None,
            };

            Ok(MemoryRegionSpec {
                address,
                size,
                data,
                force_overwrite: region.force_overwrite,
            })
        })
        .collect()
}

/// A single code patch: the location to patch (address, symbol, or symbol+offset)
/// and the replacement bytes.
#[derive(Debug, Clone)]
pub struct CodePatch {
    pub address: AddressExpr,
    pub data: Vec<u8>,
}

/// A memory region as loaded from the configuration file, with its location
/// not yet resolved against the ELF symbol table. Resolve with
/// [`MemoryRegionSpec::resolve`] once the ELF file is available.
#[derive(Debug, Clone)]
pub struct MemoryRegionSpec {
    pub address: AddressExpr,
    pub size: u64,
    pub data: Option<Vec<u8>>,
    pub force_overwrite: bool,
}

impl MemoryRegionSpec {
    /// Resolves the region's address against the ELF symbol table, producing
    /// the plain-address [`MemoryRegion`] consumed by the simulation engine.
    pub fn resolve(
        &self,
        symbol_map: &HashMap<String, elf::symbol::Symbol>,
    ) -> Result<MemoryRegion, SimulatorError> {
        Ok(MemoryRegion {
            address: self.address.resolve(symbol_map)?,
            size: self.size,
            data: self.data.clone(),
            force_overwrite: self.force_overwrite,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub address: u64,
    pub size: u64,
    pub data: Option<Vec<u8>>, // Optional: data to initialize the region with
    pub force_overwrite: bool, // If true, merge ELF segments to allow overwriting
}

/// Configuration for register value checking at a specific address, as loaded
/// from the configuration file with its location(s) not yet resolved against
/// the ELF symbol table. Resolve with [`RegisterCheckSpec::resolve`] once the
/// ELF file is available.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterCheckSpec {
    /// Address, symbol, or symbol+offset where register values should be checked
    pub address: AddressExpr,
    /// Expected register values (e.g., {"R0": "0x00000001", "R1": "0x00000000"})
    #[serde(deserialize_with = "deserialize_register_context")]
    pub expected_registers: HashMap<RegisterARM, AddressExpr>,
}

impl RegisterCheckSpec {
    pub fn resolve(
        &self,
        symbol_map: &HashMap<String, elf::symbol::Symbol>,
    ) -> Result<RegisterCheck, SimulatorError> {
        let expected_registers = self
            .expected_registers
            .iter()
            .map(|(reg, value)| Ok((*reg, value.resolve(symbol_map)?)))
            .collect::<Result<_, SimulatorError>>()?;
        Ok(RegisterCheck {
            address: self.address.resolve(symbol_map)?,
            expected_registers,
        })
    }
}

/// Configuration for register value checking at a specific (already resolved) address.
/// Consumed directly by the simulation engine; construct via
/// [`RegisterCheckSpec::resolve`] when parsing from a configuration file.
#[derive(Debug, Clone)]
pub struct RegisterCheck {
    /// Address where register values should be checked
    pub address: u64,
    /// Expected register values (e.g., {"R0": "0x00000001", "R1": "0x00000000"})
    pub expected_registers: HashMap<RegisterARM, u64>,
}

/// Configuration for register-based success/failure checking, as loaded from
/// the configuration file with locations not yet resolved against the ELF
/// symbol table. Resolve with [`ResultChecksSpec::resolve`] once the ELF file
/// is available.
#[derive(Debug, Clone, Deserialize)]
pub struct ResultChecksSpec {
    /// List of register checks that indicate success
    #[serde(default)]
    pub success_checks: Vec<RegisterCheckSpec>,
    /// List of register checks that indicate failure
    #[serde(default)]
    pub failure_checks: Vec<RegisterCheckSpec>,
}

impl ResultChecksSpec {
    pub fn resolve(
        &self,
        symbol_map: &HashMap<String, elf::symbol::Symbol>,
    ) -> Result<ResultChecks, SimulatorError> {
        Ok(ResultChecks {
            success_checks: self
                .success_checks
                .iter()
                .map(|check| check.resolve(symbol_map))
                .collect::<Result<_, _>>()?,
            failure_checks: self
                .failure_checks
                .iter()
                .map(|check| check.resolve(symbol_map))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Configuration for register-based success/failure checking, resolved to
/// plain addresses. Consumed directly by the simulation engine; construct via
/// [`ResultChecksSpec::resolve`] when parsing from a configuration file.
#[derive(Debug, Clone)]
pub struct ResultChecks {
    /// List of register checks that indicate success
    pub success_checks: Vec<RegisterCheck>,
    /// List of register checks that indicate failure
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
    fn data_u8_decodes_contiguous_hex_stream() {
        assert_eq!(
            parse_data_u8("0102030405060708090A0B").unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B]
        );
    }

    #[test]
    fn data_u8_decodes_space_separated_hex_stream() {
        assert_eq!(
            parse_data_u8("01 02 03 04 05 06 07 08 0A 0B").unwrap(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A, 0x0B]
        );
    }

    #[test]
    fn data_u8_odd_length_is_error() {
        assert!(parse_data_u8("010").is_err());
    }

    #[test]
    fn data_u16_stores_little_endian() {
        assert_eq!(parse_data_u16("0x12").unwrap(), vec![0x12, 0x00]);
        assert_eq!(parse_data_u16("0x125").unwrap(), vec![0x25, 0x01]);
        assert_eq!(parse_data_u16("0x12ab").unwrap(), vec![0xAB, 0x12]);
    }

    #[test]
    fn data_u16_overflow_is_error() {
        assert!(parse_data_u16("0x10000").is_err());
    }

    #[test]
    fn data_u32_stores_little_endian() {
        assert_eq!(
            parse_data_u32("0x12").unwrap(),
            vec![0x12, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            parse_data_u32("0x125").unwrap(),
            vec![0x25, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            parse_data_u32("0x12abcdef").unwrap(),
            vec![0xEF, 0xCD, 0xAB, 0x12]
        );
    }

    #[test]
    fn data_u32_overflow_is_error() {
        assert!(parse_data_u32("0x100000000").is_err());
    }

    #[test]
    fn resolve_patch_data_requires_exactly_one_field() {
        assert!(resolve_patch_data(None, None, None).is_err());
        assert!(resolve_patch_data(Some("01"), Some("0x1"), None).is_err());
        assert!(resolve_patch_data(Some("01"), None, None).is_ok());
    }

    #[test]
    fn code_patch_requires_one_data_field() {
        let json = r#"{"code_patches": [{"address": "0x1000", "data_u16": "0x4770"}]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.code_patches[0].data, vec![0x70, 0x47]);
    }

    #[test]
    fn code_patch_missing_data_field_is_error() {
        let json = r#"{"code_patches": [{"address": "0x1000"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn code_patch_multiple_data_fields_is_error() {
        let json =
            r#"{"code_patches": [{"address": "0x1000", "data_u16": "0x1", "data_u32": "0x1"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn code_patch_data_u8_is_literal_byte_stream() {
        let json = r#"{"code_patches": [{"address": "0x1000", "data_u8": "70470120"}]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.code_patches[0].data, vec![0x70, 0x47, 0x01, 0x20]);
    }

    #[test]
    fn memory_region_data_and_file_mutually_exclusive() {
        let json = r#"{"memory_regions": [{"address": "0x1000", "size": "0x10", "file": "x.bin", "data_u32": "0x1"}]}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn memory_region_without_data_is_none() {
        let json = r#"{"memory_regions": [{"address": "0x1000", "size": "0x10"}]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.memory_regions[0].data.is_none());
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
        assert_eq!(
            config.success_addresses,
            vec![AddressExpr::Address(0x1000), AddressExpr::Address(0x2000)]
        );
        assert_eq!(config.failure_addresses, vec![AddressExpr::Address(4096)]);
    }

    #[test]
    fn config_symbol_addresses() {
        let json =
            r#"{"success_addresses": ["check_secret", "check_secret+0x10", "check_secret-100"]}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.success_addresses,
            vec![
                AddressExpr::Symbol {
                    name: "check_secret".to_string(),
                    offset: 0
                },
                AddressExpr::Symbol {
                    name: "check_secret".to_string(),
                    offset: 0x10
                },
                AddressExpr::Symbol {
                    name: "check_secret".to_string(),
                    offset: -100
                },
            ]
        );
    }

    #[test]
    fn config_initial_registers() {
        let json = r#"{"initial_registers": {"R0": "0xFF", "SP": "0x20000000"}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.initial_registers.len(), 2);
        assert_eq!(
            config.initial_registers[&RegisterARM::R0],
            AddressExpr::Address(0xFF)
        );
        assert_eq!(
            config.initial_registers[&RegisterARM::SP],
            AddressExpr::Address(0x20000000)
        );
    }

    #[test]
    fn config_initial_registers_symbol() {
        let json = r#"{"initial_registers": {"R0": "decisiondata+0x4"}}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.initial_registers[&RegisterARM::R0],
            AddressExpr::Symbol {
                name: "decisiondata".to_string(),
                offset: 0x4
            }
        );
    }

    #[test]
    fn config_invalid_register_name() {
        let json = r#"{"initial_registers": {"INVALID": "0xFF"}}"#;
        let result: Result<Config, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn address_expr_parses_plain_address() {
        assert_eq!(
            AddressExpr::parse("0x1000").unwrap(),
            AddressExpr::Address(0x1000)
        );
    }

    #[test]
    fn address_expr_parses_bare_symbol() {
        assert_eq!(
            AddressExpr::parse("check_secret").unwrap(),
            AddressExpr::Symbol {
                name: "check_secret".to_string(),
                offset: 0
            }
        );
    }

    #[test]
    fn address_expr_parses_symbol_plus_hex_offset() {
        assert_eq!(
            AddressExpr::parse("check_secret+0x2A").unwrap(),
            AddressExpr::Symbol {
                name: "check_secret".to_string(),
                offset: 0x2A
            }
        );
    }

    #[test]
    fn address_expr_parses_symbol_minus_hex_offset() {
        assert_eq!(
            AddressExpr::parse("check_secret-0x10").unwrap(),
            AddressExpr::Symbol {
                name: "check_secret".to_string(),
                offset: -0x10
            }
        );
    }

    #[test]
    fn address_expr_parses_symbol_plus_decimal_offset() {
        assert_eq!(
            AddressExpr::parse("check_secret+20").unwrap(),
            AddressExpr::Symbol {
                name: "check_secret".to_string(),
                offset: 20
            }
        );
    }

    #[test]
    fn address_expr_parses_symbol_minus_decimal_offset() {
        assert_eq!(
            AddressExpr::parse("check_secret-100").unwrap(),
            AddressExpr::Symbol {
                name: "check_secret".to_string(),
                offset: -100
            }
        );
    }

    #[test]
    fn address_expr_parses_address_plus_offset() {
        assert_eq!(
            AddressExpr::parse("0x1000+0x10").unwrap(),
            AddressExpr::Address(0x1010)
        );
    }

    #[test]
    fn address_expr_parse_symbol_treats_hex_lookalike_as_symbol() {
        // Via the dedicated `symbol` key there is no ambiguity: even a
        // hex-lookalike name is a symbol, never an address.
        assert_eq!(
            AddressExpr::parse_symbol("abc+4").unwrap(),
            AddressExpr::Symbol {
                name: "abc".to_string(),
                offset: 4
            }
        );
    }

    #[test]
    fn address_expr_resolves_symbol_with_offset() {
        let elf = crate::elf_file::ElfFile::new(PathBuf::from("tests/bin/test.elf")).unwrap();
        let base = elf.symbol_map["check_secret"].st_value & !1;

        let expr = AddressExpr::Symbol {
            name: "check_secret".to_string(),
            offset: 0x10,
        };
        assert_eq!(expr.resolve(&elf.symbol_map).unwrap(), base + 0x10);
    }

    #[test]
    fn address_expr_resolve_missing_symbol_is_error() {
        let elf = crate::elf_file::ElfFile::new(PathBuf::from("tests/bin/test.elf")).unwrap();
        let expr = AddressExpr::Symbol {
            name: "definitely_not_a_real_symbol".to_string(),
            offset: 0,
        };
        assert!(expr.resolve(&elf.symbol_map).is_err());
    }

    #[test]
    fn address_expr_display_address() {
        assert_eq!(
            format!("{}", AddressExpr::Address(0x2000FFF8)),
            "0x2000FFF8"
        );
    }

    #[test]
    fn address_expr_display_bare_symbol() {
        assert_eq!(
            format!(
                "{}",
                AddressExpr::Symbol {
                    name: "check_secret".to_string(),
                    offset: 0
                }
            ),
            "check_secret"
        );
    }

    #[test]
    fn address_expr_display_symbol_with_offset() {
        assert_eq!(
            format!(
                "{}",
                AddressExpr::Symbol {
                    name: "check_secret".to_string(),
                    offset: 0x10
                }
            ),
            "check_secret+0x10"
        );
        assert_eq!(
            format!(
                "{}",
                AddressExpr::Symbol {
                    name: "check_secret".to_string(),
                    offset: -0x10
                }
            ),
            "check_secret-0x10"
        );
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
