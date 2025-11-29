//! # Fault Injection Implementations
//!
//! This module provides a comprehensive suite of fault injection techniques
//! for simulating various types of hardware attacks on ARM processors.
//! Each fault type implements specific attack vectors that can be applied
//! during program execution to test security vulnerabilities.
//!
//! ## Available Fault Types
//!
//! * **Glitch**: Clock/voltage glitching that causes instruction skipping
//! * **Register Bit Flip**: Single-bit errors in processor registers
//! * **Register Flood**: Complete register value corruption
//! * **Command Bit Flip**: Instruction corruption in memory or pipeline
//!
//! ## Fault Injection Framework
//!
//! All fault types implement the `FaultFunctions` trait, providing:
//! * Execution logic for applying faults to CPU state
//! * Filtering logic for identifying injection points
//! * String parsing for configuration and scripting
//! * Enumeration capabilities for automated testing

use super::FaultRecord;
use crate::{
    disassembly::Disassembly,
    simulation::{cpu::Cpu, TraceElement},
};
use std::{fmt::Debug, slice::Iter, sync::Arc};

pub mod cmd_bitflip;
pub mod glitch;
pub mod register_bitflip;
pub mod register_flood;

pub use cmd_bitflip::CmdBitFlip;
pub use glitch::Glitch;
use itertools::Itertools;
pub use register_bitflip::RegisterBitFlip;
pub use register_flood::RegisterFlood;

use unicorn_engine::RegisterARM;

/// Default fault instances for enumeration and testing.
///
/// Provides a representative sample of each fault type with common
/// parameters. Used by the fault enumeration system to generate
/// comprehensive fault injection campaigns.
const FAULTS: [&dyn FaultFunctions; 4] = [
    &Glitch { number: 1 },
    &RegisterBitFlip {
        register: RegisterARM::R0,
        xor_value: 0x01,
    },
    &RegisterFlood {
        register: RegisterARM::R0,
        value: 0x00,
    },
    &CmdBitFlip { xor_value: 0x01 },
];

/// Core trait for implementing fault injection techniques.
///
/// This trait defines the interface that all fault injection implementations
/// must provide. It enables a unified approach to fault injection while
/// allowing each fault type to implement its specific injection logic.
///
/// # Design Principles
///
/// * **Polymorphism**: All faults can be used interchangeably through this trait
/// * **Thread Safety**: Send + Sync bounds enable parallel fault execution
/// * **Flexibility**: Each fault type controls its own execution and filtering logic
/// * **Discoverability**: String parsing and enumeration support automated testing
///
/// # Implementation Requirements
///
/// Implementers must provide thread-safe execution logic and be compatible
/// with the `Arc<dyn FaultFunctions>` type system for dynamic dispatch.
pub trait FaultFunctions: Send + Sync + Debug {
    /// Applies the fault injection to the CPU state at the specified execution point.
    ///
    /// This is the core method that implements the actual fault injection logic.
    /// It may modify CPU registers, memory, or execution state depending on
    /// the fault type. The return value indicates whether instruction repair
    /// is needed (e.g., for instruction corruption faults).
    ///
    /// # Arguments
    ///
    /// * `cpu` - Mutable reference to the CPU emulator for state modification
    /// * `fault` - Fault specification containing timing and parameters
    ///
    /// # Returns
    ///
    /// * `true` - Instruction stream was modified and may need repair
    /// * `false` - Only CPU state was modified, no instruction repair needed
    fn execute(&self, cpu: &mut Cpu, fault: &FaultRecord) -> bool;

    /// Filters execution trace to identify suitable injection points for this fault type.
    ///
    /// Each fault type has different requirements for effective injection points.
    /// This method analyzes the execution trace and removes unsuitable locations,
    /// leaving only those where the fault is likely to be effective.
    ///
    /// # Arguments
    ///
    /// * `records` - Execution trace to filter (modified in-place)
    /// * `cs` - Disassembly engine for instruction analysis
    ///
    /// # Implementation Notes
    ///
    /// Filters should be conservative, removing locations where:
    /// * The fault would have no effect (e.g., unused registers)
    /// * The fault would cause immediate crashes rather than security bypasses
    /// * The instruction type is incompatible with the fault mechanism
    fn filter(&self, records: &mut TraceElement, cs: &Disassembly);

    /// Attempts to parse a fault specification from a string representation.
    ///
    /// Enables creation of fault instances from configuration files, command-line
    /// arguments, and scripting interfaces. Each fault type defines its own
    /// string format for specifying parameters.
    ///
    /// # Arguments
    ///
    /// * `input` - String containing fault specification (format varies by type)
    ///
    /// # Returns
    ///
    /// * `Some(FaultType)` - Successfully parsed fault instance
    /// * `None` - String format not recognized or parameters invalid
    ///
    /// # Example Formats
    ///
    /// * Glitch: "glitch_2" (skip 2 instructions)
    /// * Register: "regbf_r1_0x100" (flip bits in R1 with mask 0x100)
    fn try_from(&self, input: &str) -> Option<FaultType>;

    /// Enumerates all possible variations of this fault type.
    ///
    /// Provides a list of string representations for all meaningful parameter
    /// combinations of this fault type. Used by automated testing systems
    /// to generate comprehensive fault injection campaigns.
    ///
    /// # Returns
    ///
    /// Vector of strings, each representing a valid fault specification
    /// that can be parsed by `try_from()`. Should cover all practically
    /// useful parameter combinations without being exhaustive.
    ///
    /// # Usage
    ///
    /// Enables "all" fault modes where the simulator tests every reasonable
    /// fault configuration automatically.
    fn get_list(&self) -> Vec<String>;
}

/// Type alias for thread-safe, dynamically-dispatched fault injection instances.
///
/// This type enables storing different fault implementations in collections
/// and passing them between threads while maintaining type safety. The Arc
/// provides shared ownership semantics needed for parallel fault execution.
///
/// # Usage Patterns
///
/// * **Collections**: `Vec<FaultType>` for fault sequences
/// * **Threading**: Pass between worker threads safely
/// * **Polymorphism**: Treat all fault types uniformly
/// * **Configuration**: Store parsed fault specifications
pub type FaultType = Arc<dyn FaultFunctions>;

/// Get the fault type from a string
///
/// # Arguments
///
/// * `input` - The input string.
///
/// # Returns
///
/// * `Result<FaultType, String>` - Returns the fault type if found, otherwise an error message.
pub fn get_fault_from(input: &str) -> Result<FaultType, String> {
    // Parse the fault types
    let result = FAULTS.iter().find_map(|fault| fault.try_from(input));
    match result {
        Some(output) => Ok(output),
        None => Err(format!("Unknown fault type: {:?}", input)),
    }
}

/// Get lists of all suggested faults
///
/// # Arguments
///
/// * `groups` - An iterator over a list of fault group names.
///
/// # Returns
///
/// * `Vec<Vec<String>>` - A vector of vectors containing fault names.
pub fn get_fault_lists(groups: &mut Iter<String>) -> Vec<Vec<String>> {
    let fault_types: String = groups.join(" ");
    if !fault_types.is_empty() {
        // Parse all fault types
        FAULTS
            .iter()
            .filter(|fault| {
                // Get the first item of the list, get the attack name and check if it is in the list
                let list = fault.get_list();
                let item = list[0].split('_').collect::<Vec<&str>>();
                fault_types.contains(item[0])
            })
            .map(|fault| fault.get_list())
            .collect()
    } else {
        // Parse all fault types
        FAULTS.iter().map(|fault| fault.get_list()).collect()
    }
}
