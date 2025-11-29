//! # Fault Injection Simulator Library
//!
//! A comprehensive fault injection simulator targeting ARMv8-M processors (e.g., Cortex-M33).
//! This library provides tools for simulating various types of fault attacks including
//! glitch attacks, register bit flips, register flooding, and command bit flips.
//!
//! ## Core Modules
//!
//! * `compile` - Cross-compilation support for ARM targets
//! * `config` - Configuration management and command-line argument parsing
//! * `disassembly` - ARM instruction disassembly using Capstone engine
//! * `elf_file` - ELF file parsing and analysis
//! * `fault_attack_thread` - Multi-threaded fault attack execution
//! * `fault_attacks` - High-level fault attack coordination and management
//! * `simulation` - Core simulation engine and data structures
//! * `simulation_thread` - Simulation thread management and workload distribution
//!
//! ## Usage
//!
//! The library is designed to be used both as a standalone application and as a library
//! for embedding fault injection capabilities into other tools.

pub mod compile;
pub mod config;
pub mod disassembly;
pub mod elf_file;
pub mod fault_attack_thread;
pub mod fault_attacks;
pub mod simulation;
pub mod simulation_thread;

/// Common imports and re-exports for convenient library usage.
///
/// This prelude module provides the most commonly used types and traits
/// from the fault injection simulator library, allowing users to import
/// everything they need with a single `use fault_simulator::prelude::*;` statement.
///
/// ## Included Types
///
/// * Configuration and setup: `Config`, `SimulationConfig`
/// * ELF file handling: `ElfFile` and related utilities
/// * Fault attack management: `FaultAttackThread`, `FaultAttacks`
/// * Fault types: All fault implementations (glitch, register operations, etc.)
/// * Simulation core: `SimulationThread`, `WorkloadMessage`, `TraceRecord`
pub mod prelude {
    pub use crate::config::Config;
    pub use crate::elf_file::*;
    pub use crate::fault_attack_thread::FaultAttackThread;
    pub use crate::fault_attacks::{faults::*, FaultAttacks};
    pub use crate::simulation::record::TraceRecord;
    pub use crate::simulation_thread::{SimulationConfig, SimulationThread, WorkloadMessage};
}
