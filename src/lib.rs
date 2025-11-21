pub mod config;
mod disassembly;
mod elf_file;
mod fault_attacks;
mod simulation;
mod simulation_thread;

pub mod prelude {
    pub use crate::config::{CodePatch, Config, MemoryRegion};
    pub use crate::elf_file::*;
    pub use crate::fault_attacks::{faults::*, FaultAttacks};
    pub use crate::simulation::record::TraceRecord;
    pub use crate::simulation_thread::{SimulationConfig, SimulationThread, WorkloadMessage};
}
