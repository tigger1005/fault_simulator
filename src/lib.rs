mod disassembly;
mod elf_file;
mod fault_attacks;
mod simulation;

pub mod prelude {
    pub use crate::fault_attacks::{faults::*, FaultAttacks};
    pub use crate::simulation::record::TraceRecord;
}
