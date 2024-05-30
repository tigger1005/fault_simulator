mod simulation;

mod disassembly;
mod elf_file;
mod fault_attacks;

pub mod prelude {
    pub use crate::fault_attacks::FaultAttacks;
    pub use crate::simulation::{faults::*, record::TraceRecord};
}
