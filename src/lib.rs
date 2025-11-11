mod disassembly;
mod elf_file;
mod fault_attacks;
mod simulation;

#[derive(Debug, Clone)]
pub struct CodePatch {
    pub address: Option<u64>,
    pub symbol: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub address: u64,
    pub size: u64,
    pub data: Option<Vec<u8>>, // Optional: data to initialize the region with
}

pub mod prelude {
    pub use crate::fault_attacks::{faults::*, FaultAttacks};
    pub use crate::simulation::record::TraceRecord;
    pub use crate::CodePatch;
    pub use crate::MemoryRegion;
}
