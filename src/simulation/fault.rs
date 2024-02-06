#[derive(Clone, Copy, Debug)]
/// Types of faults which can be simulated.
pub enum FaultType {
    /// A fault which skips `n` consecutive instructions.
    Glitch(usize),
}

#[derive(Clone, Copy, Debug)]
/// Representation for a fault which shall be executed at step `index` of a simulation.
pub struct SimulationFaultRecord {
    pub index: usize,
    pub fault_type: FaultType,
}

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
/// One recorded step of a simulation
pub struct TraceRecord {
    pub address: u64,
    pub asm_instruction: Vec<u8>,
    pub registers: Option<[u32; 17]>,
}

#[derive(Clone, Debug)]
/// Representation of an fault which was executed in a simulation.
pub struct FaultData {
    /// The original instructions which would have been performed without the fault.
    pub original_instructions: Vec<u8>,
    /// The recorded execution trace of this fault.
    pub record: TraceRecord,
    /// SimulationFaultRecord which caused this FaultData to be simulated.
    pub fault: SimulationFaultRecord,
}

impl FaultData {
    pub fn get_simulation_fault_records(
        fault_data_records: &[FaultData],
    ) -> Vec<SimulationFaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault)
            .collect()
    }
}
