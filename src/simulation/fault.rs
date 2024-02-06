use std::fmt;

#[derive(Clone, Copy, Debug)]
/// Types of faults which can be simulated.
pub enum FaultType {
    Glitch(usize),
}

#[derive(Clone)]
pub struct SimulationFaultRecord {
    pub index: usize,
    pub record: TraceRecord,
    pub fault_type: FaultType,
}

#[derive(Hash, PartialEq, Eq, Clone)]
/// One recorded step of a simulation
pub struct TraceRecord {
    pub address: u64,
    pub size: usize,
    pub asm_instruction: Vec<u8>,
    pub registers: Option<[u32; 17]>,
}

impl TraceRecord {
    pub fn get_fault_record(&self, index: usize, fault_type: FaultType) -> SimulationFaultRecord {
        SimulationFaultRecord {
            index,
            record: self.clone(),
            fault_type,
        }
    }
}

impl fmt::Debug for SimulationFaultRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "address: 0x{:X} size: 0x{:?} fault_type: {:?}",
            self.record.address, self.record.size, self.fault_type
        )
    }
}

#[derive(Clone, Debug)]
pub struct FaultData {
    pub data: Vec<u8>,
    pub data_changed: Vec<u8>,
    pub fault: SimulationFaultRecord,
}

impl FaultData {
    pub fn get_simulation_fault_records(
        fault_data_records: &[FaultData],
    ) -> Vec<SimulationFaultRecord> {
        fault_data_records
            .iter()
            .map(|record| record.fault.clone())
            .collect()
    }
}
