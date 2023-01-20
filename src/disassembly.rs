use crate::simulation::FaultData;
use capstone::prelude::*;

pub struct Disassembly {
    cs: Capstone,
}

impl Disassembly {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .extra_mode([arch::arm::ArchExtraMode::MClass].iter().copied())
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        Self { cs }
    }

    fn bin_to_asm(&self, fault_data: &FaultData) {
        let insns_data = self
            .cs
            .disasm_all(&fault_data.data, fault_data.address)
            .expect("Failed to disassemble");
        let insns_data_changed = self
            .cs
            .disasm_all(&fault_data.data_changed, fault_data.address)
            .expect("Failed to disassemble");

        for i in 0..insns_data.as_ref().len() {
            let ins = &insns_data.as_ref()[i];
            let ins_changed = &insns_data_changed.as_ref()[i];

            println!(
                "0x{:X}:  {} {} -> {} {}",
                ins.address(),
                ins.mnemonic().unwrap(),
                ins.op_str().unwrap(),
                ins_changed.mnemonic().unwrap(),
                ins_changed.op_str().unwrap()
            );
        }
    }

    /// Print fault data of given fault_data_vec vector
    ///
    pub fn print_fault_records(&self, fault_data_vec: Vec<Vec<FaultData>>) -> usize {
        fault_data_vec.iter().for_each(|fault_context| {
            fault_context.iter().for_each(|fault_data| {
                self.bin_to_asm(&fault_data);
                println!("");
            });
            println!();
        });
        fault_data_vec.len()
    }
}
