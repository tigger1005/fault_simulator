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

    fn bin_to_asm(&self, data: &[u8], address: u64) -> String {
        let insns = self
            .cs
            .disasm_all(data, address)
            .expect("Failed to disassemble");

        let asm_cmd = &insns.as_ref()[0];
        format!(
            "{} {}",
            asm_cmd.mnemonic().unwrap(),
            asm_cmd.op_str().unwrap()
        )
    }

    /// Print fault data of given fault_data_vec vector
    ///
    pub fn print_fault_records(&self, fault_data_vec: Vec<Vec<FaultData>>) {
        fault_data_vec.iter().for_each(|fault_context| {
            fault_context.iter().for_each(|fault_data| {
                println!(
                    "0x{:X}:  {} -> {}",
                    fault_data.address,
                    self.bin_to_asm(&fault_data.data, fault_data.address),
                    self.bin_to_asm(&fault_data.data_changed, fault_data.address)
                );
            });
            println!();
        });
    }
}
