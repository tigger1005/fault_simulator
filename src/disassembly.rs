use crate::simulation::{FaultData, TraceRecord};
use addr2line::{fallible_iterator::FallibleIterator, gimli};
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

    fn disassembly_fault_data(
        &self,
        fault_data: &FaultData,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        let insns_data = self
            .cs
            .disasm_all(
                &fault_data.original_instructions,
                fault_data.record.address(),
            )
            .expect("Failed to disassemble");

        for i in 0..insns_data.as_ref().len() {
            let ins = &insns_data.as_ref()[i];

            println!(
                "0x{:X}:  {} {} -> {:?}",
                ins.address(),
                ins.mnemonic().unwrap(),
                ins.op_str().unwrap(),
                fault_data.fault.fault_type
            );
            self.print_debug_info(ins.address(), debug_context);
        }
    }

    /// Print trace_record of given trace_records vector
    pub fn disassembly_trace_records(&self, trace_records: &Option<Vec<TraceRecord>>) {
        let mut pre_registers: Option<[u32; 17]> = None;

        if let Some(trace_records) = trace_records {
            trace_records
                .iter()
                .for_each(|trace_record| match trace_record {
                    TraceRecord::Instruction {
                        address,
                        asm_instruction,
                        registers,
                    } => {
                        let insns_data = self
                            .cs
                            .disasm_all(asm_instruction, *address)
                            .expect("Failed to disassemble");

                        for i in 0..insns_data.as_ref().len() {
                            let ins = &insns_data.as_ref()[i];

                            print!(
                                "0x{:X}:  {:6} {:40}     < ",
                                ins.address(),
                                ins.mnemonic().unwrap(),
                                ins.op_str().unwrap(),
                            );
                            if let Some(registers) = registers {
                                // Allways print CPU flags
                                let cpsr = registers[16];
                                let flag_n = (cpsr & 0x80000000) >> 31;
                                let flag_z = (cpsr & 0x40000000) >> 30;
                                let flag_c = (cpsr & 0x20000000) >> 29;
                                let flag_v = (cpsr & 0x10000000) >> 28;
                                print!("NZCV:{}{}{}{} ", flag_n, flag_z, flag_c, flag_v);
                                // Print only changed register values
                                if let Some(pre_registers) = pre_registers {
                                    (0..15).for_each(|index| {
                                        if pre_registers[index] != registers[index] {
                                            print!("R{}=0x{:08X} ", index, registers[index]);
                                        }
                                    });
                                }
                            }
                            println!(">");
                            // Remember register state
                            pre_registers = registers.clone();
                        }
                    }
                    TraceRecord::Fault {
                        address: _,
                        fault_type,
                    } => {
                        println!("{:?}", fault_type)
                    }
                });
            println!("------------------------");
        }
    }

    /// Print fault data of given fault_data_vec vector
    pub fn print_fault_records(
        &self,
        fault_data_vec: &[Vec<FaultData>],
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        fault_data_vec
            .iter()
            .enumerate()
            .for_each(|(attack_num, fault_context)| {
                println!("Attack number {}", attack_num + 1);
                fault_context.iter().for_each(|fault_data| {
                    self.disassembly_fault_data(fault_data, debug_context);
                    println!();
                });
                println!("------------------------");
            });
    }

    fn print_debug_info(
        &self,
        address: u64,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        if let Ok(frames) = debug_context.find_frames(address).skip_all_loads() {
            for frame in frames.iterator().flatten() {
                if let Some(location) = frame.location {
                    match (location.file, location.line) {
                        (Some(file), Some(line)) => {
                            println!("\t\t{:?}:{:?}", file, line)
                        }

                        (Some(file), None) => println!("\t\t{:?}", file),
                        _ => println!("No debug info available"),
                    }
                }
            }
        }
    }
}
