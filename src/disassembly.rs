use std::usize;

use crate::simulation::{fault_data::FaultData, record::TraceRecord};
use addr2line::{fallible_iterator::FallibleIterator, gimli};
use capstone::prelude::*;
use regex::Regex;

pub struct Disassembly {
    cs: Capstone,
}

impl Default for Disassembly {
    fn default() -> Self {
        Self::new()
    }
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

    // Check if register is used in given instruction
    pub fn check_for_register(&self, instruction: &[u8], addr: u64, register: u32) -> bool {
        let inst = self.cs.disasm_count(instruction, addr, 1).unwrap();
        inst[0]
            .op_str()
            .unwrap()
            .contains(format!("r{}", register).as_str())
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
        let mut pre_trace_record: Option<TraceRecord> = None;
        let mut pre_register: Option<[u32; 17]> = None;

        let re = Regex::new(r"(r[0-9]+)").unwrap();

        if let Some(trace_records) = trace_records {
            trace_records.iter().for_each(|trace_record| {
                match trace_record {
                    TraceRecord::Fault { .. } => (),
                    TraceRecord::Instruction { registers, .. } => pre_register = *registers,
                }

                if pre_trace_record.is_some() {
                    match pre_trace_record.as_ref().unwrap() {
                        TraceRecord::Instruction {
                            address,
                            index: _,
                            asm_instruction,
                            ..
                        } => {
                            //
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

                                // Print register and flags

                                if pre_register.is_some() {
                                    // Allways print CPU flags
                                    let cpsr = pre_register.unwrap()[16];
                                    let flag_n = (cpsr & 0x80000000) >> 31;
                                    let flag_z = (cpsr & 0x40000000) >> 30;
                                    let flag_c = (cpsr & 0x20000000) >> 29;
                                    let flag_v = (cpsr & 0x10000000) >> 28;
                                    print!("NZCV:{}{}{}{} ", flag_n, flag_z, flag_c, flag_v);
                                    // Print used register values from opcode
                                    for (_, [reg]) in
                                        re.captures_iter(ins.op_str().unwrap()).map(|c| c.extract())
                                    {
                                        let reg_num: usize = reg[1..].parse().unwrap();
                                        print!(
                                            "R{}=0x{:08X} ",
                                            reg_num,
                                            pre_register.unwrap()[reg_num]
                                        );
                                    }
                                    if ins.op_str().unwrap().contains("sp") {
                                        print!("SP=0x{:08X} ", pre_register.unwrap()[13]);
                                    }
                                    if ins.op_str().unwrap().contains("lr") {
                                        print!("LR=0x{:08X} ", pre_register.unwrap()[14]);
                                    }
                                    if ins.op_str().unwrap().contains("pc") {
                                        print!("PC=0x{:08X} ", pre_register.unwrap()[15]);
                                    }
                                }

                                println!(">");
                            }
                        }
                        TraceRecord::Fault {
                            address: _,
                            fault_type,
                        } => {
                            println!("{:?}", fault_type)
                        }
                    }
                };
                pre_trace_record = Some(trace_record.clone())
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
