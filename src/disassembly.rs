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

        Self { cs } // Define regex to extract register number from instruction
    }

    // Check if register is used in given instruction
    pub fn check_for_register(&self, instruction: &[u8], addr: u64, register: u32) -> bool {
        let inst = self.cs.disasm_count(instruction, addr, 1).unwrap();
        inst[0]
            .op_str()
            .unwrap()
            .contains(format!("r{}", register).as_str())
    }

    /// Disassemble fault data structure
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
        let re = Regex::new(r"(r[0-9]+)").unwrap();

        // Print trace records
        if let Some(trace_records) = trace_records {
            let mut iter = trace_records.iter();
            while let Some(trace_record) = iter.next() {
                match trace_record {
                    TraceRecord::Instruction {
                        address,
                        asm_instruction,
                        ..
                    } => {
                        //
                        let insns_data = self
                            .cs
                            .disasm_count(asm_instruction, *address, 1)
                            .expect("Failed to disassemble");
                        let ins = &insns_data.as_ref()[0];

                        // Print opcode
                        print_opcode(ins);
                        // Print register and flags get next trace record::Instruction
                        let mut temp_iter = iter.clone();
                        while let Some(next_trace_record) = temp_iter.next() {
                            match next_trace_record {
                                TraceRecord::Instruction { registers, .. } => {
                                    // Allways print CPU flags
                                    print_flags_and_registers(&re, &registers.unwrap(), ins);
                                    break;
                                }
                                _ => {}
                            }
                        }

                        println!(">");
                    }
                    TraceRecord::Fault {
                        address: _,
                        fault_type,
                    } => {
                        println!("-> {fault_type}")
                    }
                };
            }
        }
        println!("------------------------");
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

/// Print opcode of given instruction
fn print_opcode(ins: &capstone::Insn) {
    print!(
        "0x{:X}:  {:6} {:40}     < ",
        ins.address(),
        ins.mnemonic().unwrap(),
        ins.op_str().unwrap(),
    );
}

/// Print registers and flags of given registers vector
fn print_flags_and_registers(re: &Regex, registers: &[u32; 17], ins: &capstone::Insn) {
    let cpsr = registers[16];
    let flag_n = (cpsr & 0x80000000) >> 31;
    let flag_z = (cpsr & 0x40000000) >> 30;
    let flag_c = (cpsr & 0x20000000) >> 29;
    let flag_v = (cpsr & 0x10000000) >> 28;
    print!("NZCV:{}{}{}{} ", flag_n, flag_z, flag_c, flag_v);
    // Print used register values from opcode
    for (_, [reg]) in re.captures_iter(ins.op_str().unwrap()).map(|c| c.extract()) {
        let reg_num: usize = reg[1..].parse().unwrap();
        print!("R{}=0x{:08X} ", reg_num, registers[reg_num]);
    }
    if ins.op_str().unwrap().contains("sp") {
        print!("SP=0x{:08X} ", registers[13]);
    }
    if ins.op_str().unwrap().contains("lr") {
        print!("LR=0x{:08X} ", registers[14]);
    }
    if ins.op_str().unwrap().contains("pc") {
        print!("PC=0x{:08X} ", registers[15]);
    }
}
