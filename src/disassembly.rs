use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
    usize,
};

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
            self.print_debug_info(ins.address(), debug_context, "".to_string());
        }
    }

    /// Print trace_record of given trace_records vector
    pub fn disassembly_trace_records(
        &self,
        trace_records: &Option<Vec<TraceRecord>>,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
    ) {
        let re = Regex::new(r"(r[0-9]+)").unwrap();
        let mut temp_string = "".to_string();

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
                        // Print source code line
                        temp_string = self.print_debug_info(*address, debug_context, temp_string);
                        //
                        let insns_data = self
                            .cs
                            .disasm_count(asm_instruction, *address, 1)
                            .expect("Failed to disassemble");
                        let ins = &insns_data.as_ref()[0];

                        // Print opcode
                        print_opcode(ins);
                        // Print register and flags get next trace record::Instruction
                        for next_trace_record in iter.clone() {
                            if let TraceRecord::Instruction { registers, .. } = next_trace_record {
                                // Allways print CPU flags
                                print_flags_and_registers(&re, &registers.unwrap(), ins);
                                break;
                            }
                        }

                        println!(">");
                    }
                    TraceRecord::Fault {
                        address,
                        fault_type,
                    } => {
                        // Print source code line
                        temp_string = self.print_debug_info(*address, debug_context, temp_string);
                        // Print fault type
                        println!("-> \x1B[38;2;200;10;10m{fault_type}\x1B[0m");
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
        comp_string: String,
    ) -> String {
        let mut temp_string = comp_string.clone();

        if let Ok(frames) = debug_context.find_frames(address).skip_all_loads() {
            for frame in frames.iterator().flatten() {
                if let Some(location) = frame.location {
                    match (location.file, location.line) {
                        (Some(file), Some(line_number)) => {
                            // println!("\t\t{:?}:{:?}", file, line);
                            if let Ok(lines) = read_lines(file) {
                                // Consumes the iterator, returns an (Optional) String
                                if let Some(line) = lines.flatten().nth(line_number as usize - 1) {
                                    if comp_string != line {
                                        println!(
                                            "\x1B[38;2;10;200;10m{:100}\x1B[0m     - {:?}:{:?}",
                                            line, file, line_number
                                        );
                                        temp_string = line.to_string();
                                    }
                                }
                            }
                        }

                        (Some(file), None) => println!("\t\t{:?}", file),
                        _ => println!("No debug info available"),
                    }
                }
            }
        }
        temp_string
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

// The output is wrapped in a Result to allow matching on errors.
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
