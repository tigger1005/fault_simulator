use std::{
    fs::File,
    io::{self, BufRead},
    path::Path,
};

use crate::simulation::{fault_data::FaultData, record::TraceRecord};
use addr2line::{fallible_iterator::FallibleIterator, gimli};
use capstone::prelude::*;
use colored::Colorize;
use regex::Regex;

/// Struct for disassembling instructions and analyzing faults.
pub struct Disassembly {
    cs: Capstone,
}

impl Default for Disassembly {
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembly {
    /// Creates a new `Disassembly` instance.
    ///
    /// # Returns
    ///
    /// * `Self` - Returns a `Disassembly` instance.
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

    /// Checks if a register is used in the given instruction.
    ///
    /// # Arguments
    ///
    /// * `instruction` - The instruction bytes.
    /// * `addr` - The address of the instruction.
    /// * `register` - The register number to check.
    ///
    /// # Returns
    ///
    /// * `bool` - Returns `true` if the register is used, otherwise `false`.
    pub fn check_for_register(&self, instruction: &[u8], addr: u64, register: u32) -> bool {
        let inst = self.cs.disasm_count(instruction, addr, 1).unwrap();
        inst[0]
            .op_str()
            .unwrap()
            .contains(format!("r{}", register).as_str())
    }

    /// Disassembles the fault data structure.
    ///
    /// # Arguments
    ///
    /// * `fault_data` - The fault data to disassemble.
    /// * `debug_context` - The debug context for the ELF file.
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
                &fault_data.original_instruction,
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
            self.print_debug_info(ins.address(), debug_context, false, "".to_string());
        }
    }

    /// Prints the trace records.
    ///
    /// # Arguments
    ///
    /// * `trace_records` - The trace records to print.
    /// * `debug_context` - The debug context for the ELF file.
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
                        registers,
                        ..
                    } => {
                        let old_registers = registers;
                        // Print source code line
                        temp_string =
                            self.print_debug_info(*address, debug_context, true, temp_string);
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
                                // Always print CPU flags
                                print_flags_and_registers(
                                    &re,
                                    &registers.unwrap(),
                                    old_registers,
                                    ins,
                                );
                                break;
                            }
                        }

                        println!(">");
                    }
                    TraceRecord::Fault {
                        address,
                        fault_type,
                        data,
                    } => {
                        // Print source code line
                        temp_string =
                            self.print_debug_info(*address, debug_context, true, temp_string);
                        // Print fault type
                        print!("-> {}", fault_type.red().bold());
                        // Print fault data if present
                        if !data.is_empty() {
                            let insns_data = self
                                .cs
                                .disasm_count(data, *address, 1)
                                .expect("Failed to disassemble");
                            let ins = &insns_data.as_ref()[0];
                            let text = format!(
                                "(original instruction: {} {})",
                                ins.mnemonic().unwrap(),
                                ins.op_str().unwrap()
                            );
                            println!(" {}", text.red().bold());
                        } else {
                            println!();
                        }
                    }
                };
            }
        }
        println!("------------------------");
    }

    /// Prints the fault data records.
    ///
    /// # Arguments
    ///
    /// * `fault_data_vec` - The vector of fault data records to print.
    /// * `debug_context` - The debug context for the ELF file.
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

    /// Prints debug information for the given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to print debug information for.
    /// * `debug_context` - The debug context for the ELF file.
    /// * `code` - Whether to print the source code line.
    /// * `comp_string` - The previous source code line for comparison.
    ///
    /// # Returns
    ///
    /// * `String` - Returns the current source code line.
    fn print_debug_info(
        &self,
        address: u64,
        debug_context: &addr2line::Context<
            gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>,
        >,
        code: bool,
        comp_string: String,
    ) -> String {
        let mut temp_string = comp_string.clone();

        if let Ok(frames) = debug_context.find_frames(address).skip_all_loads() {
            for frame in frames.iterator().flatten() {
                if let Some(location) = frame.location {
                    match (location.file, location.line) {
                        (Some(file), Some(line_number)) => {
                            let extension = Path::new(file).extension().unwrap().to_str().unwrap();
                            if extension == "S" {
                                continue;
                            }
                            if code {
                                if let Ok(lines) = read_lines(file) {
                                    // Consumes the iterator, returns an (Optional) String
                                    if let Some(line) =
                                        lines.map_while(Result::ok).nth(line_number as usize - 1)
                                    {
                                        if comp_string != line {
                                            println!(
                                                "{:70}     - {:?}:{:?}",
                                                line.replace('\t', "  ").green(),
                                                file,
                                                line_number
                                            );
                                            temp_string = line.to_string();
                                        }
                                    }
                                }
                            } else {
                                println!("\t\t\t {:?}:{:?}", file, line_number);
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
///
/// # Arguments
///
/// * `ins` - The instruction to print.
fn print_opcode(ins: &capstone::Insn) {
    print!(
        "0x{:X}:  {:6} {:40}     < ",
        ins.address(),
        ins.mnemonic().unwrap(),
        ins.op_str().unwrap(),
    );
}

/// Extracts the flags from the given value.
///
/// # Arguments
///
/// * `value` - The value to extract flags from.
///
/// # Returns
///
/// * `(bool, bool, bool, bool)` - Returns a tuple containing the flags (N, Z, C, V).
fn get_flags(value: u32) -> (bool, bool, bool, bool) {
    let n = (value & 0x80000000) >> 31;
    let z = (value & 0x40000000) >> 30;
    let c = (value & 0x20000000) >> 29;
    let v = (value & 0x10000000) >> 28;
    (n == 1, z == 1, c == 1, v == 1)
}

/// Prints the registers and flags of the given registers vector.
///
/// # Arguments
///
/// * `re` - The regex to extract register numbers.
/// * `registers` - The current register values.
/// * `old_registers` - The previous register values.
/// * `ins` - The instruction to print.
fn print_flags_and_registers(
    re: &Regex,
    registers: &[u32; 17],
    old_registers: &Option<[u32; 17]>,
    ins: &capstone::Insn,
) {
    let (flag_n, flag_z, flag_c, flag_v) = get_flags(registers[16]);

    if old_registers.is_some() {
        let (old_flag_n, old_flag_z, old_flag_c, old_flag_v) =
            get_flags(old_registers.unwrap()[16]);
        print!(
            "NZCV:{}{}{}{} ",
            format_colored_flag(flag_n, old_flag_n),
            format_colored_flag(flag_z, old_flag_z),
            format_colored_flag(flag_c, old_flag_c),
            format_colored_flag(flag_v, old_flag_v)
        );
    } else {
        print!("NZCV:{}{}{}{} ", flag_n, flag_z, flag_c, flag_v);
    }

    // Print used register values from opcode
    for (_, [reg]) in re.captures_iter(ins.op_str().unwrap()).map(|c| c.extract()) {
        let reg_num: usize = reg[1..].parse().unwrap();
        if old_registers.is_some() && registers[reg_num] != old_registers.unwrap()[reg_num] {
            let number: String = format!("0x{:08X}", registers[reg_num]);
            print!("R{}={} ", reg_num, number.blue());
        } else {
            print!("R{}=0x{:08X} ", reg_num, registers[reg_num]);
        }
    }
    if ins.op_str().unwrap().contains("sp") {
        if old_registers.is_some() && registers[13] != old_registers.unwrap()[13] {
            let number: String = format!("0x{:08X}", registers[13]);
            print!("SP={} ", number.blue());
        } else {
            print!("SP=0x{:08X} ", registers[13]);
        }
    }
    if ins.op_str().unwrap().contains("lr") {
        if old_registers.is_some() && registers[14] != old_registers.unwrap()[14] {
            let number: String = format!("0x{:08X}", registers[14]);
            print!("LR={} ", number.blue());
        } else {
            print!("LR=0x{:08X} ", registers[14]);
        }
    }
    // PC always changes -> no coloring
    if ins.op_str().unwrap().contains("pc") {
        print!("PC=0x{:08X} ", registers[15]);
    }
}

/// Formats the flag value with color if it has changed.
///
/// # Arguments
///
/// * `new_val` - The new flag value.
/// * `old_val` - The old flag value.
///
/// # Returns
///
/// * `String` - Returns the formatted flag value.
fn format_colored_flag(new_val: bool, old_val: bool) -> String {
    let new_value = format!("{}", new_val as u8);
    if new_val != old_val {
        new_value.blue().to_string()
    } else {
        new_value.to_string()
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
