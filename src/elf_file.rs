//! # ELF File Parsing and Analysis
//!
//! This module provides comprehensive ELF file parsing capabilities specifically
//! designed for fault injection simulation. It extracts program segments, debug
//! information, symbol tables, and memory layout data needed for accurate CPU emulation.

use addr2line::{gimli, object::read, Context};
use elf::{
    endian::AnyEndian, file::FileHeader, section::SectionHeader, segment::ProgramHeader,
    symbol::Symbol, ElfBytes,
};
use std::collections::HashMap;

use crate::error::SimulatorError;

pub use elf::abi::*;

/// ELF file parser and data container for fault injection simulation.
///
/// This structure provides comprehensive parsing and access to ELF binary files,
/// extracting all information necessary for accurate CPU emulation and fault
/// injection simulation. It maintains parsed program segments, section headers,
/// symbol tables, and debug information for use by the simulation engine.
///
/// # Key Features
///
/// * **Program Segment Extraction**: Parses and stores loadable program segments
/// * **Symbol Table Access**: Provides fast lookup of global and weak symbols
/// * **Debug Information**: Maintains DWARF debug context for source line mapping
/// * **Memory Layout**: Preserves original ELF memory layout for accurate simulation
///
/// # Usage
///
/// ```rust,no_run
/// use fault_simulator::elf_file::ElfFile;
/// let elf_file = ElfFile::new(std::path::PathBuf::from("target.elf")).unwrap();
/// let debug_context = elf_file.get_debug_context();
/// ```
pub struct ElfFile {
    /// ELF file header containing architecture and format information.
    ///
    /// Provides access to key file metadata including machine type,
    /// entry point address, and endianness for proper emulation setup.
    pub header: FileHeader<AnyEndian>,
    /// Loadable program segments with their data.
    ///
    /// Contains (ProgramHeader, data) tuples for all PT_LOAD segments
    /// that need to be loaded into memory during simulation setup.
    /// The data vector contains the actual bytes to be loaded.
    pub program_data: Vec<(ProgramHeader, Vec<u8>)>,
    /// Named section headers for quick section lookup.
    ///
    /// Maps section names to their headers, filtered to include only
    /// PROGBITS and NOBITS sections relevant for simulation.
    pub section_map: HashMap<String, SectionHeader>,
    /// Global and weak symbol table for symbol resolution.
    ///
    /// Maps symbol names to their Symbol entries, including functions,
    /// variables, and other global symbols needed for fault targeting.
    pub symbol_map: HashMap<String, Symbol>,
    /// Raw ELF file data for debug context creation.
    ///
    /// Preserved to enable creation of debug contexts that require
    /// access to the original file data for DWARF parsing.
    file_data: Vec<u8>,
}

impl ElfFile {
    /// Creates a new ElfFile instance by parsing the specified ELF binary.
    ///
    /// This constructor performs comprehensive ELF parsing including:
    /// * File header validation and architecture detection
    /// * Program segment extraction (PT_LOAD segments only)
    /// * Section header parsing and filtering
    /// * Symbol table construction for global and weak symbols
    /// * Debug information preparation
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the ELF binary file to parse
    ///
    /// # Returns
    ///
    /// * `Ok(ElfFile)` - Successfully parsed ELF file with all data extracted
    /// * `Err(String)` - Parsing error with descriptive message
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * File cannot be read or is not a valid ELF file
    /// * Required sections (string tables, symbol tables) are missing
    /// * ELF format is unsupported or corrupted
    pub fn new(path: std::path::PathBuf) -> Result<Self, SimulatorError> {
        let file_data = std::fs::read(&path).map_err(|e| {
            SimulatorError::elf_with(
                format!("Could not read file '{}': {}", path.display(), e),
                e,
            )
        })?;
        let elf_data = ElfBytes::<AnyEndian>::minimal_parse(file_data.as_ref()).map_err(|e| {
            SimulatorError::elf_with(
                format!("Failed to parse ELF file '{}': {}", path.display(), e),
                e,
            )
        })?;

        // Get all program headers and the linked program data into a vector
        let program_data: Vec<(ProgramHeader, Vec<u8>)> = elf_data
            .segments()
            .unwrap()
            .iter()
            // TODO: Filter PT_LOAD sections
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| (ph, elf_data.segment_data(&ph).unwrap().to_vec()))
            .collect();

        // Get all section headers and the linked section data into a vector

        // parse out all the normal symbol table symbols with their names
        let common = elf_data.find_common_data().expect("shdrs should parse");
        let strtab = common.symtab_strs.unwrap();
        let (section_headers, section_strtab) =
            match elf_data.section_headers_with_strtab().unwrap() {
                (Some(shdrs), Some(strtab)) => (shdrs, strtab),
                _ => {
                    // If we don't have shdrs, or don't have a strtab, we can't find a section by its name
                    return Err(SimulatorError::elf("Missing strtab or section headers"));
                }
            };

        // Sum Strings with their section into a hashmap
        let section_map: HashMap<String, SectionHeader> = section_headers
            .iter()
            .filter(|sec| sec.sh_type == SHT_PROGBITS || sec.sh_type == SHT_NOBITS)
            .map(|sec| {
                (
                    section_strtab
                        .get(sec.sh_name as usize)
                        .expect("should parse")
                        .to_string(),
                    sec,
                )
            })
            .collect();

        // Sum Strings with their symbol into a hashmap
        let symbol_map: HashMap<String, Symbol> = common
            .symtab
            .unwrap()
            .iter()
            .filter(|sym| sym.st_bind() & STB_GLOBAL != 0 || sym.st_bind() & STB_WEAK != 0)
            .map(|sym| {
                (
                    strtab
                        .get(sym.st_name as usize)
                        .expect("should parse")
                        .to_string(),
                    sym,
                )
            })
            .collect();

        // Fill struct
        Ok(Self {
            header: elf_data.ehdr,
            program_data,
            section_map,
            symbol_map,
            file_data,
        })
    }

    /// Creates a DWARF debug context for source line mapping and debugging.
    ///
    /// This method constructs an addr2line debug context that enables mapping
    /// between memory addresses and source file locations. Essential for
    /// generating meaningful fault injection reports and analysis.
    ///
    /// # Returns
    ///
    /// A debug context that can resolve addresses to source locations,
    /// function names, and line numbers when DWARF debug information
    /// is available in the ELF file.
    ///
    /// # Panics
    ///
    /// Panics if the ELF file data is corrupted or if DWARF parsing fails.
    /// This typically indicates an invalid or corrupted ELF file.
    pub fn get_debug_context(
        &self,
    ) -> Context<gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>> {
        Context::new(&read::File::parse(&*self.file_data).unwrap()).unwrap()
    }

    /// Address ranges of all executable segments of the loaded image.
    ///
    /// Every address a sane program can execute lies in one of these ranges, so they
    /// describe where fault injection points can legitimately be placed. An image can
    /// consist of several `PT_LOAD` segments, so all of them are collected.
    ///
    /// # Returns
    ///
    /// Half-open `(start, end)` ranges, or an empty vector if no segment is marked
    /// executable — callers treat that as "range unknown" and must not filter.
    pub fn executable_ranges(&self) -> Vec<(u64, u64)> {
        self.program_data
            .iter()
            .filter(|(header, _)| header.p_flags & PF_X != 0)
            .map(|(header, _)| (header.p_paddr, header.p_paddr + header.p_memsz))
            .collect()
    }

    /// Resolves a symbol name (with optional offset) to a concrete address.
    ///
    /// Clears the Thumb-mode LSB indicator, since the actual code/data is at
    /// the even address.
    fn resolve_symbol_address(
        &self,
        symbol_name: &str,
        offset: u64,
    ) -> Result<u64, SimulatorError> {
        let symbol = self.symbol_map.get(symbol_name).ok_or_else(|| {
            SimulatorError::elf(format!("Symbol '{}' not found in ELF file", symbol_name))
        })?;

        let mut actual_address = symbol.st_value & !1;

        if offset != 0 {
            actual_address = actual_address.wrapping_add(offset);
            log::debug!(
                "  Resolving symbol '{}' + 0x{:X} to address 0x{:08X}",
                symbol_name,
                offset,
                actual_address
            );
        } else {
            log::debug!(
                "  Resolving symbol '{}' to address 0x{:08X}",
                symbol_name,
                actual_address
            );
        }

        Ok(actual_address)
    }

    /// Resolves symbol-based addresses in a `ResultChecks` configuration against
    /// this ELF file's symbol table, in the same manner as `apply_patches`.
    pub fn resolve_result_checks(
        &self,
        result_checks: crate::cli_args::ResultChecks,
    ) -> Result<crate::cli_args::ResultChecks, SimulatorError> {
        let resolve_all = |checks: Vec<crate::cli_args::RegisterCheck>| {
            checks
                .into_iter()
                .map(|check| self.resolve_register_check(check))
                .collect::<Result<Vec<_>, _>>()
        };

        Ok(crate::cli_args::ResultChecks {
            success_checks: resolve_all(result_checks.success_checks)?,
            failure_checks: resolve_all(result_checks.failure_checks)?,
        })
    }

    fn resolve_register_check(
        &self,
        check: crate::cli_args::RegisterCheck,
    ) -> Result<crate::cli_args::RegisterCheck, SimulatorError> {
        let address = if let Some(sym_name) = &check.symbol {
            self.resolve_symbol_address(sym_name, check.offset)?
        } else if let Some(addr) = check.address {
            addr
        } else {
            return Err(SimulatorError::elf(
                "Result check must specify either 'address' or 'symbol'",
            ));
        };

        Ok(crate::cli_args::RegisterCheck {
            address: Some(address),
            symbol: None,
            offset: 0,
            expected_registers: check.expected_registers,
        })
    }

    /// Applies memory patches directly to the loaded ELF image, before simulation starts.
    ///
    /// A patch can target any address within a loadable segment's *memory* range
    /// (`p_memsz`), not just the file-backed part (`p_filesz`). Addresses beyond
    /// `p_filesz` fall in the segment's zero-initialized `.bss` range; the segment's
    /// stored data is zero-extended on demand so RAM (not just flash/code) can be
    /// patched with an initial value.
    pub fn apply_patches(
        &mut self,
        patches: &[crate::cli_args::MemoryPatch],
    ) -> Result<(), SimulatorError> {
        if patches.is_empty() {
            return Ok(());
        }

        log::info!("Applying {} memory patches to ELF data...", patches.len());

        for patch in patches {
            // Resolve address from symbol if needed, otherwise use direct address
            let address = if let Some(sym_name) = &patch.symbol {
                self.resolve_symbol_address(sym_name, patch.offset)?
            } else if let Some(addr) = patch.address {
                addr
            } else {
                return Err(SimulatorError::elf(
                    "Memory patch must specify either 'address' or 'symbol'",
                ));
            };

            log::debug!(
                "  Patching address 0x{:08X} with {} bytes",
                address,
                patch.data.len()
            );

            // Find which program segment contains this address, considering the full
            // memory range of the segment (including zero-initialized .bss).
            let mut found = false;
            for (header, data) in &mut self.program_data {
                // Use virtual address (p_vaddr) for ARM Cortex-M flat memory model
                let segment_start = header.p_vaddr;
                let segment_end = segment_start + header.p_memsz;

                if address >= segment_start && address < segment_end {
                    let offset = (address - segment_start) as usize;
                    let patch_end = offset + patch.data.len();

                    if patch_end as u64 > header.p_memsz {
                        return Err(SimulatorError::elf(format!(
                            "Memory patch at 0x{:08X} extends beyond segment boundary",
                            address
                        )));
                    }

                    // Zero-extend the file-backed data up to the patch end, covering
                    // any .bss range the patch reaches into.
                    if patch_end > data.len() {
                        data.resize(patch_end, 0);
                    }

                    // Apply the patch
                    data[offset..patch_end].copy_from_slice(&patch.data);
                    found = true;
                    break;
                }
            }

            if !found {
                return Err(SimulatorError::elf(format!(
                    "Address 0x{:08X} not found in any loadable segment",
                    address
                )));
            }
        }

        Ok(())
    }
}

impl Clone for ElfFile {
    fn clone(&self) -> Self {
        Self {
            header: self.header,
            program_data: self.program_data.clone(),
            section_map: self.section_map.clone(),
            symbol_map: self.symbol_map.clone(),
            file_data: self.file_data.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use addr2line::object::elf::PT_LOAD;

    use crate::elf_file::ElfFile;

    #[test]
    fn parse_elf_file() {
        let elf_struct = ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
        // File header
        assert_eq!(elf_struct.header.endianness, elf::endian::AnyEndian::Little);
        assert_eq!(elf_struct.header.version, 1);
        // Program header
        assert!(elf_struct.program_data.get(0).is_some());
        assert_eq!(elf_struct.program_data[0].0.p_type, PT_LOAD);
        assert_eq!(elf_struct.program_data[0].0.p_align, 4);
        assert_eq!(
            elf_struct.program_data[0].0.p_paddr,
            elf_struct.program_data[0].0.p_vaddr
        );

        assert!(elf_struct.symbol_map.get("decision_activation").is_some());
        assert!(elf_struct.symbol_map.get("serial_puts").is_some());
        assert!(elf_struct.symbol_map.get("decisiondata").is_some());

        //        assert_eq!(elf_struct.symbol_map["decision_activation"].st_name, 0xec);
        // assert_eq!(
        //     elf_struct.symbol_map["decision_activation"].st_value,
        //     0x80000009
        // );
        // assert_eq!(elf_struct.symbol_map["decision_activation"].st_size, 10);
        // assert_eq!(elf_struct.symbol_map["decision_activation"].st_shndx, 1);
        // assert_eq!(elf_struct.symbol_map["decision_activation"].st_bind(), 1);
    }

    #[test]
    fn resolve_result_checks_by_symbol() {
        use crate::cli_args::{RegisterCheck, ResultChecks};

        let elf_struct = ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
        let expected_address = elf_struct.symbol_map["decision_activation"].st_value & !1;

        let result_checks = ResultChecks {
            success_checks: vec![RegisterCheck {
                address: None,
                symbol: Some("decision_activation".to_string()),
                offset: 0,
                expected_registers: std::collections::HashMap::new(),
            }],
            failure_checks: vec![],
        };

        let resolved = elf_struct.resolve_result_checks(result_checks).unwrap();
        assert_eq!(resolved.success_checks[0].address, Some(expected_address));
        assert_eq!(resolved.success_checks[0].symbol, None);
    }

    #[test]
    fn resolve_result_checks_unknown_symbol_errors() {
        use crate::cli_args::{RegisterCheck, ResultChecks};

        let elf_struct = ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();

        let result_checks = ResultChecks {
            success_checks: vec![RegisterCheck {
                address: None,
                symbol: Some("does_not_exist".to_string()),
                offset: 0,
                expected_registers: std::collections::HashMap::new(),
            }],
            failure_checks: vec![],
        };

        assert!(elf_struct.resolve_result_checks(result_checks).is_err());
    }

    #[test]
    fn apply_patches_writes_into_file_backed_data() {
        use crate::cli_args::MemoryPatch;

        let mut elf_struct = ElfFile::new(std::path::PathBuf::from("tests/bin/test.elf")).unwrap();
        // First segment is the flash image (0x08000000), file-backed from the start.
        let address = elf_struct.program_data[0].0.p_vaddr;

        elf_struct
            .apply_patches(&[MemoryPatch {
                address: Some(address),
                symbol: None,
                offset: 0,
                data: vec![0xAA, 0xBB, 0xCC, 0xDD],
            }])
            .unwrap();

        assert_eq!(
            &elf_struct.program_data[0].1[0..4],
            &[0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn apply_patches_can_write_into_uninitialized_ram() {
        use crate::cli_args::MemoryPatch;

        let mut elf_struct = ElfFile::new(std::path::PathBuf::from("tests/bin/test.elf")).unwrap();
        // Second segment is RAM: p_vaddr 0x20000000, filesz 0x18, memsz 0x10000.
        // An address past filesz lies in the zero-initialized .bss range.
        let (header, data) = &elf_struct.program_data[1];
        assert_eq!(header.p_vaddr, 0x2000_0000);
        let ram_bss_address = header.p_vaddr + data.len() as u64 + 0x100;
        assert!(ram_bss_address < header.p_vaddr + header.p_memsz);

        let patch_data: Vec<u8> = (0..20).collect(); // exercise a patch longer than 8 bytes

        elf_struct
            .apply_patches(&[MemoryPatch {
                address: Some(ram_bss_address),
                symbol: None,
                offset: 0,
                data: patch_data.clone(),
            }])
            .unwrap();

        let (header, data) = &elf_struct.program_data[1];
        let offset = (ram_bss_address - header.p_vaddr) as usize;
        assert_eq!(&data[offset..offset + patch_data.len()], &patch_data[..]);
    }

    #[test]
    fn apply_patches_beyond_segment_memsz_errors() {
        use crate::cli_args::MemoryPatch;

        let mut elf_struct = ElfFile::new(std::path::PathBuf::from("tests/bin/test.elf")).unwrap();
        let (header, _) = &elf_struct.program_data[1];
        let out_of_range_address = header.p_vaddr + header.p_memsz;

        let result = elf_struct.apply_patches(&[MemoryPatch {
            address: Some(out_of_range_address),
            symbol: None,
            offset: 0,
            data: vec![0x01],
        }]);

        assert!(result.is_err());
    }
}
