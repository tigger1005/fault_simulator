use addr2line::{gimli, object::read, Context};
use elf::{
    endian::AnyEndian, file::FileHeader, section::SectionHeader, segment::ProgramHeader,
    symbol::Symbol, ElfBytes,
};
use std::collections::HashMap;

pub use elf::abi::*;

/// This struct is used to parse an elf file and store the relevant data
pub struct ElfFile {
    pub header: FileHeader<AnyEndian>,
    pub program_data: Vec<(ProgramHeader, Vec<u8>)>,
    pub section_map: HashMap<String, SectionHeader>,
    pub symbol_map: HashMap<String, Symbol>,
    file_data: Vec<u8>,
}

impl ElfFile {
    /// Creates a new `ElfFile` instance from the given file path.
    ///
    /// # Arguments
    ///
    /// * `path` - A `PathBuf` representing the path to the ELF file.
    ///
    /// # Returns
    ///
    /// * `Result<Self, String>` - Returns an `ElfFile` instance if successful, otherwise an error message.
    pub fn new(path: std::path::PathBuf) -> Result<Self, String> {
        let file_data = std::fs::read(path).expect("Could not read file.");
        let elf_data = ElfBytes::<AnyEndian>::minimal_parse(file_data.as_ref())
            .expect("Open file data failed");

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
                    return Err("Missing strtab or section headers".to_string());
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

    /// Returns a debug context for the ELF file.
    ///
    /// # Returns
    ///
    /// * `Context<gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>>` - The debug context.
    pub fn get_debug_context(
        &self,
    ) -> Context<gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>> {
        Context::new(&read::File::parse(&*self.file_data).unwrap()).unwrap()
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
}
