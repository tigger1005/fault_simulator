use addr2line::gimli;
use elf::endian::AnyEndian;
use elf::file::FileHeader;
use elf::segment::ProgramHeader;
use elf::symbol::Symbol;
use elf::ElfBytes;

#[derive(Clone)]
pub struct ElfFile {
    pub header: FileHeader<AnyEndian>,
    pub program_header: ProgramHeader,
    pub program: Vec<u8>,
    pub decision_activation: Symbol,
    pub serial_puts: Symbol,
    pub decision_data: Symbol,
    file_data: Vec<u8>,
}

impl ElfFile {
    pub fn new(path: std::path::PathBuf) -> Result<Self, String> {
        let file_data = std::fs::read(path).expect("Could not read file.");
        let slice = file_data.as_slice();
        let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open file data failed");

        // Get data
        let program_headers = file.segments().unwrap();
        let program_header = program_headers.get(0).unwrap();
        let program = file.segment_data(&program_header).unwrap();

        let _symbols_table = file.symbol_table().unwrap();
        let _rr = file.dynamic_symbol_table().unwrap();

        // parse out all the normal symbol table symbols with their names
        let common = file.find_common_data().expect("shdrs should parse");
        let symtab = common.symtab.unwrap();
        let strtab = common.symtab_strs.unwrap();
        let symbols_with_names: Vec<_> = symtab
            .iter()
            .map(|sym| (strtab.get(sym.st_name as usize).expect("should parse"), sym))
            .collect();

        // Find needed symbols
        let decision_activation = symbols_with_names
            .iter()
            .find(|&x| x.0 == "decision_activation")
            .unwrap()
            .1
            .clone();

        // Find needed symbols
        let serial_puts = symbols_with_names
            .iter()
            .find(|&x| x.0 == "serial_puts")
            .unwrap()
            .1
            .clone();

        // Find needed symbols
        let decision_data = symbols_with_names
            .iter()
            .find(|&x| x.0 == "decisiondata")
            .unwrap()
            .1
            .clone();

        // Fill struct
        Ok(Self {
            header: file.ehdr,
            program_header,
            program: program.to_vec(),
            decision_activation,
            serial_puts,
            file_data,
            decision_data,
        })
    }

    pub fn get_debug_context(
        &self,
    ) -> addr2line::Context<gimli::EndianReader<gimli::RunTimeEndian, std::rc::Rc<[u8]>>> {
        addr2line::Context::new(&addr2line::object::read::File::parse(&*self.file_data).unwrap())
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::elf_file::ElfFile;

    #[test]
    fn parse_elf_file() {
        let elf_struct =
            ElfFile::new(std::path::PathBuf::from("content/bin/aarch32/victim.elf")).unwrap();
        // File header
        assert_eq!(elf_struct.header.endianness, elf::endian::AnyEndian::Little);
        assert_eq!(elf_struct.header.version, 1);
        // Program header
        assert_eq!(elf_struct.program_header.p_type, 1);
        assert_eq!(elf_struct.program_header.p_align, 4);
        assert_eq!(
            elf_struct.program_header.p_paddr,
            elf_struct.program_header.p_vaddr
        );

        assert_eq!(elf_struct.decision_activation.st_size, 6);

        println!("{:?}", elf_struct.header);
        println!("{:?}", elf_struct.program_header);
        println!("{:?}", elf_struct.decision_activation);
    }
}
