use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use std::error::Error;
use std::fs;

/// Reads a file and displays the content of the ".boot" section.
fn main() -> Result<(), Box<dyn Error>> {
    let bin_data = fs::read(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"))?;
    let obj_file = object::File::parse(&*bin_data)?;

    println!("Architecture: {:?}", obj_file.architecture());
    println!("Build Id: {:?}", obj_file.build_id());
    println!("Kind: {:?}", obj_file.kind());
    println!("Endiness: {:?}", obj_file.endianness());
    println!("Entry: 0x{:x}", obj_file.entry());
    println!("Flags: {:?}", obj_file.flags());
    println!("Format: {:?}", obj_file.format());

    obj_file.sections().for_each(|section| {
        println!("Section: {:?}", section.name().unwrap());
        println!("---------------------------------");
        println!("Kind: {:?}", section.kind());
        println!("Size: {:?}", section.size());
        println!("Address: 0x{:x}", section.address());
        println!("Index: {:?}", section.index());
        println!("Align: {:?}", section.align());
        println!("Flags {:?}", section.flags());
        println!();
    });

    obj_file.segments().for_each(|segment| {
        println!("Segment: {:?}", &segment.name());
        println!("---------------------------------");
        println!("Size: {:?}", segment.size());
        println!("Address: 0x{:x}", segment.address());
        println!("Align: {:?}", segment.align());
        println!("Flags {:?}", segment.flags());
        println!();
    });

    obj_file.symbols().for_each(|symbol| {
        println!("Symbol: {:?}", symbol.name());
        println!("---------------------------------");
        println!("Address: 0x{:x}", symbol.address());
        println!("Size: {:?}", symbol.size());
        println!("Kind: {:?}", symbol.kind());
        println!("Section: {:?}", symbol.section());
        println!();
    });

    if let Some(symbol) = obj_file.symbol_by_name("serial_puts") {
        println!("Symbol: {:?}", symbol);
    };

    Ok(())
}
