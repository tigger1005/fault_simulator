use capstone::prelude::*;

pub struct Disassembly {
    cs: Capstone,
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
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

    pub fn bin2asm(&self, data: &[u8], address: u64) -> String {
        let insns = self
            .cs
            .disasm_all(data, address)
            .expect("Failed to disassemble");
        
        let asm_cmd = &insns.as_ref()[0];
        asm_cmd.to_string()
    }
}

// let insns = cs
//     .disasm_all(X86_CODE, 0x1000)
//     .expect("Failed to disassemble");
// println!("Found {} instructions", insns.len());
// for i in insns.as_ref() {
//     println!();
//     println!("{}", i);

//     let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
//     let arch_detail: ArchDetail = detail.arch_detail();
//     let ops = arch_detail.operands();

//     let output: &[(&str, String)] = &[
//         ("insn id:", format!("{:?}", i.id().0)),
//         ("bytes:", format!("{:?}", i.bytes())),
//         ("read regs:", reg_names(&cs, detail.regs_read())),
//         ("write regs:", reg_names(&cs, detail.regs_write())),
//         ("insn groups:", group_names(&cs, detail.groups())),
//     ];

//     for &(ref name, ref message) in output.iter() {
//         println!("{:4}{:12} {}", "", name, message);
//     }

//     println!("{:4}operands: {}", "", ops.len());
//     for op in ops {
//         println!("{:8}{:?}", "", op);
//     }
// }
