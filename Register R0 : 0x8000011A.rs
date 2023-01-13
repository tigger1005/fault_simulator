Register R0 : 0x8000011A
Register R1 : 0x32000001
Register R2 : 0x2
Register R3 : 0xAA01000
Register R4 : 0xFFFFFFFF
Register R5 : 0x0
Register R6 : 0x0
Register R7 : 0x8010FFE4
Register R8 : 0x0
Register R9 : 0x0
Register R10 : 0x0
Register R11 : 0x0
Register R12 : 0x0
Register SP : 0x8010FFE4
Register LR : 0x800000C3
Register PC : 0x800000C6

fn print_register_and_data(&self) {
        ARM_REG
            .iter()
            .for_each(|reg| {println!(
                "Register {:?} : 0x{:X}",*reg,
                self.emu.reg_read(*reg).unwrap()
            )});
        
        let pc = self.emu.reg_read(RegisterARM::PC).unwrap();
        let mut data: [u8; 10] = [0; 10];
        self.emu.mem_read(pc, &mut data).expect("Read memory");
        println!("Code: {:?}", data);
    }