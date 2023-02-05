use rayon::prelude::*;
use std::env;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};
use unicorn_engine::{RegisterARM, Unicorn};

const STACK_BASE: u64 = 0x80100000;
const CODE_START: u64 = 0x80000000;

fn main() {
    let arm_code: [u8; 14] = [
        0x00, 0xF0, 0x01, 0xF8, 0xFE, 0xE7, 0x80, 0xB5, 0x00, 0x20, 0x00, 0xAF, 0x80, 0xBD,
    ];

    // Set parameter from cli
    env::set_var("RAYON_NUM_THREADS", "10");

    println!("Start threads");

    (0..10000).into_par_iter().for_each(|_| {
        // Setup platform -> ARMv8-m.base
        let mut emu = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS).unwrap();
        // Setup memory
        emu.mem_map(CODE_START, 0x20000, Permission::ALL).unwrap();
        emu.mem_map(STACK_BASE, 0x1000, Permission::ALL).unwrap();
        // Setup registers
        emu.reg_write(RegisterARM::SP, STACK_BASE + 100).unwrap();
        // Write code to memory area
        emu.mem_write(CODE_START, &arm_code).unwrap();
        // Run
        emu.emu_start(
            CODE_START | 1,
            (CODE_START + arm_code.len() as u64) | 1,
            0,
            2000,
        )
        .unwrap();
    });
    println!("Done")
}
