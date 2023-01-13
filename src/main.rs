use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission};
use unicorn_engine::{RegisterARM, Unicorn};

const STACK_BASE: u64 = 0x80100000;
const CODE_START: u64 = 0x80000000;
const MMIO_ADR_1: u64 = 0x0AA01000;

fn main() {
    let arm_code: [u8; 4] = [0x1a, 0x60, 0x1a, 0x68];
    // Setup platform -> ARMv8-m.base
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS).unwrap();
    let emu = &mut unicorn;
    // Setup memory and IO
    emu.mem_map(CODE_START, 0x20000, Permission::ALL).unwrap();
    emu.mem_map(STACK_BASE, 0x1000, Permission::ALL).unwrap();
    emu.mem_map(MMIO_ADR_1, 0x1000, Permission::WRITE).unwrap();
    emu.add_mem_hook(
        HookType::MEM_WRITE,
        MMIO_ADR_1,
        MMIO_ADR_1 + 4,
        mmio_auth_write_callback,
    )
    .unwrap();
    // Setup registers
    emu.reg_write(RegisterARM::SP, STACK_BASE + 100).unwrap();
    emu.reg_write(RegisterARM::R2, 0x02).unwrap();
    emu.reg_write(RegisterARM::R3, MMIO_ADR_1).unwrap();
    // Write code to memory area
    emu.mem_write(CODE_START, &arm_code).unwrap();
    // Run
    let ret_val = emu.emu_start(
        CODE_START | 1,
        (CODE_START + arm_code.len() as u64) | 1,
        0,
        2,
    );
    println!("Return {:?}", ret_val);
    drop(unicorn);

    // Setup platform -> ARMv8-m.base
    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN | Mode::MCLASS).unwrap();
    let emu = &mut unicorn;
    // Setup memory and IO
    emu.mem_map(CODE_START, 0x20000, Permission::ALL).unwrap();
    emu.mem_map(STACK_BASE, 0x1000, Permission::READ | Permission::WRITE)
        .unwrap();
    emu.mmio_map_wo(MMIO_ADR_1, 0x1000, mmio_auth_write_callback_2)
        .unwrap();
    // Setup registers
    emu.reg_write(RegisterARM::SP, STACK_BASE + 100).unwrap();
    emu.reg_write(RegisterARM::R2, 0x02).unwrap();
    emu.reg_write(RegisterARM::R3, MMIO_ADR_1).unwrap();

    // Write code to memory area
    emu.mem_write(CODE_START, &arm_code).unwrap();
    // Run
    let ret_val = emu.emu_start(
        CODE_START | 1,
        (CODE_START + arm_code.len() as u64) | 1,
        0,
        2,
    );
    println!("Return {:?}", ret_val);
}

fn mmio_auth_write_callback<D>(
    _emu: &mut Unicorn<D>,
    _type: MemType,
    address: u64,
    size: usize,
    value: i64,
) -> bool {
    println!(
        "mmio_write_callback_1 address 0x{:X} length 0x{:X} value 0x{:X}",
        address, size, value
    );
    true
}

fn mmio_auth_write_callback_2<D>(_emu: &mut Unicorn<D>, address: u64, size: usize, value: u64) {
    println!(
        "mmio_write_callback_2 address 0x{:X} length 0x{:X} value 0x{:X}",
        address, size, value
    );
}
