use unicorn_engine::unicorn_const::{Arch, HookType, MemType, Mode, Permission, SECOND_SCALE};
use unicorn_engine::{RegisterARM, Unicorn};

fn main() {
    let arm_code32: Vec<u8> = vec![
        0x17, 0x00, 0x40, 0xe2, 0x17, 0x00, 0x40, 0xe2, 0x17, 0x00, 0x40, 0xe2, 0x17, 0x00, 0x40,
        0xe2,
    ]; // sub r0, #23

    let mut unicorn = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;
    emu.mem_map(0x1000, 0x4000, Permission::ALL)
        .expect("failed to map code page");
    emu.mem_write(0x1000, &arm_code32)
        .expect("failed to write instructions");

    emu.reg_write(RegisterARM::R0, 123)
        .expect("failed write R0");
    emu.reg_write(RegisterARM::R5, 1337)
        .expect("failed write R5");

    emu.add_mem_hook(HookType::MEM_READ, 0x1000, 0x1002, hook_read_callback)
        .expect("failed to set memory hook");

    emu.add_code_hook(0x1006, 0x1008, hook_code_callback)
        .expect("failed to set code hook");

    let _ = emu.emu_start(
        0x1000,
        (0x1000 + arm_code32.len()) as u64,
        10 * SECOND_SCALE,
        1000,
    );
    //assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
    assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));
}

fn hook_read_callback<A>(
    _emu: &mut Unicorn<A>,
    _mem_type: MemType,
    _address: u64,
    _size: usize,
    _temp: i64,
) -> bool {
    println!("Hook");
    true
}

fn hook_code_callback<A>(_emu: &mut Unicorn<A>, address: u64, size: u32) {
    println!(
        "Code Hook on address 0x{:X} with length of 0x{}",
        address, size
    );
}
