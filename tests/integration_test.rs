use fault_simulator::prelude::*;
use std::env;

#[test]
/// Test for single glitch attack api
///
/// This test runs a single glitch atttacks on two different binaries (victim_.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_single_glitch() {
    env::set_var("RAYON_NUM_THREADS", "1");
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_.elf"),
        2000,
        false,
        false,
    )
    .unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    let vec = vec!["glitch".to_string()];
    assert_eq!((true, 35), attack.single(&mut vec.iter()).unwrap());
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_4.elf"),
        2000,
        false,
        false,
    )
    .unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    assert_eq!((false, 376), attack.single(&mut vec.iter()).unwrap());
}

#[test]
/// Test for double glitch attack api
///
/// This test runs a double glitch atttacks on two different binaries (victim_3.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_double_glitch() {
    env::set_var("RAYON_NUM_THREADS", "1");
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_3.elf"),
        2000,
        false,
        false,
    )
    .unwrap();
    // Result is (false: bool, number_of_attacks: usize)
    let vec = vec!["glitch".to_string()];
    assert_eq!((false, 22808), attack.double(&mut vec.iter()).unwrap());
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_3.elf"),
        2000,
        false,
        false,
    )
    .unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    let vec = vec!["regbf".to_string()];
    assert_eq!((true, 6916), attack.double(&mut vec.iter()).unwrap());
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on two different binaries (victim_.elf, victim_3.elf)
/// and checks if the correct faults are found, identfied by their addresses
fn run_fault_simulation_one_glitch() {
    env::set_var("RAYON_NUM_THREADS", "1");
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_.elf"),
        2000,
        false,
        false,
    )
    .unwrap();
    // Result is Vec<Vec<FaultData>>
    let result = attack.fault_simulation(&[Glitch::new(1)]).unwrap();

    // Check if correct faults are found (at: 0x80004BA, 0x8000634, 0x800063C)
    assert_eq!(3, result.len());
    // Check for correct faults
    assert!(result.iter().any(|fault_data| match fault_data[0].record {
        TraceRecord::Fault { address, .. } => address == 0x80004BA,
        _ => false,
    }));
    assert!(result.iter().any(|fault_data| match fault_data[0].record {
        TraceRecord::Fault { address, .. } => address == 0x8000634,
        _ => false,
    }));
    assert!(result.iter().any(|fault_data| match fault_data[0].record {
        TraceRecord::Fault { address, .. } => address == 0x800063C,
        _ => false,
    }));
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on victim_3.elf
/// and checks if the correct faults are found, identfied by their addresses
fn run_fault_simulation_two_glitches() {
    env::set_var("RAYON_NUM_THREADS", "1");
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_3.elf"),
        2000,
        false,
        false,
    )
    .unwrap();

    let result = attack
        .fault_simulation(&[Glitch::new(1), Glitch::new(10)])
        .unwrap();

    println!("Result: {:?}", result);
    // Check if correct faults are found (at: 0x8000676, 0x80006a8)
    assert_eq!(1, result.len());
    // Check for correct faults
    assert!(result[0].iter().any(|fault_data| match fault_data.record {
        TraceRecord::Fault { address, .. } => address == 0x8000676,
        _ => false,
    }));
    assert!(result[0].iter().any(|fault_data| match fault_data.record {
        TraceRecord::Fault { address, .. } => address == 0x80006a4,
        _ => false,
    }));
}
