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
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    let vec = vec!["glitch".to_string()];
    assert_eq!(
        (true, 46),
        attack.single(2000, false, false, &mut vec.iter()).unwrap()
    );
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_4.elf")).unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    assert_eq!(
        (false, 376),
        attack.single(2000, false, false, &mut vec.iter()).unwrap()
    );
}

#[test]
/// Test for double glitch attack api
///
/// This test runs a double glitch atttacks on two different binaries (victim_3.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_double_glitch() {
    env::set_var("RAYON_NUM_THREADS", "1");
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    // Result is (false: bool, number_of_attacks: usize)
    let vec = vec!["glitch".to_string()];
    assert_eq!(
        (false, 22808),
        attack.double(2000, false, false, &mut vec.iter()).unwrap()
    );
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    let vec = vec!["regbf".to_string()];
    assert_eq!(
        (true, 6916),
        attack.double(2000, false, false, &mut vec.iter()).unwrap()
    );
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on two different binaries (victim_.elf, victim_3.elf)
/// and checks if the correct faults are found, identfied by their addresses
fn run_fault_simulation_one_glitch() {
    env::set_var("RAYON_NUM_THREADS", "1");
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    // Result is Vec<Vec<FaultData>>
    let result = attack
        .fault_simulation(2000, &[Glitch::new(1)], false, false)
        .unwrap();

    // Check if correct faults are found (at: 0x800004b2, 0x8000062E)
    assert_eq!(2, result.len());
    // Check for correct faults
    assert!(result.iter().any(|fault_data| match fault_data[0].record {
        TraceRecord::Fault { address, .. } => address == 0x800004b2,
        _ => false,
    }));
    assert!(result.iter().any(|fault_data| match fault_data[0].record {
        TraceRecord::Fault { address, .. } => address == 0x8000062E,
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
    let mut attack = FaultAttacks::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();

    let result = attack
        .fault_simulation(2000, &[Glitch::new(1), Glitch::new(10)], false, false)
        .unwrap();

    println!("Result: {:?}", result);
    // Check if correct faults are found (at: 0x80000678, 0x800006a8)
    assert_eq!(1, result.len());
    // Check for correct faults
    assert!(result[0].iter().any(|fault_data| match fault_data.record {
        TraceRecord::Fault { address, .. } => address == 0x80000678,
        _ => false,
    }));
    assert!(result[0].iter().any(|fault_data| match fault_data.record {
        TraceRecord::Fault { address, .. } => address == 0x800006a8,
        _ => false,
    }));
}
