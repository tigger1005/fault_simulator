use assert_cmd::prelude::*;
use fault_simulator::prelude::*;
use predicates::prelude::*;
use std::env;
use std::process::Command; // Used for writing assertions

#[test]
/// Test for single glitch attack api
///
/// This test runs a single glitch atttacks on two different binaries (victim_.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_single_glitch() {
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_.elf"),
        2000,
        false,
        false,
        15,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
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
        15,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
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
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_3.elf"),
        2000,
        false,
        false,
        15,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
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
        15,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
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
    // Load victim data for attack simulation
    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_.elf"),
        2000,
        false,
        false,
        15,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
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
        15,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
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

#[test]
/// Test for success_addresses and failure_addresses functionality
///
/// This test runs fault simulation on victim_3.elf with custom success and failure addresses
/// Success address: 0x08000490, Failure addresses: 0x08000690, 0x08000014
fn test_success_and_failure_addresses() {
    env::set_var("RAYON_NUM_THREADS", "1");

    // Define custom success and failure addresses for victim_3.elf
    let success_addresses = vec![0x08000490];
    let failure_addresses = vec![0x08000690, 0x08000014];

    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_3.elf"),
        2000,
        false,
        false,
        15,
        success_addresses,
        failure_addresses,
        std::collections::HashMap::new(), // initial_registers
    )
    .unwrap();

    // Test single glitch attack with custom addresses
    let vec = vec!["glitch".to_string()];
    let single_result = attack.single(&mut vec.iter()).unwrap();

    // Verify that the attack runs and produces results
    println!(
        "Single attack result: success={}, attacks={}",
        single_result.0, single_result.1
    );
    assert!(
        single_result.1 > 0,
        "Expected some attack iterations with custom addresses"
    );

    // Test fault simulation with custom addresses
    let fault_result = attack.fault_simulation(&[Glitch::new(1)]).unwrap();
    println!(
        "Fault simulation found {} successful attacks",
        fault_result.len()
    );
}

#[test]
/// Integration test for JSON config loading
///
/// This test creates a temporary JSON config file, runs the simulator with
/// --config, and checks that the output contains expected values.
/// It verifies that the config file is correctly parsed and used.
fn test_json_config() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args(&["--config", "tests/test_config.json"])
        .output()
        .expect("Failed to run binary");

    cmd.assert()
        .stdout(predicate::str::contains("Fault injection simulator"))
        .stdout(predicate::str::contains("glitch"))
        .success();
}

#[test]
/// Test for initial register context functionality
///
/// This test verifies that custom initial register values can be applied
/// and the fault simulation runs without errors using meaningful ARM register values
fn test_initial_register_context() {
    use std::collections::HashMap;
    use unicorn_engine::RegisterARM;

    // Create initial register context with meaningful ARM values
    let mut initial_registers = HashMap::new();
    initial_registers.insert(RegisterARM::R7, 0x2000FFF8); // Frame pointer
    initial_registers.insert(RegisterARM::SP, 0x2000FFF8); // Stack pointer
    initial_registers.insert(RegisterARM::LR, 0x08000005); // Link register
    initial_registers.insert(RegisterARM::PC, 0x8000620); // Program counter

    let mut attack = FaultAttacks::new(
        std::path::PathBuf::from("tests/bin/victim_3.elf"),
        2000,
        false,
        false,
        15,
        vec![], // success_addresses
        vec![], // failure_addresses
        initial_registers,
    )
    .unwrap();

    // Test that fault simulation works with custom registers
    let result = attack.fault_simulation(&[Glitch::new(1)]).unwrap();

    // Should complete without errors (specific results may vary)
    println!(
        "Fault simulation with custom registers: {} attacks found",
        result.len()
    );
}

#[test]
/// Test JSON config with initial registers
///
/// This test verifies that initial register configuration is loaded from JSON
/// and displayed in the output
fn test_json_config_initial_registers() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args(&[
        "--config",
        "tests/test_config.json",
        "--no-check",
        "--max-instructions",
        "100",
    ]);

    cmd.assert()
        .stdout(predicate::str::contains(
            "Using custom initial register context:",
        ))
        .stdout(predicate::str::contains("R7: 0x2000FFF8"))
        .stdout(predicate::str::contains("SP: 0x2000FFF8"))
        .stdout(predicate::str::contains("LR: 0x08000005"))
        .stdout(predicate::str::contains("PC: 0x08000620"))
        .success();
}
