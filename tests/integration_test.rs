use assert_cmd::prelude::*;
use fault_simulator::prelude::*;
use predicates::prelude::*;
use std::process::Command; // Used for writing assertions
use std::sync::Arc;

pub fn get_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[test]
/// Test for single glitch attack api
///
/// This test runs a single glitch atttacks on two different binaries (victim_.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_single_glitch() {
    let cpu_cores = get_cpu_cores();
    // Load victim data
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    // Create user thread for simulation with threads started
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],
                vec![],
                std::collections::HashMap::new(),
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    // Create fault attacks with dedicated threads
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();

    // Result is (success: bool, number_of_attacks: usize)
    let vec = ["glitch".to_string()];
    assert_eq!((true, 35), attack.single(&vec, false).unwrap());

    // Create user thread for simulation with threads started
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],
                vec![],
                std::collections::HashMap::new(),
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    // Create fault attacks with dedicated threads
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();

    // Result is (success: bool, number_of_attacks: usize)
    let vec = ["glitch".to_string()];
    assert_eq!((true, 280), attack.single(&vec, true).unwrap());

    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_4.elf")).unwrap();
    // Create user thread for simulation with threads started
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],
                vec![],
                std::collections::HashMap::new(),
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    // Create fault attacks with dedicated threads
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Result is (success: bool, number_of_attacks: usize)
    assert_eq!((false, 376), attack.single(&vec, true).unwrap());
}

#[test]
/// Test for double glitch attack api
///
/// This test runs a double glitch attacks on two different binaries (victim_3.elf, victim_4.elf)
/// and checks if faults are found with the correct number of attack iterations
fn run_double_glitch() {
    // Use fixed thread count for deterministic results across machines.
    // Early stopping in double() depends on chunk size (= thread count),
    // so different core counts would produce different accumulated counts.
    let fixed_threads = 4;
    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],                           // success_addresses
                vec![],                           // failure_addresses
                std::collections::HashMap::new(), // initial_registers
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            fixed_threads,
        )
        .unwrap(),
    );

    let mut attack =
        FaultAttacks::new_with_threads(&file_data, user_thread.clone(), fixed_threads).unwrap();
    // Result is (false: bool, number_of_attacks: usize)
    let vec = ["glitch".to_string()];
    let results = attack.double(&vec, false).unwrap();
    assert_eq!((false, 27240), results);

    // Test second scenario with regbf (count_sum accumulates on same attack instance)
    // Result is (success: bool, number_of_attacks: usize)
    let vec = ["regbf".to_string()];
    let results = attack.double(&vec, false).unwrap();
    assert_eq!((true, 34156), results);
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on two different binaries (victim_.elf, victim_3.elf)
/// and checks if the correct faults are found, identified by their addresses
fn run_fault_simulation_one_glitch() {
    let cpu_cores = get_cpu_cores();
    // Load victim data for attack simulation
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![],                           // success_addresses
                vec![],                           // failure_addresses
                std::collections::HashMap::new(), // initial_registers
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Result is bool indicating success of fault simulation
    let result = attack.fault_simulation(&[vec![Glitch::new(1)]]).unwrap();
    let result_data = attack.get_fault_data();

    assert_eq!(true, result);
    // Check if correct faults are found (at: 0x80004BA, 0x8000634, 0x800063C)
    assert_eq!(3, result_data.len());
    // Check for correct faults
    assert!(result_data
        .iter()
        .any(|fault_data| match fault_data[0].record {
            TraceRecord::Fault { address, .. } => address == 0x80004BA,
            _ => false,
        }));
    assert!(result_data
        .iter()
        .any(|fault_data| match fault_data[0].record {
            TraceRecord::Fault { address, .. } => address == 0x8000634,
            _ => false,
        }));
    assert!(result_data
        .iter()
        .any(|fault_data| match fault_data[0].record {
            TraceRecord::Fault { address, .. } => address == 0x800063C,
            _ => false,
        }));
}

#[test]
/// Test for fault simulation api
///
/// This test runs a fault simulation on victim_3.elf
/// and checks if the correct faults are found, identified by their addresses
fn run_fault_simulation_two_glitches() {
    let cpu_cores = get_cpu_cores();
    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let mut user_thread = SimulationThread::with_params(
        2000,
        false,
        vec![],                           // success_addresses
        vec![],                           // failure_addresses
        std::collections::HashMap::new(), // initial_registers
    )
    .unwrap();
    user_thread
        .start_worker_threads(&file_data, cpu_cores)
        .unwrap();
    let mut attack = FaultAttacks::new(&file_data, Arc::new(user_thread)).unwrap();
    attack.start_fault_attack_threads(cpu_cores).unwrap();

    let result = attack
        .fault_simulation(&[vec![Glitch::new(1), Glitch::new(10)]])
        .unwrap();

    assert_eq!(true, result);
    let result_data = attack.get_fault_data();

    println!("Result: {:?}", result);
    // Check if correct faults are found (at: 0x8000676, 0x80006a8)
    assert_eq!(1, result_data.len());
    // Check for correct faults
    assert!(result_data[0]
        .iter()
        .any(|fault_data| match fault_data.record {
            TraceRecord::Fault { address, .. } => address == 0x8000676,
            _ => false,
        }));
    println!("Fault data: {:?}", result_data);
    assert!(result_data[0]
        .iter()
        .any(|fault_data| match fault_data.record {
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
    let cpu_cores = get_cpu_cores();
    // Define custom success and failure addresses for victim_3.elf
    let success_addresses = vec![0x08000490];
    let failure_addresses = vec![0x08000690, 0x08000014];

    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                success_addresses,
                failure_addresses,
                std::collections::HashMap::new(), // initial_registers
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Test single glitch attack with custom addresses
    let vec = ["glitch".to_string()];
    let single_result = attack.single(&vec, false).unwrap();

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
    let _ = attack.fault_simulation(&[vec![Glitch::new(1)]]).unwrap();
    let fault_data = attack.get_fault_data();
    println!(
        "Fault simulation found {} successful attacks",
        fault_data.len()
    );
}

#[test]
/// Integration test for JSON5 config loading
///
/// This test creates a temporary JSON5 config file, runs the simulator with
/// --config, and checks that the output contains expected values.
/// It verifies that the config file is correctly parsed and used.
fn test_json_config() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args(["--config", "tests/test_config.json5"])
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

    let cpu_cores = get_cpu_cores();
    // Create initial register context with meaningful ARM values
    let mut initial_registers = HashMap::new();
    initial_registers.insert(RegisterARM::R7, 0x2000FFF8); // Frame pointer
    initial_registers.insert(RegisterARM::SP, 0x2000FFF8); // Stack pointer
    initial_registers.insert(RegisterARM::LR, 0x08000005); // Link register
    initial_registers.insert(RegisterARM::PC, 0x8000620); // Program counter

    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();
    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(
            SimulationConfig::new(
                2000,
                false,
                vec![], // success_addresses
                vec![], // failure_addresses
                initial_registers,
                vec![],
                "info".to_string(),
                None,
            ),
            &file_data,
            cpu_cores,
        )
        .unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();
    // Test that fault simulation works with custom registers
    let _ = attack.fault_simulation(&[vec![Glitch::new(1)]]).unwrap();
    let result_data = attack.get_fault_data();
    // Should complete without errors (specific results may vary)
    println!(
        "Fault simulation with custom registers: {} attacks found",
        result_data.len()
    );
}

#[test]
/// Test JSON5 config with initial registers
///
/// This test verifies that initial register configuration is loaded from JSON
/// and displayed in the output
fn test_json_config_initial_registers() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--config",
        "tests/test_config_initial_registers.json5",
        "--no-check",
        "--max-instructions",
        "100",
    ]);

    cmd.assert()
        .stderr(predicate::str::contains(
            "Using custom initial register context:",
        ))
        .stderr(predicate::str::contains("R7: 0x2000FFF8"))
        .stderr(predicate::str::contains("SP: 0x2000FFF8"))
        .stderr(predicate::str::contains("LR: 0x08000005"))
        .stderr(predicate::str::contains("PC: 0x08000644"))
        .success();
}

#[test]
/// Test memory region initialization from JSON5 config
///
/// This test verifies that memory regions can be initialized from the config file.
/// The test program reads from an unmapped memory address (0x30000000) which would
/// normally fault with a Unicorn READ_UNMAPPED error. With memory_regions config,
/// the region is mapped and the program can read from it without crashing.
fn test_memory_region_init() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--config",
        "tests/test_config_memory_region.json5",
        "--no-check",
    ]);

    // Should run without Unicorn error (memory mapped successfully)
    cmd.assert().success();
}

#[test]
/// Test code patching from JSON5 config using address
///
/// This test verifies that code patches can be applied using a specific address.
/// The test program has an instruction at 0x08000496 that loads from unmapped memory.
/// With code_patches config, we patch this instruction to load the expected value directly,
/// bypassing the unmapped memory access entirely.
fn test_code_patch() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--config",
        "tests/test_config_code_patch.json5",
        "--no-check",
    ]);

    // Should run without Unicorn error (instruction patched successfully)
    cmd.assert().success();
}

#[test]
/// Test code patching from JSON5 config using symbol
///
/// This test verifies that code patches can be applied using a function symbol name.
/// The test program has a check_secret() function that reads from unmapped memory.
/// With code_patches config, we patch the function entry point to return immediately,
/// bypassing the entire function logic including the unmapped memory access.
fn test_code_patch_symbol() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--config",
        "tests/test_config_code_patch_symbol.json5",
        "--no-check",
    ]);

    // Should run without Unicorn error (function patched successfully)
    cmd.assert().success();
}

#[test]
/// Test code running victim_5.elf with all tests
///
/// This test verifies that victim_5.elf can run successfully with the victim_5.elf binary,
/// which contains all the test scenarios (glitch, regbf, memory access, code patching).
/// It checks that all tests are executed without errors. And the output contains the
/// expected summary of executed tests.
fn test_code_victim_5_full_run() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args(["--elf", "tests/bin/victim_5.elf", "--no-check"]);

    // Should run without Unicorn error and execute all tests (711064 total iterations)
    cmd.assert()
        .stdout(predicate::str::contains("Overall tests executed 711064"))
        .success();
}

#[test]
/// Test for result_checks functionality
///
/// This test verifies the new result_checks mechanism that checks both address
/// and register values. It uses victim_3.elf and defines checkpoints where specific
/// register values determine success or failure.
fn test_result_checks() {
    use unicorn_engine::RegisterARM;

    let cpu_cores = get_cpu_cores();

    // Create result checks configuration
    let success_check = RegisterCheck {
        address: 0x08000490,
        expected_registers: {
            let mut map = std::collections::HashMap::new();
            map.insert(RegisterARM::R0, 0x00000000);
            map
        },
    };

    let failure_check_1 = RegisterCheck {
        address: 0x08000490,
        expected_registers: {
            let mut map = std::collections::HashMap::new();
            map.insert(RegisterARM::R0, 0x00000001);
            map
        },
    };

    let result_checks = ResultChecks {
        success_checks: vec![success_check],
        failure_checks: vec![failure_check_1],
    };

    let file_data: ElfFile =
        ElfFile::new(std::path::PathBuf::from("tests/bin/victim_3.elf")).unwrap();

    let sim_config = SimulationConfig::new(
        2000,
        false,
        vec![],
        vec![],
        std::collections::HashMap::new(),
        vec![],
        "off".to_string(),
        Some(result_checks),
    );

    let user_thread = std::sync::Arc::new(
        SimulationThread::new_with_threads(sim_config, &file_data, cpu_cores).unwrap(),
    );
    let mut attack = FaultAttacks::new_with_threads(&file_data, user_thread, cpu_cores).unwrap();

    // Test single glitch attack with result_checks
    let vec = ["glitch".to_string()];
    let single_result = attack.single(&vec, false).unwrap();

    assert!(
        single_result.1 > 0,
        "Expected some attack iterations with result_checks"
    );
}

#[test]
/// Integration test for result_checks from JSON5 config
///
/// This test verifies that result_checks can be loaded from a JSON5 config file
/// and used in simulation.
fn test_result_checks_json_config() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--config",
        "tests/test_config_result_checks.json5",
        "--no-check",
        "--max-instructions",
        "100",
    ]);

    cmd.assert()
        .stderr(predicate::str::contains(
            "Using register-based success/failure checking",
        ))
        .success();
}

#[test]
/// Test --print-analysis flag for automated analysis output
///
/// This test runs a single glitch attack on victim_.elf (which is known to produce
/// successful attacks), then uses --print-analysis 1 to print the trace for
/// the first successful attack and exit. Verifies the program exits successfully
/// and outputs the expected analysis trace header.
fn test_print_analysis() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--elf",
        "tests/bin/victim_.elf",
        "--class",
        "single",
        "glitch",
        "--no-compilation",
        "--print-analysis",
        "1",
    ]);

    cmd.assert()
        .stdout(predicate::str::contains(
            "Assembler trace of attack number 1",
        ))
        .success();
}

#[test]
/// Test --print-analysis with no successful attacks
///
/// This test runs on victim_4.elf (which has no single glitch vulnerabilities)
/// and verifies that --print-analysis prints "No successful attacks!" and still
/// exits successfully.
fn test_print_analysis_no_attacks() {
    let mut cmd = Command::cargo_bin("fault_simulator").unwrap();

    cmd.args([
        "--elf",
        "tests/bin/victim_4.elf",
        "--class",
        "single",
        "glitch",
        "--no-compilation",
        "--print-analysis",
        "1",
    ]);

    cmd.assert()
        .stdout(predicate::str::contains("No successful attacks!"))
        .success();
}
