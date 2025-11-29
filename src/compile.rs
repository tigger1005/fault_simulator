//! # Target Program Compilation
//!
//! This module provides compilation capabilities for target programs used in
//! fault injection simulation. It manages the cross-compilation process for
//! ARM targets and ensures proper build configuration for simulation.

use std::process::Command;

/// Compiles the victim binary for fault injection simulation.
///
/// This function orchestrates the compilation process for the target program
/// located in the `./content` directory. It uses the provided Makefile to
/// perform cross-compilation for ARM Cortex-M processors with appropriate
/// compiler flags and linker settings.
///
/// # Compilation Process
///
/// 1. **Cross-Compilation**: Uses ARM GCC toolchain for Cortex-M targets
/// 2. **Debug Information**: Ensures DWARF debug info is included
/// 3. **Memory Layout**: Applies custom linker script for simulation
/// 4. **Optimization**: Builds with appropriate optimization for analysis
///
/// # Output
///
/// Produces `victim.elf` in `content/bin/aarch32/` directory, ready for
/// loading into the fault injection simulator.
///
/// # Error Handling
///
/// Prints detailed compilation output (stdout/stderr) on failure and
/// terminates the program if compilation is unsuccessful.
///
/// # Panics
///
/// Panics if:
/// * The `make` command cannot be executed
/// * The compilation process returns a non-zero exit code
/// * Required build tools or dependencies are missing
pub fn compile() {
    // Compile victim
    println!("Compile victim if necessary:");
    let output = Command::new("make")
        .current_dir("./content")
        .output()
        .expect("failed to execute process");
    if !output.status.success() {
        println!("status: {}", output.status);
        println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        println!("Compilation status: OK\n")
    }
    assert!(output.status.success());
}
