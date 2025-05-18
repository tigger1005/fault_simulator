use std::process::Command;

/// Compiles the victim binary using the `make` command in the `./content` directory.
///
/// This function checks if the compilation is necessary and executes the `make` command.
/// If the compilation fails, it prints the status, stdout, and stderr for debugging purposes.
/// The function asserts that the compilation is successful.
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
