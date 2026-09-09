use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use fault_simulator::prelude::*;

use addr2line::fallible_iterator::FallibleIterator;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// Captures stdout output from a closure that prints to stdout.
fn capture_stdout<F: FnOnce()>(f: F) -> String {
    let (output, ()) = capture_stdout_with_result(f);
    output
}

/// Captures stdout output from a closure, returning both the output and the closure's return value.
///
/// Uses a pipe to intercept stdout. A dedicated reader thread drains the pipe
/// concurrently so the closure never blocks when the pipe buffer fills up.
/// Panics inside the closure are caught and re-raised after stdout is restored.
fn capture_stdout_with_result<F: FnOnce() -> T, T>(f: F) -> (String, T) {
    use std::os::unix::io::FromRawFd;

    // Create a pipe
    let (read_fd, write_fd) = {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret != 0 {
            // If pipe creation fails, just run the closure without capturing
            let result = f();
            return (String::new(), result);
        }
        (fds[0], fds[1])
    };

    // Save original stdout
    let original_stdout = unsafe { libc::dup(1) };

    // Redirect stdout to pipe write end
    unsafe {
        libc::dup2(write_fd, 1);
    }

    // Spawn a reader thread BEFORE running the closure to prevent pipe buffer deadlock.
    // The reader drains the pipe concurrently so writes never block.
    let reader_handle = std::thread::spawn(move || {
        let mut output = String::new();
        let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
        use std::io::Read;
        let _ = read_file.read_to_string(&mut output);
        output
    });

    // Run the closure, catching panics to ensure stdout is always restored
    let closure_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    // Flush stdout to ensure all data reaches the pipe
    io::stdout().flush().ok();

    // Restore original stdout and close write end so the reader thread sees EOF
    unsafe {
        libc::dup2(original_stdout, 1);
        libc::close(original_stdout);
        libc::close(write_fd);
    }

    // Collect output from the reader thread
    let output = reader_handle.join().unwrap_or_default();

    // Re-raise panic if the closure panicked
    let result = match closure_result {
        Ok(val) => val,
        Err(panic_payload) => std::panic::resume_unwind(panic_payload),
    };

    (output, result)
}

/// Truncates captured output to a maximum number of lines.
fn truncate_output(text: &str, max_lines: Option<usize>) -> String {
    match max_lines {
        Some(max) if text.lines().count() > max => {
            let total = text.lines().count();
            let kept: Vec<&str> = text.lines().take(max).collect();
            format!(
                "{}\n... [truncated: {} of {} lines shown]",
                kept.join("\n"),
                max,
                total
            )
        }
        _ => text.to_string(),
    }
}

/// Parses a hex string with optional "0x" prefix into an address.
fn parse_hex_u64(value: &str) -> Option<u64> {
    let cleaned = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(cleaned, 16).ok()
}

/// Resolves an address to "file:line" using the ELF DWARF debug information.
fn source_location(file_data: &ElfFile, address: u64) -> Option<String> {
    let debug_context = file_data.get_debug_context();
    let frames = debug_context.find_frames(address).skip_all_loads().ok()?;
    for frame in frames.iterator().flatten() {
        if let Some(location) = frame.location {
            if let (Some(file), Some(line)) = (location.file, location.line) {
                return Some(format!("{}:{}", file, line));
            }
        }
    }
    None
}

/// Static description of a loaded session, used by `get_status`.
struct SessionInfo {
    elf_path: String,
    threads: usize,
    max_instructions: usize,
    deep_analysis: bool,
    no_check: bool,
    success_addresses: Vec<u64>,
    failure_addresses: Vec<u64>,
    result_checks: bool,
    initial_registers: usize,
    memory_regions: usize,
    code_patches: usize,
    result_timeout: Option<std::time::Duration>,
    behavior_check: String,
}

impl SessionInfo {
    /// Describes how attack success is detected for the loaded target.
    fn detection_mode(&self) -> &'static str {
        if self.result_checks {
            "result_checks (register values at address)"
        } else if !self.success_addresses.is_empty() || !self.failure_addresses.is_empty() {
            "success/failure addresses"
        } else {
            "MMIO marker writes to 0x0AA01000 (instrumented target)"
        }
    }
}

/// State for a loaded simulation session
struct Session {
    attack_sim: FaultAttacks,
    info: SessionInfo,
}

// SAFETY: FaultAttacks contains raw pointers from unicorn-engine and capstone.
// All access is protected by a tokio::sync::Mutex, ensuring exclusive access.
unsafe impl Send for Session {}

/// MCP Server for the Fault Injection Simulator
struct FaultSimulatorServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    session: Mutex<Option<Session>>,
}

// --- Tool parameter types ---

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct LoadElfParams {
    /// Path to the ELF file to load. Optional when `config_file`/`config_json5` sets `elf`.
    #[serde(default)]
    elf_path: Option<String>,
    /// Path to a JSON5 configuration file (same schema as the CLI `--config` option).
    /// Use it for advanced setups: initial_registers, memory_regions, result_checks, code_patches.
    #[serde(default)]
    config_file: Option<String>,
    /// Inline JSON5 configuration content (same schema as `config_file`).
    /// Enables analysis of uninstrumented binaries without writing a file to disk.
    #[serde(default)]
    config_json5: Option<String>,
    /// Number of parallel threads (default: number of CPU cores)
    #[serde(default)]
    threads: Option<usize>,
    /// Maximum number of instructions to execute (default: 2000)
    #[serde(default)]
    max_instructions: Option<usize>,
    /// Enable deep analysis of loops
    #[serde(default)]
    deep_analysis: Option<bool>,
    /// Memory addresses that indicate attack success (hex strings like "0x8000123")
    #[serde(default)]
    success_addresses: Option<Vec<String>>,
    /// Memory addresses that indicate attack failure (hex strings like "0x8000789")
    #[serde(default)]
    failure_addresses: Option<Vec<String>>,
    /// Skip program behavior validation
    #[serde(default)]
    no_check: Option<bool>,
    /// Seconds to wait for a worker result before aborting a campaign (0 = wait forever).
    /// Raise it on slow or heavily loaded machines. Default: 120 s.
    #[serde(default)]
    result_timeout_seconds: Option<u64>,
    /// Code patches to apply: list of {address: "0x...", data: "0x..."} or {symbol: "name", data: "0x..."}
    #[serde(default)]
    code_patches: Option<Vec<HashMap<String, String>>>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct RunAttackParams {
    /// Attack class: "all", "single", or "double"
    class: String,
    /// Optional subclass filter: "glitch", "regbf", "regfld", "cmdbf"
    #[serde(default)]
    subclass: Option<Vec<String>>,
    /// Continue simulation after finding first success
    #[serde(default)]
    run_through: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct RunFaultsParams {
    /// One ordered fault sequence, e.g. ["glitch_1", "regbf_r1_00000100"].
    /// All entries are injected together, with eligible locations found recursively.
    faults: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct AnalyzeAttackParams {
    /// 1-based attack number to analyze
    attack_number: usize,
    /// Maximum number of output lines to return (default: unlimited)
    #[serde(default)]
    max_lines: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct GetTraceParams {
    /// Maximum number of output lines to return (default: unlimited)
    #[serde(default)]
    max_lines: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct GetResultsParams {
    /// Maximum number of output lines to return (default: unlimited)
    #[serde(default)]
    max_lines: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct CompileParams {
    /// Directory containing the Makefile (default: "content")
    #[serde(default)]
    directory: Option<String>,
    /// Run `make clean` before building (default: true)
    #[serde(default)]
    clean: Option<bool>,
    /// Path of the ELF that is expected after a successful build
    /// (default: "<directory>/bin/aarch32/victim.elf")
    #[serde(default)]
    expected_elf: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct GetSymbolsParams {
    /// ELF file to inspect. Defaults to the ELF of the current session.
    /// Provide it to inspect a binary before calling load_elf.
    #[serde(default)]
    elf_path: Option<String>,
    /// Case-insensitive substring filter on the symbol name
    #[serde(default)]
    filter: Option<String>,
    /// Maximum number of symbols to return (default: 200)
    #[serde(default)]
    limit: Option<usize>,
}

#[tool_router]
impl FaultSimulatorServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            session: Mutex::new(None),
        }
    }

    /// List all available fault types with their parameter variations.
    /// Returns the complete list of fault specifications that can be used with run_faults.
    #[tool(name = "list_fault_types")]
    async fn list_fault_types(&self) -> Result<CallToolResult, McpError> {
        let lists = get_fault_lists(&mut [].iter());
        let mut output = String::new();
        for (i, group) in lists.iter().enumerate() {
            output.push_str(&format!("Group {}:\n", i + 1));
            for fault in group {
                output.push_str(&format!("  {}\n", fault));
            }
            output.push('\n');
        }
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Load an ELF file and initialize the simulation environment.
    /// This must be called before running any attacks.
    ///
    /// Supports instrumented targets (MMIO success markers) as well as untouched
    /// production binaries via `success_addresses`/`failure_addresses` or via the
    /// `result_checks` mechanism of a JSON5 configuration.
    #[tool(name = "load_elf")]
    async fn load_elf(
        &self,
        Parameters(params): Parameters<LoadElfParams>,
    ) -> Result<CallToolResult, McpError> {
        // Start from a JSON5 configuration (file or inline) so that all advanced
        // options (initial_registers, memory_regions, result_checks, code_patches,
        // log_level) are available, then apply the explicit tool parameters on top.
        let mut config: Config = if let Some(path) = &params.config_file {
            Config::from_file(&PathBuf::from(path)).map_err(|e| {
                McpError::invalid_request(format!("Failed to load config file: {}", e), None)
            })?
        } else if let Some(text) = &params.config_json5 {
            json5::from_str::<Config>(text).map_err(|e| {
                McpError::invalid_request(format!("Failed to parse config_json5: {}", e), None)
            })?
        } else {
            json5::from_str::<Config>("{}").map_err(|e| {
                McpError::internal_error(format!("Failed to build default config: {}", e), None)
            })?
        };

        if let Some(elf_path) = &params.elf_path {
            config.elf = Some(PathBuf::from(elf_path));
        }
        if let Some(threads) = params.threads {
            config.threads = threads;
        }
        if let Some(max_instructions) = params.max_instructions {
            config.max_instructions = max_instructions;
        }
        if let Some(deep_analysis) = params.deep_analysis {
            config.deep_analysis = deep_analysis;
        }
        if let Some(no_check) = params.no_check {
            config.no_check = no_check;
        }
        if let Some(result_timeout) = params.result_timeout_seconds {
            config.result_timeout = result_timeout;
        }
        if let Some(addresses) = &params.success_addresses {
            config.success_addresses = addresses.iter().filter_map(|s| parse_hex_u64(s)).collect();
        }
        if let Some(addresses) = &params.failure_addresses {
            config.failure_addresses = addresses.iter().filter_map(|s| parse_hex_u64(s)).collect();
        }
        if let Some(patches) = &params.code_patches {
            config.code_patches = patches
                .iter()
                .filter_map(|patch| {
                    let data_str = patch.get("data")?;
                    let data_hex = data_str.strip_prefix("0x").unwrap_or(data_str);
                    let data = (0..data_hex.len())
                        .step_by(2)
                        .filter_map(|i| u8::from_str_radix(&data_hex[i..i + 2], 16).ok())
                        .collect::<Vec<u8>>();
                    let offset = patch
                        .get("offset")
                        .and_then(|o| parse_hex_u64(o))
                        .unwrap_or(0);
                    if let Some(addr_str) = patch.get("address") {
                        Some(CodePatch {
                            address: Some(parse_hex_u64(addr_str)?),
                            symbol: None,
                            offset,
                            data,
                        })
                    } else {
                        patch.get("symbol").map(|symbol| CodePatch {
                            address: None,
                            symbol: Some(symbol.clone()),
                            offset,
                            data,
                        })
                    }
                })
                .collect();
        }

        let path = config.elf.clone().ok_or_else(|| {
            McpError::invalid_request(
                "No ELF file specified. Provide `elf_path` or an `elf` entry in the configuration.",
                None,
            )
        })?;

        // Load ELF file
        let mut file_data = ElfFile::new(path.clone())
            .map_err(|e| McpError::internal_error(format!("Failed to load ELF: {}", e), None))?;

        // Apply code patches
        if !config.code_patches.is_empty() {
            file_data.apply_patches(&config.code_patches).map_err(|e| {
                McpError::internal_error(format!("Failed to apply patches: {}", e), None)
            })?;
        }

        // Create simulation config
        let sim_config = SimulationConfig::new(
            config.max_instructions,
            config.deep_analysis,
            config.success_addresses.clone(),
            config.failure_addresses.clone(),
            config.initial_registers.clone(),
            config.memory_regions.clone(),
            config.log_level.clone(),
            config.result_checks.clone(),
        )
        .with_result_timeout(match config.result_timeout {
            0 => None,
            seconds => Some(std::time::Duration::from_secs(seconds)),
        });
        let result_timeout = sim_config.result_timeout;

        let threads = config.threads;
        let no_check = config.no_check;

        // Create threads and run behavior check — capture all stdout output
        // to prevent library println! calls from corrupting the JSON-RPC stream.
        let (init_output, init_result) = capture_stdout_with_result(|| {
            let user_thread = Arc::new(SimulationThread::new_with_threads(
                sim_config, &file_data, threads,
            )?);

            let attack_sim =
                FaultAttacks::new_with_threads(&file_data, Arc::clone(&user_thread), threads)?;

            // Check behavior
            let behavior = if no_check {
                None
            } else {
                Some(attack_sim.check_for_correct_behavior())
            };

            Ok::<_, SimulatorError>((attack_sim, behavior))
        });

        let (attack_sim, behavior) = init_result.map_err(|e| {
            McpError::internal_error(format!("Failed to initialize simulation: {}", e), None)
        })?;

        let behavior_check = match behavior {
            None => "SKIPPED (no_check)".to_string(),
            Some(Ok(())) => "OK".to_string(),
            Some(Err(e)) => format!("FAILED: {}", e),
        };

        let info = SessionInfo {
            elf_path: path.display().to_string(),
            threads,
            max_instructions: config.max_instructions,
            deep_analysis: config.deep_analysis,
            no_check,
            success_addresses: config.success_addresses.clone(),
            failure_addresses: config.failure_addresses.clone(),
            result_checks: config.result_checks.is_some(),
            initial_registers: config.initial_registers.len(),
            memory_regions: config.memory_regions.len(),
            code_patches: config.code_patches.len(),
            result_timeout,
            behavior_check: behavior_check.clone(),
        };
        let detection_mode = info.detection_mode();

        let warning = if behavior_check.starts_with("FAILED") {
            "\nWARNING: the baseline behavior check failed. Attack results are not meaningful \
             until the success/failure criteria and the target setup are correct. \
             Use get_trace and get_symbols to diagnose.\n"
        } else {
            ""
        };

        let summary = format!(
            "ELF loaded: {}\nThreads: {}\nMax instructions: {}\nDeep analysis: {}\n\
             Success detection: {}\nCode patches applied: {}\nInitial registers: {}\n\
             Memory regions: {}\nBehavior check: {}\n{}{}",
            info.elf_path,
            info.threads,
            info.max_instructions,
            info.deep_analysis,
            detection_mode,
            info.code_patches,
            info.initial_registers,
            info.memory_regions,
            behavior_check,
            warning,
            init_output
        );

        *self.session.lock().unwrap() = Some(Session { attack_sim, info });

        Ok(CallToolResult::success(vec![Content::text(summary)]))
    }

    /// Run class-based fault attacks (single or double).
    /// Requires load_elf to be called first.
    #[tool(name = "run_attack")]
    async fn run_attack(
        &self,
        Parameters(params): Parameters<RunAttackParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut session_guard = self.session.lock().unwrap();
        let session = session_guard.as_mut().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let run_through = params.run_through.unwrap_or(false);
        let class_vec: Vec<String> = {
            let mut v = vec![params.class.clone()];
            if let Some(sub) = &params.subclass {
                v.extend(sub.clone());
            }
            v
        };

        let subclass = if class_vec.len() > 1 {
            &class_vec[1..]
        } else {
            &[]
        };

        let (output, run_result) =
            capture_stdout_with_result(|| match class_vec.first().map(|s| s.as_str()) {
                Some("all") | None => {
                    session
                        .attack_sim
                        .single(subclass, run_through)
                        .and_then(|result| {
                            if result.0 {
                                Ok(())
                            } else {
                                session.attack_sim.double(subclass, run_through).map(|_| ())
                            }
                        })
                }
                Some("single") => session.attack_sim.single(subclass, run_through).map(|_| ()),
                Some("double") => session.attack_sim.double(subclass, run_through).map(|_| ()),
                Some(other) => Err(SimulatorError::config(format!(
                    "Unknown attack class '{}'. Use \"single\", \"double\" or \"all\".",
                    other
                ))),
            });

        run_result.map_err(|e| {
            McpError::internal_error(format!("Attack campaign failed: {}", e), None)
        })?;

        let num_attacks = session.attack_sim.fault_data.len();
        let count = session.attack_sim.count_sum;
        let limit_report = session
            .attack_sim
            .instruction_limit_report()
            .map(|r| format!("\n{}", r))
            .unwrap_or_default();

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}\nSuccessful attacks: {}\nOverall tests executed: {}{}",
            output, num_attacks, count, limit_report
        ))]))
    }

    /// Run one specific, ordered fault sequence.
    /// Requires load_elf to be called first.
    #[tool(name = "run_faults")]
    async fn run_faults(
        &self,
        Parameters(params): Parameters<RunFaultsParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut session_guard = self.session.lock().unwrap();
        let session = session_guard.as_mut().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        if params.faults.is_empty() {
            return Err(McpError::invalid_request(
                "Provide at least one fault specification.",
                None,
            ));
        }

        let fault_types: Vec<FaultType> = params
            .faults
            .iter()
            .map(|fault| {
                get_fault_from(fault).map_err(|_| {
                    McpError::invalid_request(
                        format!("Invalid fault specification: `{}`.", fault),
                        None,
                    )
                })
            })
            .collect::<Result<_, _>>()?;

        let (output, run_result) = capture_stdout_with_result(|| {
            session
                .attack_sim
                .fault_simulation(&[fault_types])
                .map(|_| ())
        });

        run_result.map_err(|e| {
            McpError::internal_error(format!("Fault simulation failed: {}", e), None)
        })?;

        let num_attacks = session.attack_sim.fault_data.len();
        let count = session.attack_sim.count_sum;
        let limit_report = session
            .attack_sim
            .instruction_limit_report()
            .map(|r| format!("\n{}", r))
            .unwrap_or_default();

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}\nSuccessful attacks: {}\nOverall tests executed: {}{}",
            output, num_attacks, count, limit_report
        ))]))
    }

    /// Get a summary of all successful attacks found so far.
    /// Returns the disassembled fault data for each successful attack.
    #[tool(name = "get_results")]
    async fn get_results(
        &self,
        Parameters(params): Parameters<GetResultsParams>,
    ) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let num_attacks = session.attack_sim.fault_data.len();
        if num_attacks == 0 {
            return Ok(CallToolResult::success(vec![Content::text(
                "No successful attacks found.",
            )]));
        }

        let output = capture_stdout(|| {
            session.attack_sim.print_fault_data();
        });

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Successful attacks: {}\nOverall tests executed: {}\n\n{}",
            num_attacks,
            session.attack_sim.count_sum,
            truncate_output(&output, params.max_lines)
        ))]))
    }

    /// Get detailed execution trace analysis for a specific successful attack.
    /// Shows the full instruction-by-instruction trace with fault injection points.
    #[tool(name = "analyze_attack")]
    async fn analyze_attack(
        &self,
        Parameters(params): Parameters<AnalyzeAttackParams>,
    ) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let num_attacks = session.attack_sim.fault_data.len();
        if num_attacks == 0 {
            return Ok(CallToolResult::success(vec![Content::text(
                "No successful attacks to analyze.",
            )]));
        }

        if params.attack_number == 0 || params.attack_number > num_attacks {
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Invalid attack number {}. Valid range: 1-{}",
                params.attack_number, num_attacks
            ))]));
        }

        let attack_number = params.attack_number;
        let (output, trace_result) =
            capture_stdout_with_result(|| session.attack_sim.print_trace_for_fault(attack_number));

        trace_result.map_err(|e| McpError::internal_error(format!("Trace failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(
            truncate_output(&output, params.max_lines),
        )]))
    }

    /// Get the baseline execution trace without any fault injection.
    /// Useful for understanding normal program flow before analyzing attacks.
    #[tool(name = "get_trace")]
    async fn get_trace(
        &self,
        Parameters(params): Parameters<GetTraceParams>,
    ) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let (output, trace_result) =
            capture_stdout_with_result(|| session.attack_sim.print_trace());

        trace_result.map_err(|e| McpError::internal_error(format!("Trace failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(
            truncate_output(&output, params.max_lines),
        )]))
    }

    /// Get structured data about successful attacks in JSON format.
    /// Returns machine-readable attack data for automated processing.
    #[tool(name = "get_attack_data")]
    async fn get_attack_data(&self) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let fault_data = session.attack_sim.get_fault_data();
        if fault_data.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text("[]")]));
        }

        let mut attacks = Vec::new();
        for (i, element) in fault_data.iter().enumerate() {
            let mut faults = Vec::new();
            for fd in element {
                let address = fd.record.address();
                let fault_info = serde_json::json!({
                    "address": format!("0x{:08X}", address),
                    "source": source_location(&session.attack_sim.file_data, address),
                    "fault_type": format!("{:?}", fd.fault.fault_type),
                    "fault_index": fd.fault.index,
                    "original_instruction": format!("{:02X?}", fd.original_instruction),
                    "modified_instruction": format!("{:02X?}", fd.modified_instruction),
                });
                faults.push(fault_info);
            }
            attacks.push(serde_json::json!({
                "attack_number": i + 1,
                "faults": faults,
            }));
        }

        let json = serde_json::to_string_pretty(&attacks).unwrap_or_default();
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    /// Reset the current simulation session, clearing all attack results.
    /// The ELF file remains loaded. Use this to start a fresh attack campaign.
    #[tool(name = "reset_session")]
    async fn reset_session(&self) -> Result<CallToolResult, McpError> {
        let mut session_guard = self.session.lock().unwrap();
        if session_guard.is_none() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No session to reset.",
            )]));
        }
        // Drop and recreate is not straightforward, so clear the data
        if let Some(session) = session_guard.as_mut() {
            session.attack_sim.fault_data.clear();
            session.attack_sim.count_sum = 0;
            session.attack_sim.reset_run_statistics();
        }

        Ok(CallToolResult::success(vec![Content::text(
            "Session reset. Attack data cleared.",
        )]))
    }

    /// Report the state of the current session: loaded ELF, success detection mode,
    /// baseline behavior check result and the number of attacks found so far.
    #[tool(name = "get_status")]
    async fn get_status(&self) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let Some(session) = session_guard.as_ref() else {
            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::json!({ "loaded": false }).to_string(),
            )]));
        };

        let info = &session.info;
        let stats = session.attack_sim.run_statistics();
        let status = serde_json::json!({
            "loaded": true,
            "elf_path": info.elf_path,
            "threads": info.threads,
            "max_instructions": info.max_instructions,
            "deep_analysis": info.deep_analysis,
            "no_check": info.no_check,
            "detection_mode": info.detection_mode(),
            "success_addresses": info.success_addresses.iter().map(|a| format!("0x{:08X}", a)).collect::<Vec<_>>(),
            "failure_addresses": info.failure_addresses.iter().map(|a| format!("0x{:08X}", a)).collect::<Vec<_>>(),
            "result_checks": info.result_checks,
            "initial_registers": info.initial_registers,
            "memory_regions": info.memory_regions,
            "code_patches": info.code_patches,
            "result_timeout_seconds": info.result_timeout.map(|t| t.as_secs()),
            "behavior_check": info.behavior_check,
            "successful_attacks": session.attack_sim.fault_data.len(),
            "tests_executed": session.attack_sim.count_sum,
            "runs_completed": stats.runs,
            "runs_instruction_limit": stats.instruction_limit,
            "runs_instruction_limit_percent": (stats.instruction_limit_ratio() * 10.0).round() / 10.0,
            "runs_emulation_errors": stats.errors,
            "instruction_limit_report": session.attack_sim.instruction_limit_report(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&status).unwrap_or_default(),
        )]))
    }

    /// Re-run the baseline behavior check of the loaded target without fault injection.
    /// Confirms that the configured success/failure criteria detect both outcomes.
    #[tool(name = "check_behavior")]
    async fn check_behavior(&self) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let (output, result) =
            capture_stdout_with_result(|| session.attack_sim.check_for_correct_behavior());

        let verdict = match result {
            Ok(()) => "Behavior check: OK".to_string(),
            Err(e) => format!("Behavior check: FAILED: {}", e),
        };

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}\n{}",
            verdict, output
        ))]))
    }

    /// List the global symbols of an ELF file with their addresses.
    /// Use it to locate success/failure addresses in binaries that carry no
    /// simulator instrumentation, and to pick symbols for code patches.
    #[tool(name = "get_symbols")]
    async fn get_symbols(
        &self,
        Parameters(params): Parameters<GetSymbolsParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(200);
        let filter = params.filter.map(|f| f.to_lowercase());

        let collect = |file_data: &ElfFile| {
            let mut symbols: Vec<_> = file_data
                .symbol_map
                .iter()
                .filter(|(name, _)| {
                    !name.is_empty()
                        && filter
                            .as_ref()
                            .is_none_or(|f| name.to_lowercase().contains(f))
                })
                .map(|(name, symbol)| {
                    serde_json::json!({
                        "name": name,
                        "address": format!("0x{:08X}", symbol.st_value),
                        "entry_address": format!("0x{:08X}", symbol.st_value & !1),
                        "size": symbol.st_size,
                    })
                })
                .collect();
            symbols.sort_by_key(|s| s["address"].as_str().unwrap_or("").to_string());
            symbols
        };

        let symbols = if let Some(elf_path) = &params.elf_path {
            let file_data = ElfFile::new(PathBuf::from(elf_path)).map_err(|e| {
                McpError::invalid_request(format!("Failed to load ELF: {}", e), None)
            })?;
            collect(&file_data)
        } else {
            let session_guard = self.session.lock().unwrap();
            let session = session_guard.as_ref().ok_or_else(|| {
                McpError::invalid_request(
                    "No ELF loaded. Call load_elf first or pass `elf_path`.",
                    None,
                )
            })?;
            collect(&session.attack_sim.file_data)
        };

        let total = symbols.len();
        let result = serde_json::json!({
            "total": total,
            "shown": total.min(limit),
            "symbols": symbols.into_iter().take(limit).collect::<Vec<_>>(),
        });

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&result).unwrap_or_default(),
        )]))
    }

    /// Build the target program with `make`, so the investigation loop
    /// (edit C source -> compile -> load -> attack) runs without a shell.
    #[tool(name = "compile_target")]
    async fn compile_target(
        &self,
        Parameters(params): Parameters<CompileParams>,
    ) -> Result<CallToolResult, McpError> {
        let directory = params.directory.unwrap_or_else(|| "content".to_string());
        let clean = params.clean.unwrap_or(true);
        let expected_elf = params.expected_elf.unwrap_or_else(|| {
            format!("{}/bin/aarch32/victim.elf", directory.trim_end_matches('/'))
        });

        let mut report = String::new();

        if clean {
            let output = std::process::Command::new("make")
                .arg("clean")
                .current_dir(&directory)
                .output()
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to run 'make clean': {}", e), None)
                })?;
            report.push_str(&format!(
                "make clean: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let output = std::process::Command::new("make")
            .current_dir(&directory)
            .output()
            .map_err(|e| McpError::internal_error(format!("Failed to run 'make': {}", e), None))?;

        report.push_str(&format!(
            "make: {}\nstdout:\n{}\nstderr:\n{}\n",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));

        let elf_exists = std::path::Path::new(&expected_elf).exists();
        report.push_str(&format!(
            "Build {}. ELF '{}' {}.\n",
            if output.status.success() {
                "succeeded"
            } else {
                "FAILED"
            },
            expected_elf,
            if elf_exists { "exists" } else { "is MISSING" }
        ));

        Ok(CallToolResult::success(vec![Content::text(report)]))
    }
}

#[tool_handler]
impl ServerHandler for FaultSimulatorServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Fault Injection Simulator for ARM Cortex-M processors. \
                 Typical autonomous loop: compile_target (build the C target) -> \
                 load_elf (optionally with a JSON5 config providing initial_registers, \
                 memory_regions or result_checks for uninstrumented binaries) -> \
                 get_status/check_behavior (validate the baseline) -> get_trace \
                 (baseline program flow) -> run_attack or run_faults -> get_results, \
                 analyze_attack and get_attack_data to inspect results -> harden the \
                 source and repeat. get_symbols resolves addresses in binaries without \
                 simulator instrumentation.",
            )
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Disable colored output for clean MCP text
    std::env::set_var("NO_COLOR", "1");

    let server = FaultSimulatorServer::new();

    let transport = rmcp::transport::stdio();

    let service = server.serve(transport).await?;
    service.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_elf_params_deserialize_defaults() {
        let json = r#"{"elf_path": "test.elf"}"#;
        let params: LoadElfParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.elf_path.as_deref(), Some("test.elf"));
        assert!(params.config_file.is_none());
        assert!(params.config_json5.is_none());
        assert!(params.threads.is_none());
        assert!(params.max_instructions.is_none());
        assert!(params.deep_analysis.is_none());
        assert!(params.success_addresses.is_none());
        assert!(params.failure_addresses.is_none());
        assert!(params.no_check.is_none());
        assert!(params.code_patches.is_none());
    }

    #[test]
    fn test_load_elf_params_deserialize_full() {
        let json = r#"{
            "elf_path": "firmware.elf",
            "threads": 4,
            "max_instructions": 5000,
            "deep_analysis": true,
            "success_addresses": ["0x8000100", "0x8000200"],
            "failure_addresses": ["0x8000300"],
            "no_check": true,
            "code_patches": [
                {"address": "0x08000100", "data": "0x4770"},
                {"symbol": "check_secret", "data": "0xbf00"}
            ]
        }"#;
        let params: LoadElfParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.elf_path.as_deref(), Some("firmware.elf"));
        assert_eq!(params.threads, Some(4));
        assert_eq!(params.max_instructions, Some(5000));
        assert_eq!(params.deep_analysis, Some(true));
        assert_eq!(params.success_addresses.as_ref().unwrap().len(), 2);
        assert_eq!(params.failure_addresses.as_ref().unwrap().len(), 1);
        assert_eq!(params.no_check, Some(true));
        assert_eq!(params.code_patches.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_run_attack_params_deserialize() {
        let json = r#"{"class": "single", "subclass": ["glitch"], "run_through": true}"#;
        let params: RunAttackParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.class, "single");
        assert_eq!(params.subclass, Some(vec!["glitch".to_string()]));
        assert_eq!(params.run_through, Some(true));
    }

    #[test]
    fn test_run_attack_params_minimal() {
        let json = r#"{"class": "all"}"#;
        let params: RunAttackParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.class, "all");
        assert!(params.subclass.is_none());
        assert!(params.run_through.is_none());
    }

    #[test]
    fn test_run_faults_params_deserialize() {
        let json = r#"{"faults": ["glitch_1", "glitch_3", "regbf_r0_00000001"]}"#;
        let params: RunFaultsParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.faults.len(), 3);
        assert_eq!(params.faults[0], "glitch_1");
    }

    #[test]
    fn test_analyze_attack_params_deserialize() {
        let json = r#"{"attack_number": 5}"#;
        let params: AnalyzeAttackParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.attack_number, 5);
        assert!(params.max_lines.is_none());
    }

    #[test]
    fn test_config_json5_params_deserialize() {
        let json = r#"{"config_json5": "{ elf: 'firmware.elf', max_instructions: 500 }"}"#;
        let params: LoadElfParams = serde_json::from_str(json).unwrap();
        let config: Config = json5::from_str(params.config_json5.as_ref().unwrap()).unwrap();
        assert_eq!(config.max_instructions, 500);
        assert_eq!(config.elf, Some(PathBuf::from("firmware.elf")));
    }

    #[test]
    fn test_default_config_parses() {
        let config: Config = json5::from_str("{}").unwrap();
        assert_eq!(config.max_instructions, 2000);
        assert!(config.elf.is_none());
        assert!(config.result_checks.is_none());
    }

    #[test]
    fn test_truncate_output() {
        let text = "a\nb\nc\nd";
        assert_eq!(truncate_output(text, None), text);
        assert!(truncate_output(text, Some(2)).starts_with("a\nb\n..."));
        assert_eq!(truncate_output(text, Some(10)), text);
    }

    #[test]
    fn test_parse_hex_u64() {
        assert_eq!(parse_hex_u64("0x08000100"), Some(0x0800_0100));
        assert_eq!(parse_hex_u64("08000100"), Some(0x0800_0100));
        assert_eq!(parse_hex_u64("zzz"), None);
    }

    #[test]
    fn test_server_new() {
        let server = FaultSimulatorServer::new();
        // Session should start empty
        assert!(server.session.lock().unwrap().is_none());
    }

    #[test]
    fn test_server_get_info() {
        let server = FaultSimulatorServer::new();
        let info = server.get_info();
        // Verify capabilities include tools
        assert!(info.capabilities.tools.is_some());
    }

    #[tokio::test]
    async fn test_list_fault_types() {
        let server = FaultSimulatorServer::new();
        let result = server.list_fault_types().await.unwrap();
        let content = &result.content;
        assert!(!content.is_empty());
        // Check the text contains known fault types
        let text_content = content[0].raw.as_text().expect("Expected text content");
        assert!(text_content.text.contains("glitch"));
        assert!(text_content.text.contains("regbf"));
        assert!(text_content.text.contains("cmdbf"));
    }

    #[tokio::test]
    async fn test_reset_session_when_empty() {
        let server = FaultSimulatorServer::new();
        let result = server.reset_session().await.unwrap();
        let text_content = result.content[0]
            .raw
            .as_text()
            .expect("Expected text content");
        assert!(text_content.text.contains("No session to reset"));
    }
}
