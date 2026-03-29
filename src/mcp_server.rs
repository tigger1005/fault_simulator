use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;

use fault_simulator::prelude::*;

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
fn capture_stdout_with_result<F: FnOnce() -> T, T>(f: F) -> (String, T) {
    // Use a simple redirect approach: we run the closure and capture via gag
    // Since gag isn't available, we'll build output strings manually where possible
    // For complex print functions, we redirect by using a pipe
    use std::os::unix::io::FromRawFd;

    let mut output = String::new();

    // Create a pipe
    let (read_fd, write_fd) = {
        let mut fds = [0i32; 2];
        unsafe {
            libc::pipe(fds.as_mut_ptr());
        }
        (fds[0], fds[1])
    };

    // Save original stdout
    let original_stdout = unsafe { libc::dup(1) };

    // Redirect stdout to pipe write end
    unsafe {
        libc::dup2(write_fd, 1);
    }

    // Run the closure
    let result = f();

    // Flush stdout to ensure all data is written
    io::stdout().flush().ok();

    // Restore original stdout
    unsafe {
        libc::dup2(original_stdout, 1);
        libc::close(original_stdout);
        libc::close(write_fd);
    }

    // Read from pipe
    let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
    use std::io::Read;
    read_file.read_to_string(&mut output).ok();

    (output, result)
}

/// State for a loaded simulation session
struct Session {
    attack_sim: FaultAttacks,
}

// SAFETY: FaultAttacks contains raw pointers from unicorn-engine and capstone.
// All access is protected by a tokio::sync::Mutex, ensuring exclusive access.
unsafe impl Send for Session {}

/// MCP Server for the Fault Injection Simulator
struct FaultSimulatorServer {
    tool_router: ToolRouter<Self>,
    session: Mutex<Option<Session>>,
}

// --- Tool parameter types ---

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct LoadElfParams {
    /// Path to the ELF file to load
    elf_path: String,
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
    /// List of specific fault specifications, e.g. ["glitch_1", "regbf_r1_0100"]
    faults: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct AnalyzeAttackParams {
    /// 1-based attack number to analyze
    attack_number: usize,
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
    #[tool(name = "load_elf")]
    async fn load_elf(
        &self,
        Parameters(params): Parameters<LoadElfParams>,
    ) -> Result<CallToolResult, McpError> {
        let threads = params.threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });
        let max_instructions = params.max_instructions.unwrap_or(2000);
        let deep_analysis = params.deep_analysis.unwrap_or(false);
        let no_check = params.no_check.unwrap_or(false);

        let success_addresses: Vec<u64> = params
            .success_addresses
            .unwrap_or_default()
            .iter()
            .filter_map(|s| {
                let cleaned = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                u64::from_str_radix(cleaned, 16).ok()
            })
            .collect();

        let failure_addresses: Vec<u64> = params
            .failure_addresses
            .unwrap_or_default()
            .iter()
            .filter_map(|s| {
                let cleaned = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                u64::from_str_radix(cleaned, 16).ok()
            })
            .collect();

        // Parse code patches
        let code_patches: Vec<CodePatch> = params
            .code_patches
            .unwrap_or_default()
            .iter()
            .filter_map(|patch| {
                let data_str = patch.get("data")?;
                let data_hex = data_str.strip_prefix("0x").unwrap_or(data_str);
                let data = (0..data_hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&data_hex[i..i + 2], 16).ok())
                    .collect::<Vec<u8>>();
                if let Some(addr_str) = patch.get("address") {
                    let cleaned = addr_str
                        .strip_prefix("0x")
                        .or_else(|| addr_str.strip_prefix("0X"))
                        .unwrap_or(addr_str);
                    let address = u64::from_str_radix(cleaned, 16).ok()?;
                    let offset = patch
                        .get("offset")
                        .and_then(|o| {
                            let cleaned = o.strip_prefix("0x").unwrap_or(o);
                            u64::from_str_radix(cleaned, 16).ok()
                        })
                        .unwrap_or(0);
                    Some(CodePatch {
                        address: Some(address),
                        symbol: None,
                        offset,
                        data,
                    })
                } else if let Some(symbol) = patch.get("symbol") {
                    let offset = patch
                        .get("offset")
                        .and_then(|o| {
                            let cleaned = o.strip_prefix("0x").unwrap_or(o);
                            u64::from_str_radix(cleaned, 16).ok()
                        })
                        .unwrap_or(0);
                    Some(CodePatch {
                        address: None,
                        symbol: Some(symbol.clone()),
                        offset,
                        data,
                    })
                } else {
                    None
                }
            })
            .collect();

        let path = std::path::PathBuf::from(&params.elf_path);

        // Load ELF file
        let mut file_data = ElfFile::new(path)
            .map_err(|e| McpError::internal_error(format!("Failed to load ELF: {}", e), None))?;

        // Apply code patches
        if !code_patches.is_empty() {
            file_data.apply_patches(&code_patches).map_err(|e| {
                McpError::internal_error(format!("Failed to apply patches: {}", e), None)
            })?;
        }

        // Create simulation config
        let sim_config = SimulationConfig::new(
            max_instructions,
            deep_analysis,
            success_addresses,
            failure_addresses,
            HashMap::new(),
            vec![],
            "off".to_string(),
            None,
        );

        // Create threads and run behavior check — capture all stdout output
        // to prevent library println! calls from corrupting the JSON-RPC stream.
        let (init_output, init_result) = capture_stdout_with_result(|| {
            let user_thread = Arc::new(SimulationThread::new_with_threads(
                sim_config, &file_data, threads,
            )?);

            let attack_sim =
                FaultAttacks::new_with_threads(&file_data, Arc::clone(&user_thread), threads)?;

            // Check behavior
            if !no_check {
                let _ = attack_sim.check_for_correct_behavior();
            }

            Ok::<_, SimulatorError>(attack_sim)
        });

        let attack_sim = init_result.map_err(|e| {
            McpError::internal_error(format!("Failed to initialize simulation: {}", e), None)
        })?;

        *self.session.lock().unwrap() = Some(Session { attack_sim });

        let check_info = if no_check {
            "Behavior check skipped."
        } else {
            ""
        };

        Ok(CallToolResult::success(vec![Content::text(format!(
            "ELF loaded: {}\nThreads: {}\nMax instructions: {}\n{}{}\n",
            params.elf_path, threads, max_instructions, init_output, check_info
        ))]))
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

        let output = capture_stdout(|| match class_vec.first().map(|s| s.as_str()) {
            Some("all") | None => {
                if let Ok(result) = session.attack_sim.single(subclass, run_through) {
                    if !result.0 {
                        let _ = session.attack_sim.double(subclass, run_through);
                    }
                }
            }
            Some("single") => {
                let _ = session.attack_sim.single(subclass, run_through);
            }
            Some("double") => {
                let _ = session.attack_sim.double(subclass, run_through);
            }
            _ => println!("Unknown attack class!"),
        });

        let num_attacks = session.attack_sim.fault_data.len();
        let count = session.attack_sim.count_sum;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}\nSuccessful attacks: {}\nOverall tests executed: {}",
            output, num_attacks, count
        ))]))
    }

    /// Run specific fault sequences.
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

        let fault_types: Vec<Vec<FaultType>> = params
            .faults
            .iter()
            .filter_map(|arg| match get_fault_from(arg) {
                Ok(val) => Some(vec![val]),
                Err(_) => None,
            })
            .collect();

        if fault_types.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No valid fault types parsed from input.",
            )]));
        }

        let output = capture_stdout(|| {
            let _ = session.attack_sim.fault_simulation(&fault_types);
        });

        let num_attacks = session.attack_sim.fault_data.len();
        let count = session.attack_sim.count_sum;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}\nSuccessful attacks: {}\nOverall tests executed: {}",
            output, num_attacks, count
        ))]))
    }

    /// Get a summary of all successful attacks found so far.
    /// Returns the disassembled fault data for each successful attack.
    #[tool(name = "get_results")]
    async fn get_results(&self) -> Result<CallToolResult, McpError> {
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
            num_attacks, session.attack_sim.count_sum, output
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
        let output = capture_stdout(|| {
            let _ = session.attack_sim.print_trace_for_fault(attack_number);
        });

        Ok(CallToolResult::success(vec![Content::text(output)]))
    }

    /// Get the baseline execution trace without any fault injection.
    /// Useful for understanding normal program flow before analyzing attacks.
    #[tool(name = "get_trace")]
    async fn get_trace(&self) -> Result<CallToolResult, McpError> {
        let session_guard = self.session.lock().unwrap();
        let session = session_guard.as_ref().ok_or_else(|| {
            McpError::invalid_request("No ELF loaded. Call load_elf first.", None)
        })?;

        let output = capture_stdout(|| {
            let _ = session.attack_sim.print_trace();
        });

        Ok(CallToolResult::success(vec![Content::text(output)]))
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
                let fault_info = serde_json::json!({
                    "address": format!("0x{:08X}", fd.record.address()),
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
        }

        Ok(CallToolResult::success(vec![Content::text(
            "Session reset. Attack data cleared.",
        )]))
    }
}

#[tool_handler]
impl ServerHandler for FaultSimulatorServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "Fault Injection Simulator for ARM Cortex-M processors. \
                 Use load_elf to load a target binary, then run_attack or run_faults \
                 to execute fault injection campaigns. Use get_results, analyze_attack, \
                 and get_attack_data to inspect results. Use get_trace for baseline \
                 program flow analysis.",
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
        assert_eq!(params.elf_path, "test.elf");
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
        assert_eq!(params.elf_path, "firmware.elf");
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
