use std::sync::Arc;

use fault_simulator::config::Config;
use fault_simulator::error::SimulatorError;
use fault_simulator::prelude::*;

/// Creates simulation and attack threads, validates program behavior,
/// and runs the configured fault attack campaign.
///
/// Returns `None` if trace mode was selected (no results to report),
/// or `Some(FaultAttacks)` with the completed attack data.
pub fn run(config: Config, file_data: &ElfFile) -> Result<Option<FaultAttacks>, SimulatorError> {
    let analysis = config.analysis;
    let print_analysis = config.print_analysis;

    // Create simulation configuration
    let sim_config = SimulationConfig::new(
        config.max_instructions,
        config.deep_analysis,
        config.success_addresses,
        config.failure_addresses,
        config.initial_registers,
        config.memory_regions,
        config.log_level.clone(),
        config.result_checks,
    );

    // Create user thread for simulation
    let user_thread = Arc::new(SimulationThread::new_with_threads(
        sim_config,
        file_data,
        config.threads,
    )?);

    // Load victim data for attack simulation with dedicated fault attack threads
    let mut attack_sim =
        FaultAttacks::new_with_threads(file_data, Arc::clone(&user_thread), config.threads)?;

    // Check for correct program behavior
    if !config.no_check {
        println!("Check for correct program behavior:");
        attack_sim.check_for_correct_behavior()?;
    }

    // Check if trace is selected
    if config.trace {
        attack_sim.print_trace()?;
        return Ok(None);
    }

    println!("\nRun fault simulations:");

    // Run attack simulation
    if config.faults.is_empty() {
        let subclass = if config.class.len() > 1 {
            &config.class[1..]
        } else {
            &[]
        };
        match config.class.first().map(|s| s.as_str()) {
            Some("all") | None => {
                if !attack_sim.single(subclass, config.run_through)?.0 {
                    attack_sim.double(subclass, config.run_through)?;
                }
            }
            Some("single") => {
                attack_sim.single(subclass, config.run_through)?;
            }
            Some("double") => {
                attack_sim.double(subclass, config.run_through)?;
            }
            _ => println!("Unknown attack class!"),
        }
    } else {
        // Get fault type and numbers
        let fault_types: Vec<Vec<FaultType>> = config
            .faults
            .iter()
            .filter_map(|argument| match get_fault_from(argument) {
                Ok(val) => Some(vec![val]),
                Err(_) => None,
            })
            .collect();

        // Use threaded fault simulation for better performance
        let _result = attack_sim.fault_simulation(&fault_types)?;
    }

    // Print results and handle analysis options
    super::report::print_results(&attack_sim, analysis, print_analysis)?;

    Ok(Some(attack_sim))
}
