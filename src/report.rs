use std::io::stdout;
use std::io::{self, Write};

use fault_simulator::error::SimulatorError;
use fault_simulator::prelude::FaultAttacks;

/// Handles all post-attack output: summary, analysis trace, and interactive analysis.
pub fn print_results(
    attack_sim: &FaultAttacks,
    analysis: bool,
    print_analysis: Option<usize>,
) -> Result<(), SimulatorError> {
    // Pretty print fault data
    attack_sim.print_fault_data();

    println!("Successful attacks {}", attack_sim.fault_data.len());
    println!("Overall tests executed {}", attack_sim.count_sum);

    // Print analysis for a specific attack number and exit
    if let Some(number) = print_analysis {
        if attack_sim.fault_data.is_empty() {
            println!("No successful attacks!");
        } else {
            attack_sim.print_trace_for_fault(number)?;
        }
        return Ok(());
    }

    if analysis {
        loop {
            if attack_sim.fault_data.is_empty() {
                println!("No successful attacks!");
                break;
            }
            print!("\nList trace for attack number : (Return for exit): ");
            stdout().flush().unwrap();
            let mut buffer = String::new();
            if io::stdin().read_line(&mut buffer).is_ok() {
                if let Ok(number) = buffer.trim().parse::<usize>() {
                    attack_sim.print_trace_for_fault(number)?;
                    continue;
                }
            }
            break;
        }
    }
    Ok(())
}
