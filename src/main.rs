#![allow(dead_code)]

//use log::debug;

mod simulation;
use simulation::Simulation;

fn main() {
    env_logger::init(); // Switch on with: RUST_LOG=debug cargo run

    // Load and parse elf file
    let mut simulation = Simulation::new(std::path::PathBuf::from("Content/bin/aarch32/bl1.elf"));

    // Setup simulation
    simulation.setup();

    // Check simulation
    /*
        # Check for correct system
            - Prepare system
            - Set state to positive run
                - Run
            - Check Success_State
            - Prepare system
            - Set state to negative run
                - Run
            - Check Failed_State
    */
    //simulation.check();

    //simulation.get_cycles();

    simulation.test();
}

/*
# Get address table
- Prepare system
- Set state to negative run
- Go with single step till Failed_State
    - Count Steps
    - Note all individual addresses into array

# NOP run
- Loop from Count 0..Steps
    - Prepare system
    - Set state to negative run
    - Run (Count)
        Check for ASM Cmd - 16/32 Bit
        Change to NOP
    - Run (1/2)
        Change back
    - Run till Success/Failed state
        If Success add to found list
- Repeat till end of loop

# Glitch run
- Loop from Count 0..Steps
    - Loop (16/32) according to cmd size
        - Prepare system
        - Set state to negative run
        - Run (Count)
            Check for ASM Cmd - 16/32 Bit
            Change (xor) bit in cmd
        - Run (1/2)
            Change back
        - Run till Success/Failed state
            If Success add to found list
- Repeat till end of loop

*/
