
# Fault Simulator
This project is used as a tool to simulate fault attacks to ARM-M processors (Thumb mode).
It includes a C project in the "content" folder which is loaded into the simulation.
Glitches are introduces in a range from 1 to 10 assembler commands, from 1 glitch to double glitching.

Attack 'C' project is in the folder "content". Current compiler flags are set to:

Code examples for main.c in content\src\examples

Found vulnerabilities can be analysed with the "--analysis" switch (beta version).

``` make
TARGET = armv8-m.main

CFLAGS = -c -O3 -fPIC -Iinclude \
         -g -gdwarf -Wno-unused-but-set-variable -fno-inline -fno-omit-frame-pointer \
         -fno-ipa-cp-clone -fno-ipa-cp -fno-common -fno-builtin -ffreestanding -fno-stack-protector \
         -Wall Wno-format-security \ -Wno-format-nonliteral -Wno-return-local-addr -Wno-int-to-pointer-cast \
         -march=$(TARGET) -DMCUBOOT_FIH_PROFILE_ON -DMCUBOOT_FIH_PROFILE_HIGH -DFAULT_INJECTION_TEST

CFLAGS_LD = -N -Wl,--build-id=none -fPIC -fPIE -g -gdwarf -Os -Wno-unused-but-set-variable \
            -Wno-return-local-addr -fno-inline -fno-ipa-cp-clone \
            -fno-ipa-cp -nostartfiles -nodefaultlibs
```

## Setup / Requirements
* Rust toolchain
  * Included crates:
    * unicorn-engine
    * elf
    * log
    * env_logger
    * capstone
    * indicatif
    * git-version
    * rayon
    * itertools
    * clap
* "gcc-arm-none-eabi" compiler toolchain
* make toolchain

## Execution

To run the simulation use the command `cargo run` or `./target/debug/unicorn_1`

Program parameters:

```
-t, --threads <THREADS>  Number of threads started in parallel [default: 1]
-n, --no-compilation     Suppress re-compilation of target program
    --attack <ATTACK>    Attacks to be executed. Possible values are: all, single, double, bit_flip [default: all]
    --faults <FAULTS>    Run a command line defined sequence of faults. Alternative to --attack [possible values: Glitch, Glitch2, Glitch3, Glitch4, Glitch5]
-a, --analysis           Activate trace analysis of picked fault
-l, --low-complexity     Switch on low complexity attack-scan (same addresses are discarded)
-m, --max_instructions   Maximum number of instructions to be executed. Required for longer code under investigation (Default value: 2000)
-h, --help               Print help
-V, --version            Print version
```
