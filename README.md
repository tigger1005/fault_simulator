
# Fault Simulator
This project is used as a tool to simulate fault attacks to ARM-M processors (Thumb mode).
It includes a C project in the "content" folder which is loaded into the simulation.
Faults are introduces depending the predefined ranges or manualy. For the simulated attacks "all", "single" and "double", all implemented faults are executed till one leads to an successful attack.
(e.g. "--attack double")

After finding a vulnerability the attack command sequence can be analysed with the '--analysis' command line parameter.
```ARM
Assembler trace of attack number 1
0x80000000:  bl     #0x80000638                                  < NZCV:0000 >
0x80000638:  push   {r4, r5, r7, lr}                             < NZCV:0000 R4=0x00000000 R5=0x00000000 R7=0x00000000 LR=0x80000005 >
0x8000063A:  sub    sp, #0x20                                    < NZCV:0000 SP=0x8010FFCC >
0x8000063C:  add    r7, sp, #0                                   < NZCV:0000 R7=0x8010FFCC SP=0x8010FFCC >
```

For fast reproduction of a successful attack, the faults can be setup with the --faults feature manualy.
(E.g. "--faults glitch_1,glitch_10" - a double attack with 1 and 10 instruction glitches)
Code examples for main.c are located at: "content\src\examples"


## Implemented attacks:
> 
> ### Glitch
> Insert a glitch to the program counter PC (1 to 10 assembler commands)
> 
> #### Syntax:
> **glitch_1 .. glitch_10**
> 
> ### Register Bit Flip
> Inserted a bit flip into a register. Registers from R0 to R12. 
> The bit flip is inserted via a XOR operation with the given hexadecimal value. Currently only single bits could be changed
> #### Syntax:
> **regbf_r0_00000001 .. regbf_r12_800000000**
>





### Compiler flags are set to:
The included main project is at the "content" folder.

```make
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

To run the simulation use the command `cargo run` or `./target/debug/fault_simulator

Program parameters:

```
-t, --threads <THREADS>       Number of threads started in parallel [default: 1]. "-t 0" activate full thread usage
                              
-n, --no-compilation          Suppress re-compilation of target program
    --class <ATTACK>,<GROUPS> Attack class to be executed. Possible values are: all, single, double [default: all]
                              GROUPS can be the names of the implemented attacks. E.g. **--class single,regbf** separated by ','
    --faults <FAULTS>         Run a command line defined sequence of faults. Alternative to --attack. (E.g. --faults glitch_1, glitch_10)
                              Current implemented fault attacks: glitch_1 .. glitch_10, regbf_r0_00000001 .. regbf_r12_80000000
-a, --analysis                Activate trace analysis of picked fault
-d, --deep-analysis           Check with deep analysis scan. Repeated code (e.g. loops) are fully analysed
-m, --max_instructions        Maximum number of instructions to be executed. Required for longer code under investigation (Default value: 2000)
-e, --elf <FILE>              Use external elf file w/o compilation step
    --trace                   Trace and analyse program w/o fault injection
-h, --help                    Print help
-V, --version                 Print version

Command line examples:
--class single
--class single,glitch --analysis
--class single,glitch,regbf --analysis
--class single,regbf --elf tests/bin/victim_4.elf --analysis -t 0
--faults regbf_r1_0100
```
