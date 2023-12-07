
# unicorn_1
This project is used as a tool to simulate fault attacks to ARM-M processors (Thumb mode).
It includes a C project in the "content" folder which is loaded into the simulation. 
Glitches are introduces in a range from 1 to 10 assembler commands, from 1 glitch to double glitching.

Attack 'C' project is in the folder "Content". Current compiler flags are set to:

Code examples for main.c in Content\src\examples


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

To run simulation

**"cargo run"**
**"./target/debug/unicorn_1"**

program parameters:

```
"--attack name"           [all], single, double, (bit_flip currently not supported)
"--threads number"        0-n [1] (If set to 0 framework choose number)
"--no_compilation bool"   [false] suppress compilation
```