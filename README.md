# Fault Simulator
This project is used as a tool to simulate fault attacks to ARM-M processors (Thumb mode).
Within the "content" folder, there is a C project that is loaded into the simulation environment.
Faults are introduces depending the predefined ranges or manualy. For the simulated attacks "all", "single" and "double", all implemented faults are executed till one leads to an successful attack.
(e.g. "--class double"). For specific cases the check of the C code operation can be disabled with the "--no-check" option. This will allow to remove for e.g. the SUCCESS_DATA from the file under attack.

Once a vulnerability is found, the attack command sequence can be further analyzed using the '--analysis' command line parameter.

![Ghidra Visualization](assets/fault_listing.png)
*Screenshot of the attack visualization with highlighted instructions.*

For fast reproduction of a successful attack, the faults can be setup with the --faults feature manualy.
(E.g. *"--faults glitch_1 glitch_10"* -a double attack with 1 and 10 instruction glitches)
Code examples for main.c are located at: "content\src\examples"

## Implemented Attacks

### 1. Glitch
Inject a program counter (PC) glitch (skips 1–10 assembly instructions).

**Syntax:**
- Attack class: `glitch`
- Specific attacks: `glitch_1`, `glitch_2`, ..., `glitch_10`

**Example:**
```bash
glitch_3  # Skips 3 instructions
```

### 2. Register Bit Flip (regbf)
Flip bits in registers R0–R12 using XOR with a hex mask (single-bit only).

**Syntax:**
- Attack class: `regbf`
- Specific attacks: `regbf_rX_YYYYYYYY` (X=0–12, Y=hex mask)

**Examples:**
```bash
regbf_r0_00000001  # Flip bit 0 of R0
regbf_r12_80000000  # Flip bit 31 of R12
```

### 3. Register Flood (regfld)
Flood a register with `0x00000000` or `0xFFFFFFFF`.

**Syntax:**
- Attack class: `regfld`
- Specific attacks: `regfld_rX_00000000`, `regfld_rX_FFFFFFFF`

**Example:**
```bash
regfld_r5_FFFFFFFF  # Set R5 to 0xFFFFFFFF
```

### 4. Command Fetch Bit Flip (cmdbf)
Flip bits in instructions during fetch (single-bit only).

**Syntax:**
- Attack class: `cmdbf`
- Specific attacks: `cmdbf_YYYYYYYY` (Y=hex mask)

**Example:**
```bash
cmdbf_00000001  # Flip bit 0 of the fetched instruction
```

## Compiler Configuration

The included C project (`/content`) is compiled with these flags:

```make
TARGET = armv8-m.main

CFLAGS = -c -O3 -Iinclude \
         -g -gdwarf -Wno-unused-but-set-variable -fno-inline -fno-omit-frame-pointer \
         -fno-ipa-cp-clone -fno-ipa-cp -fno-common -fno-builtin -ffreestanding -fno-stack-protector \
         -Wall -Wno-format-security -Wno-format-nonliteral -Wno-return-local-addr -Wno-int-to-pointer-cast \
         -march=$(TARGET) -DMCUBOOT_FIH_PROFILE_ON -DMCUBOOT_FIH_PROFILE_HIGH -DFAULT_INJECTION_TEST

CFLAGS_LD = -N -Wl,--build-id=none -g -gdwarf -Os -Wno-unused-but-set-variable \
            -Wno-return-local-addr -fno-inline -fno-ipa-cp-clone \
            -fno-ipa-cp -nostartfiles -nodefaultlibs
```

## Setup / Requirements
**Rust Toolchain**
- Included crates:
  - `unicorn-engine`
  - `elf`
  - `log`
  - `env_logger`
  - `capstone`
  - `indicatif`
  - `git-version`
  - `rayon`
  - `itertools`
  - `clap`

**Compiler Toolchain**
- `gcc-arm-none-eabi` compiler toolchain

**Build Tools**
- `make` toolchain

**Ghidra Trace Visualization**
- Ghidra 11.3 with PyGhidra mode.

## Usage

### Command-Line Options
| Flag/Option                    | Description |
|--------------------------------|-------------|
| `-t, --threads <THREADS>`      | Number of threads started in parallel [default: 1]. "-t 0" activate full thread usage |
| `-n, --no-compilation`         | Suppress re-compilation of target program |
| `--class <ATTACK>,<GROUPS>`    | Attack class to be executed. Possible values are: all, single, double [default: all]. GROUPS can be the names of the implemented attacks. E.g. --class single regbf separated by ' ' |
| `--faults <FAULTS>`            | Run a command line defined sequence of faults. Alternative to --attack. (E.g. --faults glitch_1 glitch_10). Current implemented fault attacks: <br> - glitch_1 .. glitch_10 <br> - regbf_r0_00000001 .. regbf_r12_80000000 <br> - regfld_r0_00000000 or regfld_r0_FFFFFFFF <br> - cmdbf_00000000 .. cmdbf_80000000 |
| `-a, --analysis`               | Activate trace analysis of picked fault |
| `-d, --deep-analysis`          | Check with deep analysis scan. Repeated code (e.g. loops) are fully analysed |
| `-m, --max_instructions`       | Maximum number of instructions to be executed. Required for longer code under investigation (Default value: 2000) |
| `--no_check`                   | Disable program flow check |
| `-e, --elf <FILE>`             | Use external elf file w/o compilation step |
| `--trace`                      | Trace and analyse program w/o fault injection |
| `-r, --run-through`            | Don't stop on first successful fault injection |
| `-h, --help`                   | Print help |
| `-V, --version`                | Print version |

### Examples

1. **Single glitch attack with trace analysis:**
   ```bash
   cargo run -- --class single glitch --analysis
   ```  

2. **Double attack (glitch + register flood) on custom ELF:**
   ```bash
   cargo run -- --class double glitch regfld --elf tests/bin/victim.elf -t 4
   ```
3. **Running a fault sequence with register bit-flip and glitch:**
   ```bash
   cargo run -- --faults regbf_r1_0100 glitch_1
   ```

## Ghidra Visualization

The Ghidra script you created enhances the visualization of the trace output generated by the simulator with the `-a, --analysis` option. 

**Usage:**

1.  Ensure Ghidra 11.3 is installed and running in PyGhidra mode as described in the [Ghidra Installation Guide](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_11.3_build/GhidraDocs/InstallationGuide.md#pyghidra-mode).
2. Start the script in Ghidra.
3. Paste the trace output from the simulation.
4. Observe the executed instructions highlighted in green and the faulted instruction in red.
5. Use the table window to step through the instruction trace.

**Visualization Example:**

![Ghidra Visualization](assets/ghidra_vis.png)
*Screenshot of the Ghidra visualization with highlighted instructions.*
