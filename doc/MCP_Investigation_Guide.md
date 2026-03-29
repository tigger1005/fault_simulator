# Fault Simulator MCP — AI Investigation Guide

This document describes the complete workflow for an AI agent to perform fault injection code investigations using the Fault Simulator MCP server. It covers the MCP API, compilation, code structure, attack execution, analysis, and hardening.

---

## 1. Overview

The Fault Simulator simulates hardware fault attacks (glitches, bit-flips, register floods) against ARM Cortex-M firmware (Thumb mode). The goal of an investigation is to:

1. Load a target C program as an ELF binary
2. Run fault injection campaigns (single and double faults)
3. Analyze successful attacks to understand vulnerabilities
4. Modify the C source code to harden against discovered attacks
5. Recompile and re-test until no attacks succeed

The simulator is exposed as an **MCP server** (`fault-simulat`) with tools accessible via the Model Context Protocol.

---

## 2. MCP API Reference

### 2.1 `load_elf` — Load ELF and Initialize Simulation

**Must be called first before any other tool.**

| Parameter           | Type     | Required | Default   | Description                                                                              |
| ------------------- | -------- | -------- | --------- | ---------------------------------------------------------------------------------------- |
| `elf_path`          | string   | **yes**  | —         | Absolute path to the ELF file                                                            |
| `threads`           | number   | no       | CPU cores | Parallel simulation threads                                                              |
| `max_instructions`  | number   | no       | 2000      | Max instructions per simulation run                                                      |
| `deep_analysis`     | boolean  | no       | false     | Enable deep analysis of loops                                                            |
| `success_addresses` | string[] | no       | []        | Hex addresses indicating attack success (e.g. `"0x8000123"`)                             |
| `failure_addresses` | string[] | no       | []        | Hex addresses indicating attack failure                                                  |
| `no_check`          | boolean  | no       | false     | Skip program behavior validation                                                         |
| `code_patches`      | object[] | no       | []        | Binary patches: `{address: "0x...", data: "0x..."}` or `{symbol: "name", data: "0x..."}` |

**When to use `no_check`:** When the `DECISION_DATA_STRUCTURE` does not contain a SUCCESS value (e.g. both values are identical failure values). Without `no_check`, the simulator verifies that the program can reach both the success and failure paths. This is useful when your hardening removes the success reference data from memory entirely (see Section 7.6).

**Example call:**
```json
{
  "elf_path": "/path/to/fault_simulator/content/bin/aarch32/victim.elf",
  "max_instructions": 2000
}
```

### 2.2 `get_trace` — Get Baseline Execution Trace

Returns the instruction-by-instruction trace of normal program execution (no faults). Use this to understand the program flow, identify security-critical instructions (comparisons, branches), and map source lines to assembly addresses.

**No parameters.**

### 2.3 `run_attack` — Run Fault Attack Campaign

| Parameter     | Type     | Required | Default   | Description                                          |
| ------------- | -------- | -------- | --------- | ---------------------------------------------------- |
| `class`       | string   | **yes**  | —         | `"all"`, `"single"`, or `"double"`                   |
| `subclass`    | string[] | no       | all types | Filter: `"glitch"`, `"regbf"`, `"regfld"`, `"cmdbf"` |
| `run_through` | boolean  | no       | false     | Continue after first success (find all attacks)      |

**Attack classes:**
- `"single"` — One fault per simulation (fastest, tests basic resilience)
- `"double"` — Two faults per simulation (tests against coordinated attacks)
- `"all"` — Run single first; if vulnerabilities found, also run double

**Subclass filters:**
- `"glitch"` — NOP 1–10 instructions (simulates voltage/clock glitches)
- `"regbf"` — Single-bit flip in registers R0–R12
- `"regfld"` — Flood register with 0x00000000 or 0xFFFFFFFF
- `"cmdbf"` — Single-bit flip in fetched instruction opcode

**Example:** Run all single attacks, finding all vulnerabilities:
```json
{
  "class": "single",
  "run_through": true
}
```

### 2.4 `run_faults` — Run Specific Fault Sequences

| Parameter | Type     | Required | Description                                           |
| --------- | -------- | -------- | ----------------------------------------------------- |
| `faults`  | string[] | **yes**  | List of fault specs, e.g. `["glitch_1", "glitch_10"]` |

**Fault specification syntax:**
- `glitch_N` — Skip N instructions (N = 1..10)
- `regbf_rX_YYYYYYYY` — XOR register X (0–12) with hex mask Y (single bit only)
- `regfld_rX_00000000` or `regfld_rX_FFFFFFFF` — Flood register X
- `cmdbf_YYYYYYYY` — XOR fetched instruction with hex mask Y (single bit only)

### 2.5 `get_results` — Get Attack Summary

Returns a disassembly-annotated summary of all successful attacks found. Each result shows the fault type, target address, and affected instructions.

**No parameters.**

### 2.6 `analyze_attack` — Get Detailed Attack Trace

| Parameter       | Type   | Required | Description                            |
| --------------- | ------ | -------- | -------------------------------------- |
| `attack_number` | number | **yes**  | 1-based index of the attack to analyze |

Returns a full instruction-by-instruction execution trace with fault injection points marked. This is the primary tool for understanding **why** an attack succeeds.

### 2.7 `get_attack_data` — Get Machine-Readable Attack Data

Returns JSON with structured data about each successful attack: addresses, fault types, original/modified instructions.

**No parameters.**

### 2.8 `list_fault_types` — List Available Fault Types

Returns all available fault specifications grouped by type.

**No parameters.**

### 2.9 `reset_session` — Clear Attack Results

Clears all attack data while keeping the ELF loaded. Use before running a new campaign on the same binary.

**No parameters.**

---

## 3. Project Structure

### 3.1 Directory Layout

```
content/                          ← C project root
├── Makefile                      ← Cross-compilation build system
├── include/
│   ├── common.h                  ← Simulator framework macros (DECISION_DATA_STRUCTURE, __SET_SIM_*)
│   ├── utils.h                   ← Utility function declarations (memcmp, serial output)
│   └── bootutil/
│       └── fault_injection_hardening.h  ← Existing FIH library (reference only)
├── src/
│   ├── main.c                    ← **THE FILE UNDER INVESTIGATION** (edit this)
│   ├── common.c                  ← Framework variable definitions
│   ├── utils.c                   ← memcmp, memcpy, serial output
│   ├── fault_injection_hardening.c ← FIH runtime (reference only)
│   └── examples/
│       ├── main_0.c              ← Simplest: uint32_t, no hardening
│       ├── main_1.c              ← uint32_t with naive double-check
│       ├── main_2.c              ← uint32_t with volatile constants
│       ├── main_3.c .. main_5.c  ← Various hardening approaches (reference)
└── bin/aarch32/
    ├── victim.elf                ← Compiled ELF (simulation target)
    ├── victim.bin                ← Binary output
    └── victim.lst                ← Disassembly listing
```

### 3.2 Key Files to Edit

- **`content/src/main.c`** — The primary file under investigation. This is where you write and modify the security logic using pure C.
- **`content/include/common.h`** — Framework macros. Rarely needs editing, but understand the simulator macros defined here.

### 3.3 Key Files to Read (Do Not Edit)

- **`content/include/common.h`** — Defines `DECISION_DATA_STRUCTURE`, `__SET_SIM_SUCCESS`, `__SET_SIM_FAILED`, `__SET_SIM_CONDITION_TRUE`, `__SET_SIM_SUCCESS_WITH_CONDITION`. These are the simulator's instrumentation hooks.
- **`content/include/bootutil/fault_injection_hardening.h`** — An existing FIH library for reference. You may study the *techniques* it uses (data redundancy, XOR masking, delayed comparison patterns), but the goal is to implement hardening in pure C rather than relying on pre-built library macros. The investigation should discover and validate hardening patterns from first principles.
- **`content/src/examples/`** — Reference implementations at various hardening levels. Useful for understanding problem progression.

---

## 4. Compilation

### 4.1 Prerequisites

- `arm-none-eabi-gcc` cross-compiler toolchain installed and on PATH

### 4.2 Build Commands

From the project root directory:

```bash
cd content && make clean && make
```

This compiles `content/src/main.c` (and other source files) into `content/bin/aarch32/victim.elf`.

**The ELF path for `load_elf` is:** `<project_root>/content/bin/aarch32/victim.elf`

### 4.3 Compiler Flags (Important for Understanding Assembly)

```
-O3                    ← Aggressive optimization (affects instruction ordering)
-fno-inline            ← Functions are NOT inlined (preserves bl/function calls)
-fno-omit-frame-pointer
-march=armv8-m.main    ← ARMv8-M Cortex-M33 Thumb instruction set
-DFAULT_INJECTION_TEST ← Enables simulator instrumentation macros (__SET_SIM_* etc.)
-DMCUBOOT_FIH_PROFILE_HIGH ← Enables FIH library features (available for reference)
```

**Key implication:** `-fno-inline` means `__attribute__((noinline))` functions generate actual `bl` instructions, creating function boundaries useful for security. Functions marked `__attribute__((always_inline))` are still inlined regardless.

---

## 5. Simulator Framework Concepts

### 5.1 The DECISION_DATA_STRUCTURE Macro

This macro defines the global data structure that the simulator uses to control program behavior:

```c
DECISION_DATA_STRUCTURE(element_type, success_value, failure_value);
```

- **`element_type`**: The data type used for the decision variable (e.g. `uint32_t`, or a custom struct)
- **`success_value`**: Value stored in `success_data_element` (used by `decision_activation()` during baseline check)
- **`failure_value`**: Value stored in `data_element` (the initial value the program sees) and `failure_data_element`

At program start, `DECISION_DATA` contains `failure_value`. The `decision_activation()` function swaps it to `success_value` during the simulator's baseline check. An attacker must make the program reach `__SET_SIM_SUCCESS()` despite `DECISION_DATA` holding `failure_value`.

**You can use any C data type** for `element_type` — plain integers, structs with redundant fields, etc. The choice of data type is part of the hardening investigation.

### 5.2 Success/Failure Markers

| Macro                                | Address Written     | Value                     | Meaning                                   |
| ------------------------------------ | ------------------- | ------------------------- | ----------------------------------------- |
| `__SET_SIM_SUCCESS()`                | `0xAA01000`         | `0x11111111`              | Attack succeeded (security bypassed)      |
| `__SET_SIM_FAILED()`                 | `0xAA01000`         | `0x22222222`              | Secure behavior (expected path)           |
| `__SET_SIM_CONDITION_TRUE()`         | `success_condition` | `0x11111111`              | Arms a condition gate variable            |
| `__SET_SIM_SUCCESS_WITH_CONDITION()` | `0xAA01000`         | `success_condition` value | Success only if condition was armed first |

### 5.3 The `--no-check` Pattern

When using `no_check: true` in `load_elf`:
- The `DECISION_DATA_STRUCTURE` can use identical failure values for both slots (no success reference data in memory)
- `decision_activation()` is not needed and should be removed
- This eliminates any success reference data from memory, reducing the attack surface
- The simulator skips verifying that the program can reach both paths

This is an advanced pattern — use it when your hardening design intentionally removes success reference data from the binary.

---

## 6. Step-by-Step Investigation Workflow

### Step 1: Read and Understand the Source Code

Read `content/src/main.c` to understand the security logic. Identify:
- What data type is used for the decision variable
- How the comparison is performed (simple `==`, struct field checks, etc.)
- What happens in the success and failure paths
- Whether condition-gated success is used
- What data is stored in memory (does the binary contain success reference values?)

### Step 2: Compile the Code

```bash
cd content && make clean && make
```

Verify the build succeeds and `content/bin/aarch32/victim.elf` is produced.

### Step 3: Load the ELF

Use `load_elf`:
```json
{
  "elf_path": "/absolute/path/to/content/bin/aarch32/victim.elf"
}
```

Add `"no_check": true` if the code uses the `--no-check` pattern (no success reference data stored in DECISION_DATA).

### Step 4: Get the Baseline Trace

Use `get_trace` to see the normal (non-faulted) execution. This shows:
- The instruction sequence from `main()` entry to termination
- Source file and line annotations
- Register values at each step
- The addresses of key comparison and branch instructions

**Study the trace carefully.** Map the C code logic to the assembly instructions.

### Step 5: Run Single Fault Attacks

```json
{
  "class": "single",
  "run_through": true
}
```

Use `run_through: true` to find ALL vulnerabilities, not just the first.

### Step 6: Analyze Results

If attacks succeed:

1. Use `get_results` to see a summary of all successful attacks
2. For each attack, use `analyze_attack` with the attack number to get the full trace
3. Identify the **root cause** of each vulnerability:
   - Which instruction was faulted?
   - What is the effect (skipped comparison, corrupted register, modified branch)?
   - Why does the remaining code fail to catch the fault?

### Step 7: Run Double Fault Attacks (if single attacks are clean)

```json
{
  "class": "double",
  "run_through": true
}
```

Double faults combine two independent faults. Even if single attacks fail, double attacks may succeed.

For thorough testing, also run specific double attack combinations:
```json
{
  "class": "double",
  "subclass": ["glitch"],
  "run_through": true
}
```
```json
{
  "class": "double",
  "subclass": ["cmdbf"],
  "run_through": true
}
```

### Step 8: Harden the Code

Based on the attack analysis, modify `content/src/main.c`. See Section 7 for hardening techniques.

### Step 9: Recompile and Re-test

After each modification:
1. Recompile: `cd content && make clean && make`
2. Load the new ELF: `load_elf` (or `reset_session` + `load_elf`)
3. Re-run the same attack campaign
4. Compare results — were vulnerabilities eliminated?

### Step 10: Iterate Until Secure

Repeat Steps 5–9 until:
- **Single attacks:** 0 successful across all fault types
- **Double attacks:** 0 successful across all fault types (or all tested combinations)

---

## 7. Hardening Techniques — Pure C Principles

The goal of hardening is to make the code resilient against single and double fault attacks using **pure C** constructs. Rather than relying on pre-built library macros, the investigation should discover and validate hardening patterns from first principles. After a successful hardening, the resulting patterns can optionally be distilled into reusable macros.

### 7.1 Data Redundancy (Store Every Value Twice)

A single fault can corrupt one memory location or register, but not two independent ones simultaneously. Store critical values redundantly using a struct:

```c
typedef struct {
    volatile uint32_t val;       // The actual value
    volatile uint32_t val_copy;  // The same value, transformed (e.g. XOR with a mask)
} secure_uint;

#define MASK 0xA5C35A3C
#define secure_init(x) ((secure_uint){ (x), (x) ^ MASK })
```

**Why it works:** An attacker corrupting `val` cannot simultaneously corrupt `val_copy` in a consistent way. Any single fault creates a detectable mismatch between the two representations.

**Key principle:** The copy should not be a plain duplicate but a transformation (XOR, complement, etc.) so that a single memory/bus fault affecting adjacent bytes doesn't corrupt both identically.

### 7.2 Redundant Comparison Chains

A single comparison compiles to a single branch instruction — trivially bypassed by one glitch. Chain multiple independent checks using `&&`:

```c
bool values_equal = 
    (a.val == b.val) &&
    (a.val_copy == b.val_copy) &&
    ((a.val ^ MASK) == (b.val ^ MASK));
```

Each `&&` operator generates a **separate branch instruction** in the compiled assembly. Glitching one branch only skips one check — the others still guard the result.

**Key principle:** Each check in the chain must test a **different aspect** of the data. Repeating the same comparison twice is less effective because the compiler may optimize it away or use cached register values.

### 7.3 Branch Separation (Inserting Code Between Checks)

If two comparison instructions are adjacent in memory, a single glitch spanning 2–3 instructions can skip both. Insert non-trivial code between checks to force spatial separation:

```c
bool check_passed = (a.val == b.val);

// Separation: non-trivial volatile code that generates real instructions
volatile uint32_t dummy = some_volatile_computation();
(void)dummy;

check_passed = check_passed && (a.val_copy == b.val_copy);
```

**More effective: Use a non-inlined function call** as a separator. A `bl` instruction (function call) creates a jump to a different code location, guaranteeing the two checks cannot be covered by a single contiguous NOP glitch:

```c
__attribute__((noinline)) bool verify_delay(void) {
    volatile uint32_t r = some_computation();
    return r != 0;  // Always returns true in normal operation
}

if ((a.val == b.val) && verify_delay() && (a.val_copy == b.val_copy)) { ... }
```

### 7.4 Non-Inlined Tail Call (Function Boundary as Security Barrier)

The final check in a comparison chain should be a **non-inlined function call**. This creates a function boundary (via `bl` instruction) that requires an independent glitch to bypass:

```c
__attribute__((noinline)) bool verify_copies_match(secure_uint *a, secure_uint *b) {
    return a->val_copy == b->val_copy;
}
```

**Why inline macros + non-inlined tail is the strongest pattern:**
- An **inline macro** expands in the caller — each `&&` generates its own branch. Arguments are not pre-loaded into a single register set, so corrupting one load only affects one check.
- A **non-inlined function** as the final check adds a code boundary. The attacker needs an independent glitch specifically targeting this function call.
- A **fully non-inlined comparison function** (all checks in one function) is weaker because: (a) all arguments must be pre-loaded into registers before the `bl` call, creating a concentrated vulnerability point, and (b) glitching the single `bl` instruction skips all checks at once.

### 7.5 Condition-Gated Success

Split the success signaling into two separate steps so that bypassing the `if` check alone is insufficient:

```c
extern volatile unsigned int success_condition;  // Defined in common.c, initialized to 0x22222222

if (all_checks_passed) {
    success_condition = 0x11111111;   // Step 1: Arm the gate INSIDE the if-body
    start_success_handling();
}

void start_success_handling(void) {
    // Step 2: Write success_condition's value — only 0x11111111 means success
    __SET_SIM_SUCCESS_WITH_CONDITION();
}
```

**Why it works:** Even if an attacker glitches past the `if` check and reaches `start_success_handling()`, the success marker won't be `0x11111111` because `success_condition` was never armed. The attacker would need an additional fault to also set the condition variable.

Use the framework macros `__SET_SIM_CONDITION_TRUE()` and `__SET_SIM_SUCCESS_WITH_CONDITION()` (from `common.h`) to implement this.

### 7.6 Removing Success Reference Data from Memory

If the binary contains the "correct" value in memory (e.g. `DECISION_DATA_STRUCTURE(uint32_t, 0x01234567, 0xFEFEFEFE)` stores `0x01234567`), an attacker can potentially corrupt the data pointer to read the success value instead. Remove it:

```c
#define FAILURE_VAL 0xFEFEFEFE
DECISION_DATA_STRUCTURE(uint32_t, FAILURE_VAL, FAILURE_VAL);
// Both slots contain the failure value — no success reference exists in memory
```

When using this pattern:
- Remove the `decision_activation()` call (it has no success value to swap in)
- Use `load_elf` with `"no_check": true` (the simulator can't verify the positive path)
- The comparison now checks `DECISION_DATA` against a compile-time constant that only exists in the instruction stream, not as data in memory

### 7.7 Self-Consistency Validation

After using data redundancy (7.1), periodically validate that the two representations are still consistent:

```c
__attribute__((always_inline)) static inline bool validate_secure(secure_uint x) {
    if (x.val != (x.val_copy ^ MASK)) {
        // Tampered — halt or trap
        while(1);  // Or trigger a panic loop
    }
    return true;
}
```

Insert this validation into the comparison chain as an additional `&&` check. It catches cases where a single fault corrupted one field without affecting the comparison result.

### 7.8 Summary: The Minimum Effective Hardened Comparison

Based on tested investigations, a fault-resistant comparison needs **all** of the following elements in the `&&` chain:

| #   | Check                                          | Technique                | Purpose                                         |
| --- | ---------------------------------------------- | ------------------------ | ----------------------------------------------- |
| 1   | `a.val == b.val`                               | Primary comparison       | Basic equality                                  |
| 2   | Non-inlined function call returning bool       | Branch separation (7.3)  | Prevents single glitch spanning checks 1+3      |
| 3   | Cross-validate: `b.val == (a.val_copy ^ MASK)` | Cross redundancy (7.1)   | Validates val against the OTHER variable's copy |
| 4   | Non-inlined function call returning bool       | Branch separation (7.3)  | Prevents single glitch spanning checks 3+5      |
| 5   | `validate_secure(a)`                           | Self-consistency (7.7)   | Catches single-field corruption                 |
| 6   | Non-inlined `verify_copies_match(&a, &b)`      | Tail call boundary (7.4) | Requires independent glitch to bypass           |

**All 6 elements are independently necessary.** Removing any one has been shown to re-introduce exploitable vulnerabilities (see `doc/MCP Example/investigation_main_5.md` for experimental proof).

### 7.9 Post-Investigation: Distilling Macros

Once you have a hardened pure C implementation with 0 successful attacks in both single and double campaigns, you can optionally:

1. Extract repeated hardening patterns into `#define` macros or `static inline` functions
2. Create a hardened data type (struct + init macro + comparison macro)
3. Verify the macro-based version still produces identical assembly and passes all tests

This approach ensures the macros are **derived from proven patterns** rather than assumed correct. The existing FIH library in `include/bootutil/fault_injection_hardening.h` can serve as a reference for how such macros might look, but the investigation should validate each pattern independently.

---

## 8. Common Attack Patterns to Watch For

### 8.1 Fall-Through Between Adjacent Code Paths

If the failure and success paths are adjacent in memory, a glitch at the boundary can cause execution to "fall through" from the failure path into the success path.

**Fix:** Condition-gated success (7.5) makes fall-through harmless.

### 8.2 Cached Register Values

The compiler may optimize a "double check" to compare against a cached register instead of re-loading the constant from memory. This makes the double check ineffective — both comparisons use the same corrupt value.

**Fix:** Use data redundancy (7.1) so each check tests a **different field** (`val` vs `val_copy`). Mark fields `volatile` to prevent caching.

### 8.3 Stale Return Values

When a non-inlined function returns `bool`, the register `r0` may contain a non-zero value from argument setup. Glitching the `bl` (function call) instruction means the comparison result is the stale register value — which may be non-zero (truthy).

**Fix:** Use inline comparison chains with a non-inlined tail call (7.4). Avoid putting ALL comparison logic in a single non-inlined function.

### 8.4 Command Bit-Flip on Comparison + Branch

A `cmdbf` attack can change the register operand of a `cmp` instruction AND the condition of a `beq`/`bne` branch, defeating simple comparisons.

**Fix:** Multiple redundant comparisons (7.2) with branch separation (7.3) between them. A single bit-flip can only affect one comparison in the chain.

### 8.5 Size Parameter Corruption (memcmp)

If `memcmp` is used, glitching the size-load instruction to NOP makes `memcmp` compare 0 bytes (always returns 0).

**Fix:** Load the size from memory twice (using `volatile`) and cross-check both loads before calling the comparison function. Or avoid `memcmp` entirely and use redundant field-by-field comparison.

### 8.6 Pre-Loaded Function Arguments

When calling a non-inlined function, ALL arguments are loaded into registers (r0–r3) BEFORE the `bl` instruction. A single glitch on one `ldm` or `ldr` instruction can cause the function to receive stale/wrong register values. If both arguments happen to be identical (e.g. from a previous load), all internal checks pass despite the fault.

**Fix:** Inline the comparison chain as a macro (7.4) so arguments are loaded incrementally, one per check. Only the final tail-call function receives pre-loaded arguments.

---

## 9. Typical Investigation Report Structure

When documenting an investigation, include:

1. **Executive Summary** — Starting code, goal, final result (attacks before/after)
2. **Original Code Analysis** — The C source and what it does
3. **Baseline Trace** — Key assembly excerpts from `get_trace`
4. **Vulnerabilities Found** — For each successful attack:
   - Attack type and location (address, source line)
   - What was faulted (original vs. modified instruction)
   - Step-by-step explanation of why the attack succeeds
   - Root cause
5. **Hardening Changes Applied** — What was changed and why
6. **Verification Results** — Attack counts before and after hardening
7. **Why Each Hardening Measure Matters** — Justify every change independently

---

## 10. Quick Reference: Full Investigation Session

```
1. Read content/src/main.c                      → Understand the code
2. cd content && make clean && make              → Compile
3. load_elf(elf_path="..victim.elf")             → Load into simulator
4. get_trace()                                   → Study normal execution
5. run_attack(class="single", run_through=true)  → Find single-fault vulns
6. get_results()                                 → Summary of attacks
7. analyze_attack(attack_number=1)               → Deep-dive attack #1
8. analyze_attack(attack_number=2)               → Deep-dive attack #2 (etc.)
9. run_attack(class="double", run_through=true)  → Find double-fault vulns
10. [Analyze double attacks similarly]
11. Edit content/src/main.c                      → Apply hardening
12. cd content && make clean && make             → Recompile
13. load_elf(elf_path="..victim.elf")            → Reload
14. run_attack(class="single", run_through=true) → Re-test single
15. run_attack(class="double", run_through=true) → Re-test double
16. Repeat 11–15 until 0 successful attacks
```

---

## 11. Example Code Progression (Reference)

The `content/src/examples/` directory contains implementations at increasing hardening levels. These show the *progression* of techniques, not a prescription:

| File       | Technique Summary                                                                             | Single Attacks | Double Attacks   |
| ---------- | --------------------------------------------------------------------------------------------- | -------------- | ---------------- |
| `main_0.c` | Plain `uint32_t`, single `==` comparison                                                      | Vulnerable     | Vulnerable       |
| `main_1.c` | Naive double-check (same comparison repeated)                                                 | 2 found        | 392+ found       |
| `main_2.c` | Volatile constants to prevent register caching                                                | Reduced        | Still vulnerable |
| `main_3.c` | Redundant data type with multi-check chain                                                    | 0 found        | Vulnerable       |
| `main_4.c` | Re-verification in success handler function                                                   | 0 found        | Reduced          |
| `main_5.c` | Full hardening: 6-check chain + non-inlined tail + condition gate + no success data in memory | **0 found**    | **0 found**      |

Study these to understand what worked and what failed, but implement your own hardening from pure C principles.

---

## 12. Important Notes

- **Always use `run_through: true`** when testing hardened code to ensure ALL attacks are found, not just the first.
- **Always test both single AND double attacks** for a complete assessment.
- **The order of checks matters** — each separate function call or branch-generating operation creates spatial separation in the compiled assembly.
- **Non-inlined functions create function boundaries** (via `bl` instruction), which require an independent glitch to bypass.
- **Inline macros/chains expand in the caller's context** — each `&&` generates its own branch. This is more secure than a non-inlined function because arguments don't need to be pre-loaded all at once.
- **Recompile after every change** — the assembly output determines security, not the C source alone.
- **Check the disassembly** (`content/bin/aarch32/victim.lst`) when in doubt about compiler behavior.
- **Use `volatile`** for security-critical variables to prevent the compiler from optimizing away redundant loads/stores.
- **Hardening is an empirical process** — the simulator is the ground truth. A change that looks secure in C may compile to vulnerable assembly. Test every iteration.
