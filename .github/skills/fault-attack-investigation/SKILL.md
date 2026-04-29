---
name: fault-attack-investigation
description: "Use when: investigating fault attacks on C code, hardening C code against fault injection, analyzing fault injection vulnerabilities, performing fault attack simulations on ARM Cortex-M firmware, asking to test C code against glitch or bitflip attacks, or when C source code is provided for security analysis against hardware fault attacks. Triggers on phrases like 'investigate fault attacks', 'harden this C code', 'run fault simulation', 'fault injection analysis', 'check for fault vulnerabilities'."
---

# Fault Attack Investigation Skill

## Overview

This skill guides a complete fault injection investigation cycle: insert C code into the simulator, compile it, run attacks via the MCP server, analyze results, apply mitigation techniques, and iterate until the code is fully hardened — or until it is proven that no solution exists. The investigation ends with a written report.

**MCP server prefix:** `mcp_fault-simulat_` (all tool calls use this prefix)  
**Project root:** The directory containing `content/` and `src/` (the workspace root)  
**Target file:** `<project_root>/content/src/main.c` — this is the only file to edit  
**Compiled ELF:** `<project_root>/content/bin/aarch32/victim.elf`

---

## Constraints (Mandatory — Follow Strictly)

1. **No FIH_ library macros.** Do NOT use `FIH_CALL`, `FIH_RET`, `FIH_SUCCESS`, `FIH_FAILURE`, `fih_int`, `fih_uint`, `FIH_DECLARE`, `FIH_EQ`, `FIH_IF_UINT_EQUAL`, `FIH_IF_UINT_EQUAL_BODY_CHECK`, `FIH_PANIC`, `fih_delay()`, or any other symbol from `bootutil/fault_injection_hardening.h`.  
2. **Pure C only.** Hardening must be implemented with plain C constructs: structs, `volatile`, `__attribute__((noinline))`, `__attribute__((always_inline))`, `asm volatile`, and `#define` macros as shortcut aliases.  
3. **`#define` macros are allowed** only as shortcut aliases for pure C constructs — not as a replacement for reasoning through the hardening.  
4. **Do not look at or copy from example files.** The `content/src/examples/` directory and all `main_*.c` files are reference-only — never read them during an investigation.  
5. **Do not modify any file other than `content/src/main.c`** (and only if explicitly extending the framework is required, `content/include/common.h` — but this is almost never needed).  
6. **`decision_activation()` must remain** unless `no_check: true` is used (see §6.6).

---

## Phase 0 — Understand the Target Code

Before touching any tool:

1. **Read the provided C code.** If the user provides C source inline, treat it as the candidate `main.c` content.
2. Identify:
   - The `DECISION_DATA_STRUCTURE` macro usage: element type, success value, failure value.
   - How the comparison is performed (simple `==`, `memcmp`, struct field checks, etc.).
   - What `__SET_SIM_SUCCESS()` / `__SET_SIM_FAILED()` is called from.
   - Whether condition-gated success (`__SET_SIM_SUCCESS_WITH_CONDITION()`) is used.
   - Whether the code already includes any hardening constructs.
3. Note which simulator framework macros from `common.h` are in use.

---

## Phase 1 — Insert Code into the Simulator

### 1.1 Write `main.c`

Place the provided (or to-be-investigated) C code into `content/src/main.c`.

**Required structure of `main.c`:**

```c
#include "common.h"
#include "utils.h"
#include <stdint.h>
#include <stdbool.h>

// Define the decision data structure
// element_type: data type for the decision variable
// success_value: value indicating a successful authentication
// failure_value: value indicating failed authentication (initial value)
DECISION_DATA_STRUCTURE(uint32_t, 0x01234567, 0xFEFEFEFE);

// The start_success_handling function must be non-inlined
// and call __SET_SIM_SUCCESS() or __SET_SIM_SUCCESS_WITH_CONDITION()
__attribute__((noinline))
void start_success_handling(void)
{
    __SET_SIM_SUCCESS();
    while(1);
}

int main(void)
{
    decision_activation();  // Simulator baseline setup — keep unless using no_check

    // --- Security logic under investigation goes here ---

    __SET_SIM_FAILED();
    while(1);
}
```

**`common.h` simulator macros available (do not modify these):**

| Macro | Effect |
|-------|--------|
| `DECISION_DATA_STRUCTURE(type, success, failure)` | Declares `decisiondata` struct and `DECISION_DATA` alias |
| `DECISION_DATA` | The runtime decision variable (holds `failure_value` initially) |
| `decision_activation()` | Swaps `DECISION_DATA` to `success_value` for baseline path check |
| `__SET_SIM_SUCCESS()` | Marks simulation as "attack succeeded" |
| `__SET_SIM_FAILED()` | Marks simulation as "expected failure" |
| `__SET_SIM_CONDITION_TRUE()` | Arms the condition gate (`success_condition = 0x11111111`) |
| `__SET_SIM_SUCCESS_WITH_CONDITION()` | Signals success only if condition was armed (`success_condition == 0x11111111`) |

### 1.2 Compile

Run from the project root:

```bash
cd content && make clean && make
```

- Success: `content/bin/aarch32/victim.elf` is produced.
- On compiler error: fix `main.c` and retry.
- **Verify the ELF exists** before loading it into the simulator.

**Compiler flags used (important for understanding generated assembly):**
- `-O3` — Aggressive optimization; redundant checks WILL be removed unless `volatile` is used correctly.
- `-fno-inline` — Functions are NOT inlined unless marked `__attribute__((always_inline))`.
- `-march=armv8-m.main` — ARMv8-M Cortex-M33 Thumb instruction set.

---

## Phase 2 — Load and Baseline

### 2.1 Load the ELF

```
mcp_fault-simulat_load_elf(
  elf_path = "<absolute_project_root>/content/bin/aarch32/victim.elf",
  max_instructions = 2000
)
```

Use `no_check: true` only when the `DECISION_DATA_STRUCTURE` has identical success and failure values (§6.6).

### 2.2 Get the Baseline Trace

```
mcp_fault-simulat_get_trace()
```

From the trace:
- Map each C source line to its assembly address.
- Identify the key security instructions: `cmp`, `bne`/`beq`/`cbnz`/`cbz`, `ldr` of decision variables, `bl` calls.
- Note which registers hold the decision values at each branch.
- Record the addresses of comparison and branch instructions — these are the primary attack targets.

---

## Phase 3 — Run Attacks

### 3.1 Single Fault Campaign

```
mcp_fault-simulat_run_attack(class="single", run_through=true)
```

Always use `run_through: true` to find ALL vulnerabilities, not just the first.

### 3.2 Retrieve Results

```
mcp_fault-simulat_get_results()
```

If 0 attacks found → proceed to double fault campaign (§3.4).  
If attacks found → analyze each one before hardening.

### 3.3 Analyze Each Attack

For each successful attack (1-based index):

```
mcp_fault-simulat_analyze_attack(attack_number=N)
```

From the trace, determine:
- **What was faulted:** Which instruction at which address. Original opcode vs. faulted opcode.
- **Attack type:** `glitch_N` (NOP), `regbf_rX_MASK` (register bit-flip), `regfld_rX` (register flood), `cmdbf_MASK` (instruction bit-flip).
- **Effect:** What the fault changed about the program's state or control flow.
- **Root cause:** Which vulnerability class this exploits (see §7 — Root Cause Taxonomy).
- **Why it succeeds:** Trace through the post-fault execution step by step.

Also call:
```
mcp_fault-simulat_get_attack_data()
```
to get machine-readable JSON for structured analysis.

### 3.4 Double Fault Campaign

```
mcp_fault-simulat_run_attack(class="double", run_through=true)
```

Run this only after single attacks are at 0. Double faults test all pairs of fault types simultaneously. Also run targeted sub-campaigns:

```
mcp_fault-simulat_run_attack(class="double", subclass=["glitch"], run_through=true)
mcp_fault-simulat_run_attack(class="double", subclass=["cmdbf"], run_through=true)
```

Analyze double-fault attacks the same way as single-fault attacks. The root cause is typically that two independent weaknesses exist that can each be faulted simultaneously.

---

## Phase 4 — Hardening

Apply mitigations from `doc/Fault_Attack_Mitigation_Techniques.md`. Map each vulnerability to its fix.

### 4.1 Root Cause → Mitigation Mapping

| Root Cause | Mitigation Technique |
|---|---|
| Single branch instruction guards the whole decision | Redundant comparison chain (§2.5), multiple `&&` checks each testing a different field |
| Two adjacent comparisons skipped by one multi-instruction glitch | Branch separation via non-inlined function calls (§2.5) |
| Compiler caches the comparison value in a register — double check is vacuous | `volatile` on struct fields; test different fields (`val` vs `val_copy`) |
| `memcmp` size loaded once — glitching the load sets size=0 | Load size twice with `volatile`; cross-check; or eliminate `memcmp` entirely |
| Single `bl` call skipped — stale register is truthy | Inline comparisons as macros; put only the tail call in a non-inlined function |
| Pre-loaded function arguments corrupted before `bl` | Inline comparison chain so args are loaded incrementally, not all before `bl` |
| Fall-through from failure path to success path | Condition-gated success (§2.13) so fall-through finds unarmed gate |
| Single-field corruption of redundant struct goes undetected | Self-consistency validation (§2.11): check `val == val_copy ^ MASK` |
| Success reference data in memory enables pointer redirect attacks | Remove success value from data: use identical failure values + `no_check` (§6.6) |
| `while(1)` failure loop escapable with one glitch | Hardened failure loop with multiple `asm volatile ("b .")` instructions (§2.15) |
| Simple boolean (`0`/`1`) trivially flipped | Secure Boolean with equal-Hamming-weight constants (§2.1) |
| Loop terminates early due to counter fault | Secure Loop with up/down dual counter and post-loop validation (§2.2) |
| Return value via register attackable during register-to-memory transfer | Secure Return: pass `volatile BOOL *pfRet` pointer instead of returning value (§2.3) |

### 4.2 Standard Hardening Template (Starting Point)

When the original code has a simple scalar comparison, use this progression:

**Step 1 — Introduce redundant data type:**

```c
typedef struct {
    volatile uint32_t val;
    volatile uint32_t val_copy;  // val ^ MASK
} secure_uint;

#define MASK 0xA5C35A3C
#define secure_init(x) ((secure_uint){ (x), (x) ^ MASK })
```

**Step 2 — Self-consistency validator (always_inline):**

```c
__attribute__((always_inline))
static inline bool validate_secure(secure_uint x) {
    if (x.val != (x.val_copy ^ MASK)) {
        while(1);  // Halt on tamper — use hardened loop in production
    }
    return true;
}
```

**Step 3 — Branch separator (noinline):**

```c
__attribute__((noinline))
bool verify_delay(volatile uint32_t *v) {
    return (*v != 0);  // Always true; generates real instructions
}
```

**Step 4 — Non-inlined tail call (noinline):**

```c
__attribute__((noinline))
bool verify_copies_match(secure_uint *a, secure_uint *b) {
    return a->val_copy == b->val_copy;
}
```

**Step 5 — Condition-gated success:**

```c
// success_condition is declared in common.c and extern in common.h
// It is initialized to 0x22222222

__attribute__((noinline))
void start_success_handling(void) {
    __SET_SIM_SUCCESS_WITH_CONDITION();  // Only 0x11111111 is a real success
    while(1);
}
```

**Step 6 — The hardened comparison in `main()`:**

```c
int main(void) {
    decision_activation();

    secure_uint data   = secure_init(DECISION_DATA.val);   // Adjust to your type
    secure_uint target = secure_init(decisiondata.success_data_element.val);

    volatile uint32_t sep = 1;

    if (
        (data.val == target.val) &&                    // Check 1: primary
        verify_delay(&sep) &&                          // Separator
        (target.val == (data.val_copy ^ MASK)) &&      // Check 2: cross-redundancy
        verify_delay(&sep) &&                          // Separator
        validate_secure(data) &&                       // Check 3: self-consistency
        verify_copies_match(&data, &target)            // Check 4: tail call
    ) {
        __SET_SIM_CONDITION_TRUE();                    // Arm the gate
        start_success_handling();
    }

    __SET_SIM_FAILED();
    while(1);
}
```

> **Important:** Always adapt this template to the actual data type used in the investigation. If `element_type` is a struct, apply redundancy to each field independently.

### 4.3 Hardening for `memcmp`-Based Comparisons

If the original code uses `memcmp`:

1. **Do not use `memcmp` with a memory-loaded size.** Replace with:
   ```c
   volatile uint16_t size1 = decisiondata.decision_element_size;
   volatile uint16_t size2 = decisiondata.decision_element_size;
   if (size1 != size2 || size1 == 0) { while(1); }
   ```
2. **Replace `memcmp` with a constant-time byte-by-byte comparison** inside a Secure Loop (§2.2).
3. **Apply redundant checks** on the comparison result before branching.

### 4.4 Hardened Failure Loop

Replace every `while(1)` in security-critical failure/panic paths with:

```c
__attribute__((noreturn, noinline))
void security_panic(void) {
    __asm volatile ("security_panic_loop:");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    __asm volatile ("b security_panic_loop");
    while(1);
}
```

---

## Phase 5 — Recompile and Retest

After each hardening iteration:

1. Recompile: `cd content && make clean && make`
2. Verify ELF exists.
3. Load new ELF: `mcp_fault-simulat_load_elf(...)` (this also resets session)  
   OR: `mcp_fault-simulat_reset_session()` then `mcp_fault-simulat_load_elf(...)`
4. Re-run single attacks: `mcp_fault-simulat_run_attack(class="single", run_through=true)`
5. If single = 0: re-run double attacks.
6. If still > 0: go back to Phase 3 for analysis, then Phase 4 for more hardening.

---

## Phase 6 — Iteration Decision Logic

```
LOOP:
  Run single attacks
  IF single > 0:
    Analyze each attack → identify root cause
    Apply targeted hardening
    Recompile
    Reset + Reload ELF
    CONTINUE LOOP
  
  Run double attacks
  IF double > 0:
    Analyze each attack → identify root cause
    Apply targeted hardening (typically: add more separators, strengthen tail call)
    Recompile
    Reset + Reload ELF
    CONTINUE LOOP
  
  IF single = 0 AND double = 0:
    DONE → Write report

  IF same attacks persist after 3 hardening attempts with no improvement:
    ASSESS whether a solution is theoretically possible:
    - Is the entire comparison reducible to a single bit? (mathematical impossibility)
    - Is the compiler defeating ALL volatile protections? (verify with get_trace)
    - Has every element of the minimum effective hardened comparison (§2.14) been applied?
    If all elements applied and attacks remain: conclude with "no pure-C solution found" + explanation
```

### 6.1 Signs That More Hardening Is Needed (Double Fault)

After single faults = 0, double fault vulnerabilities indicate:
- Two independent weaknesses: the first fault bypasses check A, the second bypasses check B.
- Fix: add more `verify_delay()` separators, add a second condition-gate layer, or use Checkpoint Handling (§2.4).

### 6.2 When to Add Checkpoint Handling (§2.4)

If the code has a multi-step sequence (e.g., multiple function calls that must all execute):

```c
volatile uint16_t wCheckPoint = 0x1234;

// Before each step, increment. After each step, validate.
wCheckPoint++;
result = perform_step_1();
if (wCheckPoint != 0x1235) security_panic();

wCheckPoint++;
result = perform_step_2();
if (wCheckPoint != 0x1236) security_panic();
```

### 6.3 When to Use Secure Loop (§2.2)

If the hardened code contains any security-critical loop (byte-by-byte comparison, key processing):

```c
volatile uint16_t wi, wd;
for (wi = 0, wd = length; wi < length && wd > 0; wi++, wd--) {
    if (wi + wd != length) security_panic();
    // critical loop body
}
if ((wi != length) || (wd != 0)) security_panic();
```

### 6.4 When to Use Secure Boolean (§2.1)

When a boolean result variable controls access:

```c
typedef enum {
    BOOL_INIT  = 0x99,
    BOOL_FALSE = 0x3C,
    BOOL_TRUE  = 0x5A,
} SecBool;

// Use volatile SecBool for all security-critical flags
volatile SecBool result = BOOL_INIT;
```

### 6.5 When to Use Secure Return (§2.3)

When a function returns a security-critical value:

```c
// INSECURE:
bool check(void) { return result; }
volatile bool r = check(); // register r0 → r, attackable

// SECURE:
void check(volatile SecBool *pResult) {
    *pResult = BOOL_FALSE;
    // ... logic ...
    *pResult = BOOL_TRUE;
}
volatile SecBool r = BOOL_INIT;
check(&r);
```

### 6.6 Removing Success Reference Data from Memory

When the `DECISION_DATA_STRUCTURE` stores a success value that could be redirected to by a pointer fault:

```c
// Use identical failure values — no success reference in binary data section
#define FAILURE_VAL 0xFEFEFEFE
DECISION_DATA_STRUCTURE(uint32_t, FAILURE_VAL, FAILURE_VAL);
// Remove decision_activation() call
// Load with: no_check = true
```

Then compare `DECISION_DATA` against a `#define` compile-time constant (encoded in the instruction stream, not stored in memory):

```c
#define EXPECTED_SUCCESS 0x01234567
if (DECISION_DATA == EXPECTED_SUCCESS) { ... }
```

---

## Phase 7 — Report

After the investigation completes (either 0 attacks found or impossibility determined), write a report covering:

### Report Structure

```markdown
# Fault Attack Investigation Report

## 1. Executive Summary
- Target: description of the C code under investigation
- Attack classes tested: single / double, all subclasses
- Final result: N attacks before hardening → 0 attacks after (or "no solution found")
- Hardening severity: LOW / MEDIUM / HIGH / CRITICAL

## 2. Original Code Analysis
- Paste the original `main.c`
- Describe what it does and identify the security-critical path
- Note the DECISION_DATA_STRUCTURE configuration

## 3. Baseline Trace Analysis
- Key assembly excerpts from `get_trace`
- Map of C lines to assembly addresses for security-critical instructions

## 4. Vulnerabilities Found

For each successful attack:
### Attack #N — [Attack Type] at [address] ([source:line])
- **Fault:** `original_instruction` → NOP / modified opcode
- **Effect:** [what changed in state/registers]
- **Post-fault path:** [step-by-step why it reaches SUCCESS]
- **Root cause:** [vulnerability class from §4.1]

## 5. Hardening Applied
For each change to `main.c`:
- What was changed
- Which technique (cite §2.X from mitigation doc)
- Why this specific technique addresses the root cause

## 6. Verification Results
| Iteration | Single Attacks | Double Attacks | Key Change |
|-----------|---------------|----------------|------------|
| Original  | N             | N              | — |
| After v1  | N             | N              | Description |
| Final     | 0             | 0              | — |

## 7. Final Hardened `main.c`
Paste the complete final source code.

## 8. Why Each Element Is Necessary
For each hardening element, explain independently why removing it would re-introduce a vulnerability. Reference the attack(s) it defeats.

## 9. Conclusion
- Was a pure-C solution found? Yes/No
- If no: explain the theoretical limit
- Recommended next steps if applicable
```

---

## Phase 8 — Termination Without Solution

If after applying all elements from §2.14 (Minimum Effective Hardened Comparison) attacks still persist:

1. Use `mcp_fault-simulat_get_attack_data()` and `mcp_fault-simulat_analyze_attack()` to characterize every remaining attack precisely.
2. Check if the attack exploits a property outside the control of pure C (e.g., the compiler unconditionally eliminates a check at `-O3` even with `volatile`).
3. Verify the generated assembly via `get_trace` — confirm that the C code actually produces the expected separate branch instructions.
4. If assembly confirms the full 6-check chain is present yet attacks still succeed, document which attacks cannot be defeated and explain the fundamental limitation.
5. Write the report with section 9 concluding "No solution found" with specific reasoning.

---

## Quick Reference — MCP Tool Calls

```
mcp_fault-simulat_load_elf(elf_path, [max_instructions], [no_check])
mcp_fault-simulat_get_trace()
mcp_fault-simulat_run_attack(class, [subclass], [run_through])
mcp_fault-simulat_get_results()
mcp_fault-simulat_analyze_attack(attack_number)
mcp_fault-simulat_get_attack_data()
mcp_fault-simulat_list_fault_types()
mcp_fault-simulat_reset_session()
mcp_fault-simulat_run_faults(faults)
```

**Attack classes:** `"single"`, `"double"`, `"all"`  
**Subclass filters:** `"glitch"`, `"regbf"`, `"regfld"`, `"cmdbf"`

---

## Quick Reference — Mitigation Techniques

| Technique | Section | Use When |
|---|---|---|
| Secure Memory Compare (constant-time) | §1.1 | Any `memcmp` on security-critical data |
| Unconditional Flow (branchless) | §1.3 | Side-channel timing leak via branches |
| Variable Initialization | §1.4 | All security-relevant booleans and buffers |
| Secure Boolean | §2.1 | Boolean result variables controlling access |
| Secure Loop | §2.2 | Any security-critical loop |
| Secure Return Parameter | §2.3 | Functions returning security-critical values |
| Checkpoint Handling | §2.4 | Multi-step sequences where skipping a step is dangerous |
| Redundant Comparison + Branch Separation | §2.5 | Any security-critical branch (primary defence) |
| Causal Chain Check | §2.6 | Dispatch tables / functions that must only run in specific context |
| Function Signature Check | §2.7 | Functions that must not be called out of sequence |
| Condition-Gated Success | §2.13 | All success signaling (defeats fall-through and branch-skip) |
| Minimum Effective Hardened Comparison | §2.14 | Standard starting template for any comparison |
| Hardened Failure Loop | §2.15 | All panic/failure handlers |
| XOR-Masked Redundant Struct | §2.11 | Decision variables and comparison operands |

---

## Common Pitfalls

| Pitfall | Symptom | Fix |
|---|---|---|
| Compiler collapses double-check | Both comparisons use same cached register; single glitch bypasses both | Use `volatile` fields; test different fields (`val` vs `val_copy`) |
| Adjacent comparisons glitched together | One multi-NOP glitch skips two checks | Insert `__attribute__((noinline))` function call between them |
| All checks in one `noinline` function | Glitching `bl` skips ALL checks at once; stale `r0` may be truthy | Inline the chain; only the tail call should be `noinline` |
| Pre-loaded arguments corrupted | Arguments loaded into r0–r3 before `bl`; one ldr glitch corrupts all | Inline comparison chain; arguments loaded one per check |
| `memcmp` with size=0 | Size loaded once; glitching load gives size=0 → memcmp returns 0 | Double-load size with `volatile`; validate before calling |
| `while(1)` escapable | Single NOP glitch exits the loop | Hardened failure loop with multiple `asm volatile ("b .")` |
| Success value in memory | Pointer redirect fault reads success value | Remove success data: identical failure values + `no_check` |
| Missing `volatile` | Compiler eliminates "redundant" checks | Declare all security-critical variables `volatile` |

---

## Reference Documents

- `doc/MCP_Investigation_Guide.md` — Full MCP API reference, step-by-step workflow, hardening techniques (§7), common attack patterns (§8), report structure (§9).
- `doc/Fault_Attack_Mitigation_Techniques.md` — All 16 mitigation techniques with code patterns, simulator-tested pitfalls, and the minimum effective hardened comparison template (§2.14).
- `content/include/common.h` — Simulator framework macros: `DECISION_DATA_STRUCTURE`, `__SET_SIM_*`, `CHECKPOINT_*`.
- `content/include/utils.h` — Available utility declarations (`serial_puts`, custom `memcmp`/`memcpy`).
