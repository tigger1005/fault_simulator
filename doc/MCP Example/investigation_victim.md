# Fault Injection Investigation Report — `victim_.elf`

## 1. Executive Summary

**Target:** `victim_.elf` — ARM Cortex-M33 firmware performing a `memcmp`-based authentication check.

**Attack type:** Single glitch (1 NOP instruction replacement)

**Result:** **3 successful attacks** found in 35 tests. All 3 bypass the authentication using only a single-instruction glitch — the lowest-cost attack possible.

**Severity: CRITICAL** — The firmware's core security decision can be completely bypassed with minimal attacker effort.

---

## 2. Program Logic Under Test

The `main.c` code at lines 48–62:

```c
int main() {
    decision_activation();

    int res = memcmp(&decisiondata.data_element,
                     &decisiondata.success_data_element,
                     decisiondata.decision_element_size);        // line 51
    if (res == 0) {                                              // line 53
        serial_puts("Verification positive path  : OK\n");
        start_success_handling();  // → __SET_SIM_SUCCESS()
    } else {
        serial_puts("Verification negative path : OK\n");
        __SET_SIM_FAILED();
    }
    FIH_PANIC;
}
```

The `DECISION_DATA_STRUCTURE` macro initializes `decisiondata.data_element` with `FAILED_DATA` (byte 20 is `0x14` instead of `0x15`). So **normally** `memcmp` returns non-zero, taking the `else` (failure) path. The attacker needs `memcmp` to return 0 (or the branch to be skipped).

---

## 3. Detailed Attack Analysis

### Attack #1 — Glitch the `ldr` (size parameter corruption)

**Location:** `0x8000634` — `main.c` line 51
**Glitched instruction:** `ldr r2, [r1], #0x1c` → replaced with NOP

**What happens:**

- This instruction loads `decisiondata.decision_element_size` (= 24 = `0x18`) into `r2`, which becomes the `count` parameter for `memcmp`.
- When glitched to NOP, **`r2` stays at its previous value of 0**.
- `memcmp` is then called with `count = 0`.
- Comparing 0 bytes always returns 0.
- `res == 0` → success path taken.

**Trace evidence:**

```
0x8000632:  adds r0, r1, #4          R0=0x20000008 (str1)
-> Glitch (original: ldr r2, [r1], #0x1c)   ← r2 NOT loaded, stays 0
0x8000638:  bl   #0x80004a4          ← calls memcmp(str1, str2, 0)
  0x80004A6:  add r2, r0             R2=0x20000008 (end = str1 + 0)
  0x80004B8:  cmp r0, r2             ← 0x20000008 == 0x20000008, EQUAL!
  0x80004BA:  bne #0x80004ac         ← NOT taken (loop never entered)
  0x80004BC:  movs r0, #0            ← returns 0
```

**Root cause:** Single point of failure — the size parameter is loaded once and never validated.

---

### Attack #2 — Glitch the `bne` loop branch in `memcmp`

**Location:** `0x80004BA` — `utils.c` line 8
**Glitched instruction:** `bne #0x80004ac` → replaced with NOP

**What happens:**

- Inside `memcmp`, after comparing `r0` (current pointer) vs `r2` (end pointer), the `bne` branch re-enters the comparison loop.
- On the **first iteration**, before any byte is compared, the glitch replaces `bne` with NOP.
- The loop immediately falls through to `movs r0, #0` (return 0).
- `memcmp` returns 0 without comparing any bytes.

**Trace evidence:**

```
0x80004B8:  cmp r0, r2               R0=0x20000008, R2=0x20000020 (NOT equal)
-> Glitch (original: bne #0x80004ac)  ← branch NOT taken, falls through
0x80004BC:  movs r0, #0              ← returns 0 (success!)
```

**Root cause:** Standard `memcmp` has a single branch controlling the loop. Glitching one branch instruction skips all comparisons.

---

### Attack #3 — Glitch the `cbnz` result check in `main`

**Location:** `0x800063C` — `main.c` line 53
**Glitched instruction:** `cbnz r0, #0x8000650` → replaced with NOP

**What happens:**

- `memcmp` executes correctly and returns **non-zero** (data mismatches at byte 20).
- The `cbnz r0` (Compare and Branch if Not Zero) instruction in `main` should jump to the failure path.
- When glitched to NOP, execution falls through to the success path regardless of the `memcmp` result.

**Trace evidence:**

```
0x80004BA:  bne  #0x80004ac          ← memcmp loops normally...
  (compares all 24 bytes, finds mismatch at byte 20)
0x80004C4:  ...                      ← memcmp returns NON-ZERO
0x800063C:  cbnz r0, #0x8000650      R0=0x00000001
-> Glitch (original: cbnz r0, #0x8000650)  ← branch skipped!
0x800063E:  ldr  r0, [pc, #0x24]     ← falls into success path
0x8000644:  bl   #0x800048c          ← __SET_SIM_SUCCESS()
```

**Root cause:** The security decision (`if (res == 0)`) compiles to a single branch instruction. One NOP glitch bypasses it entirely.

---

## 4. Vulnerability Summary

| #   | Target                   | Location  | Technique                           | Root Cause                                      |
| --- | ------------------------ | --------- | ----------------------------------- | ----------------------------------------------- |
| 1   | `ldr r2` (size param)    | main.c:51 | NOP the size load → `memcmp(a,b,0)` | Size loaded once, no validation                 |
| 2   | `bne` (loop branch)      | utils.c:8 | NOP the loop → 0-iteration return   | Standard `memcmp` — single branch controls loop |
| 3   | `cbnz r0` (result check) | main.c:53 | NOP the branch → skip to success    | Single `if` compiles to single branch           |

**All 3 attacks succeed with a single 1-instruction glitch (glitch_1).** This is the weakest fault model — any of these vulnerabilities alone is sufficient for a full bypass.

---

## 5. Hardening Recommendations for `main.c`

### 5.1 — Use Fault Injection Hardened (FIH) comparison instead of `memcmp`

The codebase already includes `bootutil/fault_injection_hardening.h`. Use the FIH comparison primitives:

```c
// INSTEAD OF:
int res = memcmp(&decisiondata.data_element,
                 &decisiondata.success_data_element,
                 decisiondata.decision_element_size);
if (res == 0) { ... }

// USE:
fih_uint fih_rc = FIH_FAILURE;
fih_rc = fih_uint_encode(
    fih_mem_cmp(&decisiondata.data_element,
                &decisiondata.success_data_element,
                decisiondata.decision_element_size));
FIH_IF_UINT_EQUAL(fih_rc, FIH_SUCCESS)
FIH_IF_UINT_EQUAL_BODY_CHECK(fih_rc, FIH_SUCCESS)
{
    serial_puts("Verification positive path  : OK\n");
    start_success_handling();
}
else { ... }
```

This eliminates attacks #2 and #3 because:

- `fih_mem_cmp` uses redundant comparisons internally (attacks the loop differently)
- `FIH_IF_UINT_EQUAL` + `FIH_IF_UINT_EQUAL_BODY_CHECK` creates a **double-check** on the result, requiring 2 glitches instead of 1

### 5.2 — Validate the size parameter redundantly (eliminates Attack #1)

```c
volatile size_t size1 = decisiondata.decision_element_size;
volatile size_t size2 = decisiondata.decision_element_size;
if (size1 != size2 || size1 == 0) {
    FIH_PANIC;
}
```

Loading the size twice from memory via `volatile` means a single NOP glitch can only corrupt one load; the mismatch triggers a panic.

### 5.3 — Add Control Flow Integrity (CFI) checkpoints

The codebase already has `CHECKPOINT` macros. Use them:

```c
int main() {
    CHECKPOINT_INIT();
    decision_activation();
    CHECKPOINT();

    fih_uint fih_rc = FIH_FAILURE;
    fih_rc = fih_uint_encode(
        fih_mem_cmp(&decisiondata.data_element,
                    &decisiondata.success_data_element,
                    decisiondata.decision_element_size));
    CHECKPOINT();

    VALIDATE_CHECKPOINT(2);  // verify we reached here legitimately

    FIH_IF_UINT_EQUAL(fih_rc, FIH_SUCCESS)
    FIH_IF_UINT_EQUAL_BODY_CHECK(fih_rc, FIH_SUCCESS)
    {
        start_success_handling();
    }
    else {
        __SET_SIM_FAILED();
    }
    FIH_PANIC;
}
```

This ensures an attacker cannot skip instructions without the CFI counter becoming desynchronized.

### 5.4 — Summary of mitigations vs. attacks

| Mitigation                                             | Blocks Attack #1 | Blocks Attack #2 | Blocks Attack #3 |
| ------------------------------------------------------ | ---------------- | ---------------- | ---------------- |
| FIH memcmp (`fih_mem_cmp`)                             | —                | ✅                | —                |
| Double result check (`FIH_IF_UINT_EQUAL` + body check) | —                | —                | ✅                |
| Redundant size validation                              | ✅                | —                | —                |
| CFI checkpoints                                        | ✅                | ✅                | ✅                |

**Recommendation:** Apply **all four** mitigations. Each addresses a different class of vulnerability. Together they raise the minimum attack from a single glitch to requiring multiple precisely-timed glitches — a significantly harder attack.
