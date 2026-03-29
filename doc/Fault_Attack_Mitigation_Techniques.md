# Fault Attack Mitigation Techniques

Reference: *Sichere Implementierungen auf Mikrocontrollern (Secure C Coding Concepts)*

This document catalogs all fault attack mitigation techniques described in the presentation. Each technique includes a text description, a code-level description for AI-assisted implementation, and guidance on when and how to apply it.

---

## Table of Contents

- [Fault Attack Mitigation Techniques](#fault-attack-mitigation-techniques)
  - [Table of Contents](#table-of-contents)
  - [1. Observative Attack Mitigations](#1-observative-attack-mitigations)
    - [1.1 Secure Memory Compare](#11-secure-memory-compare)
    - [1.2 Secure Memory Copy](#12-secure-memory-copy)
    - [1.3 Unconditional Flow](#13-unconditional-flow)
    - [1.4 Variable Initialization](#14-variable-initialization)
    - [1.5 Statistic Data Hiding](#15-statistic-data-hiding)
    - [1.6 Mathematical Data Hiding](#16-mathematical-data-hiding)
    - [1.7 Random Delay Handling](#17-random-delay-handling)
  - [2. Semi-Invasive \& Manipulative Attack Mitigations](#2-semi-invasive--manipulative-attack-mitigations)
    - [2.1 Secure Boolean](#21-secure-boolean)
    - [2.2 Secure Loop](#22-secure-loop)
    - [2.3 Secure Return Parameter Handling](#23-secure-return-parameter-handling)
    - [2.4 Checkpoint Handling](#24-checkpoint-handling)
    - [2.5 Branch Protection](#25-branch-protection)
    - [2.6 Causal Chain Check](#26-causal-chain-check)
    - [2.7 Function Signature Check](#27-function-signature-check)
    - [2.8 Caller Gate Check](#28-caller-gate-check)
    - [2.9 Redundancy Call](#29-redundancy-call)
    - [2.10 Sentinel Handling](#210-sentinel-handling)
    - [2.11 Data Integrity Protection](#211-data-integrity-protection)
    - [2.12 Pre-Penalization](#212-pre-penalization)
    - [2.13 Condition-Gated Success](#213-condition-gated-success)
    - [2.14 Minimum Effective Hardened Comparison](#214-minimum-effective-hardened-comparison)
  - [Summary Matrix](#summary-matrix)

---

## 1. Observative Attack Mitigations

These techniques defend against side-channel attacks that observe the system's behavior (power consumption, electromagnetic radiation, timing, etc.) to extract secrets.

---

### 1.1 Secure Memory Compare

**Description:**
Standard C library comparison functions (`memcmp`, `strcmp`) are timing-dependent — they return early on the first mismatch. This leaks information about where the first difference occurs, enabling timing attacks (e.g., byte-by-byte password recovery). A secure comparison must always process the entire data range regardless of mismatches, producing a constant-time execution.

**Code Pattern:**
Replace any use of `memcmp`/`strcmp` on security-critical data with a constant-time comparison that ORs all XOR differences into an accumulator:

```c
uint8_t SecureMemCmp(const void *P1, const void *P2, uint16_t wSize)
{
    uint8_t bResult = 0;
    const uint8_t *p1 = (const uint8_t *)P1;
    const uint8_t *p2 = (const uint8_t *)P2;
    while (wSize--)
    {
        bResult |= (*(p1++) ^ *(p2++));
    }
    return bResult; // 0 = equal, non-zero = different
}
```

**When to use:**

- Password or PIN comparisons
- Signature verification (comparing computed vs. expected digest)
- Key comparison
- Any comparison of secret data where timing leakage is a concern

**Additional notes:**

- The XOR operation itself can leak Hamming weight via DPA — consider combining with Secure Memory Copy or random Hamming weight masking for higher security.
- Use `volatile` if compiler optimization may remove the constant-time property.
- **Simulator-tested pitfall — Size Parameter Corruption:** If `memcmp` is used with a size loaded from memory, glitching the size-load instruction to NOP makes `memcmp` compare 0 bytes (always returns 0 = equal). **Fix:** Load the size from memory twice (using `volatile`) and cross-check both loads before calling the comparison function. Or avoid `memcmp` entirely and use redundant field-by-field comparison with branch separation.

---

### 1.2 Secure Memory Copy

**Description:**
Standard `memcpy` copies bytes sequentially, leaking the Hamming weight (number of 1-bits) of each byte through power consumption. An attacker can deduce the copied data (e.g., cryptographic keys) from the power trace. Secure memory copy randomizes the copy order and/or pre-loads destinations with random values to hide the real data's Hamming weight.

**Code Pattern — Randomized Copy Order (for power-of-2 sized data):**

```c
#define AES_256_KEY_LENGTH 32

void CopyKeyData(uint8_t *dest, uint8_t *source)
{
    uint16_t wXorMask = rand() & (AES_256_KEY_LENGTH - 1);
    for (uint16_t i = 0; i < AES_256_KEY_LENGTH; i++)
    {
        dest[i ^ wXorMask] = source[i ^ wXorMask];
    }
}
```

**When to use:**

- Copying cryptographic keys from storage to working memory
- Transferring any secret data (passwords, tokens, nonces)
- Loading assets from NVM into RAM

**Additional notes:**

- The randomized order method only works for fixed-size arrays where size is a power of 2.
- For maximum security, implement in assembly to prevent compiler from reordering operations.

---

### 1.3 Unconditional Flow

**Description:**
Data-dependent branching (`if`/`else`) creates visible differences in power traces and timing, allowing attackers to deduce which branch was taken and thus learn about secret data. Unconditional flow replaces conditional branches with table lookups or arithmetic that always execute the same instructions regardless of the data, making the execution path data-independent.

**Code Pattern — Table Lookup:**

```c
// Replace: if (bResult == 0) fRet = TRUE; else fRet = FALSE;
// With:
const BOOL CompTable[2] = {TRUE, FALSE};

// Reduce any non-zero result to 0 or 1 without branching:
bResult = bResult | (bResult >> 4);
bResult = bResult | (bResult >> 2);
bResult = bResult | (bResult >> 1);
bResult = bResult & 0x01;

fRet = CompTable[bResult];
```

**Code Pattern — Branchless Boolean Operations:**

```c
uint8_t isZero(uint32_t a)         { return (((0 - a) | a) >> 31) ^ 0x01; }
uint8_t isEqual(uint32_t a, uint32_t b) { return isZero(a - b); }
```

**Code Pattern — Branchless Min/Max:**

```c
uint32_t min(uint32_t a, uint32_t b)
{
    uint32_t mask = b ^ (a - b);
    mask = (~mask & b) | (mask & (~a));
    mask = (mask >> 31) - 1;
    return (mask & a) | (~mask & b);
}
```

**When to use:**

- RSA "square and multiply" exponentiation (to hide key bits)
- Bleichenbacher-style padding oracle defenses (PKCS#1 v1.5 decoding)
- Any comparison or decision based on secret data
- Password check result handling

**Additional notes:**

- Be aware of compiler optimizations that may reintroduce branches.
- Use `volatile` or inline assembly where needed.

---

### 1.4 Variable Initialization

**Description:**
Security-relevant variables must always be initialized before use to prevent attacks that exploit undefined/uninitialized memory states. The initialization value must be chosen according to the data type (e.g., Secure Boolean INIT value for boolean flags, random values for key buffers). Beware of compiler optimizations that may remove initializations it considers redundant.

**Code Pattern:**

```c
// For secure boolean variables — initialize to INIT (not TRUE or FALSE)
volatile BOOL DataResult = INIT;

// For key/hash buffers — initialize with random data
uint8_t keyBuffer[KEY_SIZE];
for (int i = 0; i < KEY_SIZE; i++)
    keyBuffer[i] = rand();

// For data arrays that will hold secrets — zero or random fill
memset(sensitiveBuffer, 0, sizeof(sensitiveBuffer));
```

**When to use:**

- All security-relevant boolean variables (use INIT value to detect unset states)
- Key buffers before loading keys
- Hash value buffers before computation
- Any variable where an uninitialized state could be exploited

**Additional notes:**

- Use `volatile` to prevent the compiler from optimizing away the initialization.
- Consider Hamming weight implications when choosing init values (avoid constant patterns that leak through power analysis).
- The KRACK attack on WPA2 Android exploited exactly this: a key was not re-initialized, allowing it to be set to a known value.

---

### 1.5 Statistic Data Hiding

**Description:**
When an algorithm has known side-channel weaknesses that cannot be fixed (e.g., a fixed hardware crypto module or a mandatory library), the real data is mixed with random/fake data during execution. This prevents the attacker from isolating the actual computation in power traces. The real data must be mixed differently on every execution, enough fake data must be added, and the power profile of real vs. fake operations must be indistinguishable.

**Code Pattern (conceptual):**

```c
// Instead of one AES computation, perform N computations
// with random keys/data, interleaving the real one at a random position
uint8_t slot = rand() % N;
for (uint8_t i = 0; i < N; i++)
{
    if (i == slot)
        AES_Encrypt(realData, realOutput, realKey);
    else
        AES_Encrypt(randomData[i], dummyOutput, randomKey[i]);
}
// Verify real output with a "Known Answer Test" to detect fault injection
```

**When to use:**

- When using a hardware crypto accelerator with known SPA/DPA vulnerabilities
- When using a third-party library that cannot be modified
- When Mathematical Data Hiding is not applicable

**Additional notes:**

- Significantly increases computational cost (e.g., 32x for 32 dummy runs).
- Must include "Known Answer Tests" and double-computation to detect invasive attacks during the dummy calculations.
- The mixing order must be randomized per execution.

---

### 1.6 Mathematical Data Hiding

**Description:**
Security-critical values are mathematically split, masked, or transformed so that intermediate computation values never directly expose the secret. Random values are added before computation and mathematically removed afterward (blinding). Alternatively, secrets are split into shares that are processed independently (secret sharing), or transformed through one-way functions.

**Code Pattern — Blinding (RSA example):**

```c
// Instead of: N = P * Q  (leaks P, Q through power analysis of multiplication)
R1 = rand();
R2 = rand();
P_prime = P + R1;
Q_prime = Q + R2;
N = (P_prime * Q_prime) - (R2 * P_prime) + (R1 * R2) - (R1 * Q_prime);
// Mathematically equivalent to P * Q, but intermediate values are randomized
```

**Code Pattern — Exponent Splitting (RSA decryption):**

```c
// Instead of: m = c ^ D  (leaks D through power analysis)
R = rand() % D;
D1 = D - R;
D2 = R;
m = power(c, D1) * power(c, D2); // m = c^D1 * c^D2 = c^(D1+D2) = c^D
```

**When to use:**

- RSA key operations (modular exponentiation, key generation)
- Any cryptographic computation where intermediate values reveal the key
- ECC scalar multiplication
- Whenever mathematical operations on secrets are observable

**Additional notes:**

- Only addition/subtraction are considered safe from power analysis; multiplication and XOR are vulnerable.
- Random values must come from a secure RNG.

---

### 1.7 Random Delay Handling

**Description:**
Random wait loops are inserted before, during, or after security-critical operations. This adds temporal jitter to the execution, making it harder for an attacker to align power traces for DPA/template attacks. The delay duration is determined by a hardware random number generator.

**Code Pattern:**

```c
void RandomDelay(void)
{
    volatile uint8_t bDelayCount;
    bDelayCount = rand(); // Random value from internal RNG
    do
    {
        bDelayCount--;
    } while (bDelayCount > 0);
}
```

**When to use:**

- Before/after cryptographic operations
- Between security-critical function calls
- Inside loops processing secret data
- As a complement to other countermeasures

**Additional notes:**

- This is a statistical defense only — with enough traces, the attacker can still succeed by repeating the attack many times.
- An attacker may use SAD (Sum of Absolute Differences) to detect and remove the delay from captured traces.
- Should be combined with invasive attack detection (e.g., triggering a security alert if repeated attacks are detected).

---

## 2. Semi-Invasive & Manipulative Attack Mitigations

These techniques defend against fault injection attacks (voltage glitches, clock spiking, laser attacks, EM pulses) that manipulate the CPU state, program counter, registers, or memory.

---

### 2.1 Secure Boolean

**Description:**
Standard C booleans use 0 for FALSE and any non-zero value for TRUE, meaning 255 out of 256 possible byte values map to TRUE. A single-bit fault can easily flip FALSE to TRUE. Secure booleans use specific, carefully chosen values for TRUE, FALSE, and an INIT state, with equal Hamming weight and distance between all states. Any value not matching TRUE or FALSE triggers a security alert.

**Code Pattern:**

```c
typedef enum {
    INIT  = 0x99,  // Hamming weight = 4
    FALSE = 0x3C,  // Hamming weight = 4
    TRUE  = 0x5A,  // Hamming weight = 4
} BOOL;

// Hamming distances: INIT<->TRUE = 4, INIT<->FALSE = 4, TRUE<->FALSE = 4

#define BOOL_OP_NOT_TRUE(value)  ((value) != TRUE)
#define BOOL_OP_NOT_FALSE(value) ((value) != FALSE)

#define IF_BOOL_OP_ALARM(value) \
    if (BOOL_OP_NOT_TRUE(value) && BOOL_OP_NOT_FALSE(value)) SecurityAlert();

#define IF_BOOL_OP_TRUE_ALARM(value) \
    IF_BOOL_OP_ALARM(value) if ((value) == TRUE)

#define IF_BOOL_OP_FALSE_ALARM(value) \
    IF_BOOL_OP_ALARM(value) if ((value) == FALSE)
```

**Usage:**

```c
volatile BOOL secPassWord = INIT;
secPassWord = PasswordCheck();

IF_BOOL_OP_TRUE_ALARM(secPassWord)
{
    // Success handling
}
```

**When to use:**

- Return values of password/PIN checks
- Return values of signature/certificate verification
- Any security-critical decision variable
- Access control flags

**Additional notes:**

- Probability of a random fault producing a valid TRUE drops from 255/256 to 1/256.
- For higher security, use `uint32_t` instead of `uint8_t` (reduces attack probability to 1/2^32).
- The Hamming weight of all three values should be identical to prevent side-channel detection of the state.
- Always use `volatile` to prevent compiler optimization.

---

### 2.2 Secure Loop

**Description:**
Loop counter variables can be corrupted by fault injection, causing security-critical loops (password comparison, signature verification, data copying) to terminate early or skip iterations. Secure loops use dual counter variables — one counting up and one counting down — with consistency checks inside and after the loop.

**Code Pattern:**

```c
volatile uint16_t wi, wd;
wd = 0;

for (wi = 0, wd = wLength; wi < wLength && wd > 0; wi++, wd--)
{
    // Consistency check: counters must always sum to wLength
    if (wi + wd != wLength)
        SecurityAlert();

    // Perform critical operation
    x = op1(x, wi);
}

// Post-loop verification
if ((wi != wLength) || (wd != 0))
    SecurityAlert();
```

**When to use:**

- Password/PIN comparison loops
- Signature verification loops
- Cryptographic round loops
- Memory compare/copy of security-critical data
- Secure data erasure loops
- Any loop where premature termination would compromise security

**Additional notes:**

- Both counter variables should be declared `volatile` to prevent compiler optimization.
- The in-loop check (`wi + wd != wLength`) catches faults during iteration.
- The post-loop check catches faults that cause the loop to exit early.

---

### 2.3 Secure Return Parameter Handling

**Description:**
Standard C `return` values are transferred via CPU registers. After returning to the caller, the value is written from the register to a variable. This register-to-variable transfer can be attacked by fault injection (e.g., corrupting the register before the move instruction). Secure return parameter handling passes return values through a pointer parameter, so the callee writes directly to the caller's memory.

**Code Pattern:**

```c
// INSECURE: Return via register
bool PasswordCheck(void)
{
    // ...
    return fCheck; // Value placed in register, vulnerable during transfer
}
fRet = PasswordCheck(); // Register -> variable, attackable

// SECURE: Return via pointer parameter
void PasswordCheck(BOOL *pfRet)
{
    // ...
    *pfRet = FALSE; // Written directly to caller's memory
    // ... (verification logic)
    *pfRet = TRUE;
    return;
}

BOOL fRet = INIT;
PasswordCheck(&fRet);
// fRet is already set in caller's memory space
```

**When to use:**

- Security-critical functions returning pass/fail status
- Cryptographic function results
- Any function whose return value controls a security decision

**Additional notes:**

- Combine with Secure Boolean for the return value type.
- The pointer should be to a `volatile` variable.
- **Simulator-tested pitfall — Stale Return Values:** When a non-inlined function returns `bool`, the register `r0` may already contain a non-zero value from argument setup. If the attacker glitches the `bl` (function call) instruction, the function never executes, and the stale register value (which may be truthy) is used as the result. **Fix:** Prefer pointer-based return parameter handling for security-critical results, or use inline comparison chains (see Section 2.5 — Non-Inlined Tail Call pattern).
- **Simulator-tested pitfall — Pre-Loaded Function Arguments:** When calling a non-inlined function, ALL arguments are loaded into registers (r0–r3) BEFORE the `bl` instruction. A single glitch on one `ldm` or `ldr` instruction can cause the function to receive stale/wrong register values, potentially making all internal checks pass despite the fault. **Fix:** Inline the comparison chain as a macro so arguments are loaded incrementally, one per check. Only the final tail-call function receives pre-loaded arguments.

---

### 2.4 Checkpoint Handling

**Description:**
In complex security-critical program sequences (e.g., firmware update: load → verify password → decrypt → program), an attacker can skip individual steps via fault injection. Checkpoint handling uses a global counter variable that is incremented at each step. After the sequence, the counter is verified against the expected value. Any skipped step results in a wrong counter and triggers a security alert.

**Code Pattern:**

```c
volatile uint16_t wCheckPoint = 0x1234; // Start with a non-trivial value

void UpdateSequence(void)
{
    wCheckPoint++;   // Step 1 entry
    fRet = PasswordCheck();
    // ...

    // Verify checkpoint after step that includes sub-increments
    if (wCheckPoint != (0x1234 + 2))
        SecurityAlert();

    wCheckPoint++;   // Step 2 entry
    fRet = DecryptFile();
    // ...
}

BOOL PasswordCheck(void)
{
    wCheckPoint++;   // Sub-step increment
    // ... verification logic
}
```

**When to use:**

- Multi-step firmware update sequences
- Boot chain validation (measure → verify → decrypt → load)
- Any ordered sequence of security operations where skipping a step is dangerous
- Transaction processing with multiple validation stages

**Additional notes:**

- The start value should not be zero (use a random-looking value like `0x1234`).
- Each function in the chain increments the counter, and the caller verifies the expected value.
- Can be combined with Function Signature Check for stronger protection.

---

### 2.5 Branch Protection

**Description:**
Program branches (if/else) can be bypassed by fault injection that corrupts the program counter, causing the CPU to skip the branch and continue with normal (non-protected) execution. Branch protection doubles the conditional check: the condition is evaluated once, then after some intervening operations (e.g., random wait states), it is evaluated again. If the second check fails, a security alert is raised.

**Code Pattern:**

```c
if (fPassComp == SEC_TRUE)
{
    // Preparation / random delay to separate the two checks in time
    RandomWaitStates();

    // Second check of the same condition
    if (fPassComp == SEC_TRUE)
        LoadFile();         // Protected operation
    else
        SecurityAlert();    // Fault detected
}
```

**When to use:**

- Before executing protected operations (decryption, flash programming)
- Before executing protection mechanisms (memory erasure, error counter increment)
- Any critical branch where the attacker benefits from skipping it

**Additional notes:**

- Beware of compiler optimizations that may collapse the duplicate check into a single branch. Use `volatile` for the checked variable.
- The random wait between checks makes it harder for the attacker to glitch both checks with a single fault.

#### Simulator-Tested Pattern: Redundant Comparison Chains

A single comparison compiles to a single branch instruction — trivially bypassed by one glitch. Chain multiple **independent** checks using `&&`, where each check tests a **different aspect** of the data:

```c
typedef struct {
    volatile uint32_t val;
    volatile uint32_t val_copy;  // val XOR MASK
} secure_uint;

#define MASK 0xA5C35A3C

bool values_equal =
    (a.val == b.val) &&
    (a.val_copy == b.val_copy) &&
    ((a.val ^ MASK) == (b.val ^ MASK));
```

Each `&&` generates a **separate branch instruction** in compiled assembly. Glitching one branch only skips one check — the others still guard the result. Repeating the same comparison twice is less effective because the compiler may optimize it away or use cached register values. Each check must test a **different field or transformation**.

#### Simulator-Tested Pattern: Branch Separation via Function Calls

If two comparison instructions are adjacent in memory, a single glitch spanning 2–3 instructions can skip both. Insert **non-inlined function calls** between checks to force spatial separation. A `bl` instruction (function call) creates a jump to a different code location, guaranteeing the two checks cannot be covered by a single contiguous NOP glitch:

```c
__attribute__((noinline)) bool verify_delay(void) {
    volatile uint32_t r = some_computation();
    return r != 0;  // Always returns true in normal operation
}

if ((a.val == b.val) && verify_delay() && (a.val_copy == b.val_copy)) { ... }
```

**When to use:** Between any two adjacent security-critical comparisons. The function call acts as a code-location barrier that requires an independent glitch to bypass.

#### Simulator-Tested Pattern: Non-Inlined Tail Call

The final check in a comparison chain should be a **non-inlined function call**. This creates a function boundary (via `bl` instruction) that requires an independent glitch to bypass:

```c
__attribute__((noinline)) bool verify_copies_match(secure_uint *a, secure_uint *b) {
    return a->val_copy == b->val_copy;
}

// In the comparison chain:
if ((a.val == b.val) &&
    verify_delay() &&
    (a.val_copy == b.val_copy) &&
    verify_delay() &&
    validate_secure(a) &&
    verify_copies_match(&a, &b))   // Non-inlined tail call
{
    // Protected operation
}
```

**Why inline checks + non-inlined tail is the strongest pattern:**
- An **inline macro/check** expands in the caller — each `&&` generates its own branch. Arguments are not pre-loaded into a single register set, so corrupting one load only affects one check.
- A **non-inlined function** as the final check adds a code boundary. The attacker needs an independent glitch specifically targeting this function call.
- A **fully non-inlined comparison function** (all checks in one function) is *weaker* because: (a) all arguments must be pre-loaded into registers before the `bl` call, creating a concentrated vulnerability point, and (b) glitching the single `bl` instruction skips all checks at once.

**Simulator-measured pitfall — Stale Return Values:** When a non-inlined function returns `bool`, the register `r0` may contain a non-zero value from argument setup. Glitching the `bl` (function call) instruction means the comparison function never executes, and the stale register value — which may be non-zero (truthy) — is used as the result. **Fix:** Use inline comparison chains with a non-inlined tail call, rather than putting ALL comparison logic in a single non-inlined function.

**Simulator-measured pitfall — Cached Register Values:** The compiler may optimize a "double check" to compare against a cached register instead of re-loading the constant from memory. Both comparisons then use the same corrupt value. **Fix:** Use data redundancy so each check tests a **different field** (`val` vs `val_copy`). Mark fields `volatile` to prevent caching.

**Simulator-measured pitfall — Command Bit-Flip on Comparison + Branch:** A `cmdbf` attack can change the register operand of a `cmp` instruction AND the condition of a `beq`/`bne` branch in the same fault, defeating simple comparisons. **Fix:** Multiple redundant comparisons with branch separation between them.

---

### 2.6 Causal Chain Check

**Description:**
Similar to Branch Protection but extends across function boundaries. Before calling a function that depends on a prior decision (e.g., calling `Func1()` because `bVersionDat == VERSION1`), the decision value is stored in a global variable. The called function checks the global variable to confirm it was called for the right reason. This detects program counter corruption that causes a function to be called from the wrong context.

**Code Pattern:**

```c
volatile uint32_t GlobalCheck;

void Dispatcher(void)
{
    GlobalCheck = bVersionDat;
    switch (bVersionDat)
    {
        case VERSION1: fRet = Func1(); break;
        case VERSION2: fRet = Func2(); break;
        // ...
    }
}

void Func1(void)
{
    if (GlobalCheck != VERSION1)
        SecurityAlert(); // Called from wrong context — fault detected
    // ... proceed with operation
}
```

**When to use:**

- Dispatch tables / command handlers where the wrong function must not execute
- State machines where transitions are security-critical
- Multi-version protocol handlers
- Any scenario where a function should only be callable under specific conditions

---

### 2.7 Function Signature Check

**Description:**
An attacker who can manipulate the program counter or skip return operations could call security-critical functions out of sequence or from unauthorized locations. Function signature checking injects entry and exit markers: the caller sets an entry marker before calling, the callee verifies it on entry, sets an exit marker before returning, and the caller verifies the exit marker afterward.

**Code Pattern:**

```c
#define FUNCTION_ID_SETUP           uint32_t function_id = 0x10101010
#define FUNCTION_ID_SET_ENTRY(x)    function_id = x##_ENTRY
#define FUNCTION_ID_CHECK_ENTRY(x)  if (function_id != x##_ENTRY) SecurityAlert()
#define FUNCTION_ID_SET_EXIT(x)     function_id = x##_EXIT
#define FUNCTION_ID_CHECK_EXIT(x)   if (function_id != x##_EXIT) SecurityAlert()

#define FUNCTION_ID_FUNC1_ENTRY 0xAABBCCDD
#define FUNCTION_ID_FUNC1_EXIT  0x11223344

void caller(void)
{
    FUNCTION_ID_SETUP;

    FUNCTION_ID_SET_ENTRY(FUNCTION_ID_FUNC1);
    func1(&function_id);
    FUNCTION_ID_CHECK_EXIT(FUNCTION_ID_FUNC1);
}

void func1(uint32_t *function_id)
{
    FUNCTION_ID_CHECK_ENTRY(FUNCTION_ID_FUNC1);
    // ... critical operation
    FUNCTION_ID_SET_EXIT(FUNCTION_ID_FUNC1);
    return;
}
```

**When to use:**

- All security-critical function calls
- Cryptographic operations
- Key management functions
- Functions that must not be called out of sequence (e.g., after boot validation)

**Additional notes:**

- Entry and exit IDs should have good Hamming distance from each other.
- Can be combined with Checkpoint Handling for even stronger protection.

---

### 2.8 Caller Gate Check

**Description:**
An attacker may use ROP (Return-Oriented Programming) or JOP (Jump-Oriented Programming) attacks to call security-critical functions from unauthorized locations (e.g., injected code in RAM). Caller gate checking reads the return address from the stack and compares it against a whitelist of allowed caller addresses. If the return address doesn't match, a security alert is raised.

**Code Pattern:**

```c
extern void func_a_call_return_func_b(); // Label at the call site in func_a

void func_a(void)
{
    func_b();
    // Place a label right after the call for return address verification
    asm(".global _func_a_call_return_func_b\n\t"
        "_func_a_call_return_func_b:\n\t");
}

void func_b(void)
{
    // Verify the caller is func_a by checking the return address
    if (__builtin_return_address(0) != (void *)func_a_call_return_func_b)
        SecurityAlert();
    // ... proceed with operation
}
```

**When to use:**

- High-security functions that must only be called from specific locations
- Key derivation / cryptographic functions
- Functions that grant elevated privileges
- Protection against ROP/JOP attacks

**Additional notes:**

- Uses GCC's `__builtin_return_address(0)` to read the return address.
- The allowed caller addresses can be stored in a lookup table for functions with multiple valid callers.
- Requires careful handling of compiler optimizations (inlining, tail-call optimization).

---

### 2.9 Redundancy Call

**Description:**
Security-critical functions are called multiple times and the results compared. If a fault injection affected one execution, the results will differ, triggering a security alert. This is particularly important for cryptographic operations where a single faulted computation can leak the key (e.g., DFA on AES — a fault in round 8 reduces the key space from 2^128 to 2^12).

**Code Pattern:**

```c
void EncryptData(uint8_t *prgbIn, uint8_t *prgbOut, uint16_t wDataSize)
{
    uint8_t rgbBlock[AES_BLOCK_SIZE];

    for (uint16_t bBlock = 0; bBlock < (wDataSize / AES_BLOCK_SIZE); bBlock++)
    {
        // First encryption into a temporary buffer
        AES_Encrypt(prgbIn, rgbBlock, prgbKey);
        // Second encryption into the output buffer
        AES_Encrypt(prgbIn, prgbOut, prgbKey);

        // Compare both results — must be identical
        if (memcmp(prgbOut, rgbBlock, AES_BLOCK_SIZE) != 0)
            SecurityAlert(); // Fault injection detected
    }
}
```

**When to use:**

- AES encryption/decryption (DFA resistance)
- RSA/ECC signature generation
- Hash computation for integrity checks
- Any cryptographic operation where a faulted output can leak the key

**Additional notes:**

- Doubles execution time but provides strong fault detection.
- Use `SecureMemCmp` (constant-time comparison) instead of `memcmp` for the comparison.
- The temporary buffer should be in a different memory location to protect against address bus faults.

---

### 2.10 Sentinel Handling

**Description:**
Attacks on the address bus can redirect memory reads to attacker-controlled regions. When reading assets (e.g., keys), the system may unknowingly read from a wrong address that the attacker has filled with known data. Sentinel handling places known "sentinel" values at specific memory addresses adjacent to or surrounding the asset. Before and after reading the asset, the sentinels are verified. If the address bus was corrupted, the sentinel values will be wrong.

**Code Pattern (conceptual):**

```c
// Memory layout:
//   [SENTINEL_BEFORE] [KEY_DATA] [SENTINEL_AFTER]

#define SENTINEL_VALUE_BEFORE 0xDEADBEEF
#define SENTINEL_VALUE_AFTER  0xCAFEBABE

volatile uint32_t sentinel_before = SENTINEL_VALUE_BEFORE;
uint8_t key_data[KEY_SIZE];
volatile uint32_t sentinel_after = SENTINEL_VALUE_AFTER;

void ReadKey(uint8_t *dest)
{
    if (sentinel_before != SENTINEL_VALUE_BEFORE)
        SecurityAlert();
    if (sentinel_after != SENTINEL_VALUE_AFTER)
        SecurityAlert();

    SecMemCopy(dest, key_data, KEY_SIZE);

    if (sentinel_before != SENTINEL_VALUE_BEFORE)
        SecurityAlert();
    if (sentinel_after != SENTINEL_VALUE_AFTER)
        SecurityAlert();
}
```

**When to use:**

- Reading cryptographic keys from memory
- Accessing any high-value assets stored in RAM or Flash
- Systems where address bus attacks are a threat
- External memory interfaces

**Additional notes:**

- Cache handling must be considered (sentinels could be served from cache while the actual read goes to the bus).
- Sentinel values should be chosen carefully and may need to change over time to prevent the attacker from learning them.
- Sentinel data can itself be attacked via fault injection — combine with Data Integrity Protection.

---

### 2.11 Data Integrity Protection

**Description:**
Stored data/keys (assets) must be protected against modification by fault injection in both volatile (RAM) and non-volatile (Flash) memory. Attacks include: injecting a known key, changing passwords, modifying access rights, tampering with error counters, or causing denial of service. Protection is achieved through checksums, redundancy (data + inverse), or authenticated encryption.

**Code Pattern — CRC/Checksum:**

```c
typedef struct {
    uint8_t  key[KEY_SIZE];
    uint32_t checksum;
} ProtectedKey;

void StoreKey(ProtectedKey *pk, const uint8_t *key)
{
    memcpy(pk->key, key, KEY_SIZE);
    pk->checksum = CRC32(pk->key, KEY_SIZE);
}

bool VerifyKey(const ProtectedKey *pk)
{
    return (pk->checksum == CRC32(pk->key, KEY_SIZE));
}
```

**Code Pattern — Data and Inverse:**

```c
typedef struct {
    uint8_t  data[DATA_SIZE];
    uint8_t  data_inv[DATA_SIZE]; // Bitwise inverse of data
} RedundantData;

void StoreData(RedundantData *rd, const uint8_t *src, uint16_t size)
{
    for (uint16_t i = 0; i < size; i++)
    {
        rd->data[i] = src[i];
        rd->data_inv[i] = ~src[i];
    }
}

bool VerifyData(const RedundantData *rd, uint16_t size)
{
    for (uint16_t i = 0; i < size; i++)
    {
        if (rd->data[i] != (uint8_t)~rd->data_inv[i])
            return false;
    }
    return true;
}
```

**Integrity methods (from low to high security):**

- **Data + Inverse:** Store bitwise complement alongside data
- **Secure Boolean values:** Use specific values with known Hamming weight
- **LRC (Longitudinal Redundancy Check):** Simple XOR checksum
- **CRC16/CRC32:** Cyclic redundancy check
- **Hash (SHA-256):** Cryptographic hash for strong integrity
- **CMAC:** Cipher-based MAC for authenticated integrity
- **Authenticated Encryption (AES-CTR, AES-OFB, KeyWrap):** Encrypt + authenticate to prevent targeted modifications

**When to use:**

- Storing cryptographic keys in RAM or Flash
- Error/retry counters
- Access control flags and privilege levels
- Configuration data
- Any persistent security-critical state

#### Simulator-Tested Pattern: XOR-Masked Redundant Data Type

For runtime comparison hardening against fault injection, store every critical value twice — the original and a transformed copy (XOR with a constant mask). A single fault can corrupt one memory location or register, but not two independent representations simultaneously:

```c
typedef struct {
    volatile uint32_t val;       // The actual value
    volatile uint32_t val_copy;  // val XOR MASK
} secure_uint;

#define MASK 0xA5C35A3C
#define secure_init(x) ((secure_uint){ (x), (x) ^ MASK })
```

**Why it works:** An attacker corrupting `val` cannot simultaneously corrupt `val_copy` in a consistent way. Any single fault creates a detectable mismatch between the two representations. The copy uses XOR (not a plain duplicate) so a single memory/bus fault affecting adjacent bytes doesn't corrupt both identically.

**When to use:** For any decision variable (password check result, signature verification status, comparison operands) that will be used in a security-critical branch.

#### Simulator-Tested Pattern: Self-Consistency Validation

After using XOR-masked redundancy, periodically validate that the two representations are still consistent. Insert this as an additional `&&` check in comparison chains:

```c
__attribute__((always_inline)) static inline bool validate_secure(secure_uint x) {
    if (x.val != (x.val_copy ^ MASK)) {
        while(1);  // Tampered — halt (or SecurityAlert)
    }
    return true;
}
```

**When to use:** Inside redundant comparison chains, between other checks. Catches cases where a single fault corrupted one field of the `secure_uint` without affecting the comparison result.

#### Simulator-Tested Pattern: Removing Success Reference Data from Memory

If the binary contains the "correct" value in memory (e.g., a password, a comparison target, a decision value), an attacker can potentially corrupt a data pointer to read the success value instead of the failure value. Remove the reference data entirely so it only exists as an immediate value in the instruction stream:

```c
// INSECURE: Both success and failure values stored in memory
// An attacker can corrupt the pointer to read success_value instead of failure_value
DECISION_DATA_STRUCTURE(uint32_t, 0x01234567, 0xFEFEFEFE);

// SECURE: Only the failure value exists in memory
// The "correct" value is a compile-time constant in the instruction stream only
#define FAILURE_VAL 0xFEFEFEFE
DECISION_DATA_STRUCTURE(uint32_t, FAILURE_VAL, FAILURE_VAL);
// Comparison uses a #define constant, not a memory-stored value
```

**When to use:** When the decision variable is compared against a known-good reference value. Instead of storing the reference in a data structure, use a compile-time `#define` constant. The constant is encoded directly in the `cmp` or `mov` instructions, never stored as data in memory.

---

### 2.12 Pre-Penalization

**Description:**
When a failed authentication or detected attack triggers a countermeasure (e.g., incrementing an error counter, locking the device), the attacker can observe the countermeasure through side-channels (e.g., NVM write pump activity) and then disrupt it (glitch, reset, power cut) before it completes. Pre-penalization assumes failure *before* testing: the error counter is incremented (or the penalty applied) before the security check, and only decremented if the check succeeds.

**Code Pattern:**

```c
volatile uint16_t errorCounter; // Stored in NVM

void AuthenticatePassword(const uint8_t *password)
{
    // PRE-PENALIZE: Assume failure, increment counter BEFORE checking
    errorCounter++;
    NVM_Write(&errorCounter); // Persist to non-volatile memory

    if (errorCounter >= MAX_ATTEMPTS)
    {
        LockDevice(); // Permanent lockout
        return;
    }

    // Now perform the actual check
    BOOL result = INIT;
    PasswordCheck(password, &result);

    IF_BOOL_OP_TRUE_ALARM(result)
    {
        // Success: undo the pre-penalization
        errorCounter--;
        NVM_Write(&errorCounter);
        // ... grant access
    }
    // On failure: counter already incremented, nothing more to do
}
```

**When to use:**

- Password/PIN verification with retry limits
- Certificate/signature verification with lockout policy
- Any authentication mechanism with a failure counter
- Secure boot validation with retry limits

**Additional notes:**

- The NVM write for the increment happens *before* the check, so even if the attacker resets the device mid-check, the attempt is already counted.
- If the attacker disrupts the decrement after a successful check, the user simply loses one attempt — a safe failure mode.
- Counter measures should include: delayed retry, data erasure, or permanent device lockout after threshold.

---

### 2.13 Condition-Gated Success

**Description:**
Even with hardened comparisons and branch protection, an attacker who can glitch past an `if` check may reach the success handling code. Condition-gated success splits the success signaling into two separate steps: (1) arm a gate variable *inside* the protected `if`-body, and (2) use the gate variable's value as the actual success signal. Bypassing the `if` check alone is insufficient — the attacker would need a second independent fault to also set the gate variable.

**Code Pattern:**

```c
volatile uint32_t success_condition = 0x22222222; // Initialized to non-success value

void main_check(void)
{
    // ... perform hardened comparison ...
    if (all_checks_passed)
    {
        // Step 1: Arm the gate INSIDE the if-body
        success_condition = 0x11111111;
        start_success_handling();
    }
    else
    {
        // Failure path
        handle_failure();
    }
}

void start_success_handling(void)
{
    // Step 2: Use the gate variable — only 0x11111111 means actual success
    if (success_condition == 0x11111111)
    {
        // True success
        perform_privileged_operation();
    }
    else
    {
        // Gate was not armed — fault attack detected
        SecurityAlert();
    }
}
```

**When to use:**
- Any security-critical decision where the success path grants privileges, access, or performs irreversible operations
- Boot chain validation (the success handler checks that the validation gate was properly armed)
- Firmware update authorization
- Cryptographic key release

**How it defeats fault injection:**
- If an attacker glitches past the `if` check and reaches `start_success_handling()`, the `success_condition` variable was never set to `0x11111111` because the assignment inside the `if`-body was skipped
- The attacker would need a **second independent fault** to either: (a) set `success_condition` to `0x11111111`, or (b) bypass the gate check in `start_success_handling()`
- Combined with branch separation and redundant comparisons, this requires an impractical number of simultaneous faults

**Additional notes:**
- The gate variable must be `volatile` to prevent compiler optimization.
- The non-success initial value (`0x22222222`) should have maximum Hamming distance from the success value (`0x11111111`).
- The `start_success_handling()` function should be non-inlined to create a function boundary.

#### Simulator-Tested Pattern: Fall-Through Protection

If the failure and success code paths are adjacent in compiled memory, a glitch at the failure path boundary can cause execution to "fall through" into the success path. Condition-gated success makes this harmless because the gate variable was never armed:

```c
// Even if attacker falls through from failure handling into success handling,
// success_condition is still 0x22222222 (never armed), so the gate blocks.
```

---

### 2.14 Minimum Effective Hardened Comparison

**Description:**
Based on systematic fault injection testing (single and double fault campaigns across glitch, register bit-flip, register flood, and command bit-flip attack types), a minimum set of combined techniques has been identified that achieves zero successful attacks. Removing any single element re-introduces exploitable vulnerabilities. This is the recommended template for any security-critical comparison.

**Code Pattern — Complete Hardened Comparison Chain:**

```c
#include <stdint.h>
#include <stdbool.h>

// --- Data type with XOR-masked redundancy (Section 2.11) ---
typedef struct {
    volatile uint32_t val;
    volatile uint32_t val_copy;  // val ^ MASK
} secure_uint;

#define MASK 0xA5C35A3C
#define secure_init(x) ((secure_uint){ (x), (x) ^ MASK })

// --- Self-consistency validation (Section 2.11) ---
__attribute__((always_inline))
static inline bool validate_secure(secure_uint x) {
    if (x.val != (x.val_copy ^ MASK)) {
        while(1);  // Halt on tamper detection
    }
    return true;
}

// --- Branch separator (Section 2.5) ---
__attribute__((noinline))
bool verify_delay(volatile uint32_t *v) {
    return (*v != 0);  // Always true in normal operation
}

// --- Non-inlined tail call (Section 2.5) ---
__attribute__((noinline))
bool verify_copies_match(secure_uint *a, secure_uint *b) {
    return a->val_copy == b->val_copy;
}

// --- Gate variable for condition-gated success (Section 2.13) ---
volatile uint32_t success_condition = 0x22222222;

// --- The hardened comparison ---
void hardened_check(secure_uint a, secure_uint b)
{
    volatile uint32_t sep = 1;  // Separator variable

    if (
        (a.val == b.val) &&               // Check 1: Primary comparison
        verify_delay(&sep) &&             // Separator: non-inlined function call
        (b.val == (a.val_copy ^ MASK)) && // Check 2: Cross-redundancy validation
        verify_delay(&sep) &&             // Separator: prevents glitch spanning 2+4
        validate_secure(a) &&             // Check 3: Self-consistency of 'a'
        verify_copies_match(&a, &b)       // Check 4: Non-inlined tail call
    )
    {
        success_condition = 0x11111111;   // Arm the gate
        start_success_handling();
    }
    else
    {
        handle_failure();
    }
}

__attribute__((noinline))
void start_success_handling(void)
{
    if (success_condition == 0x11111111)
    {
        // Actual success — perform privileged operation
    }
    else
    {
        SecurityAlert(); // Gate not armed — fault detected
    }
}
```

**Element Necessity Table:**

| #   | Check                                           | Technique                      | Purpose                                         |
| --- | ----------------------------------------------- | ------------------------------ | ----------------------------------------------- |
| 1   | `a.val == b.val`                                | Primary comparison             | Basic equality check                            |
| 2   | Non-inlined `verify_delay()` call               | Branch Separation (2.5)        | Prevents single glitch spanning checks 1+3      |
| 3   | `b.val == (a.val_copy ^ MASK)`                  | Cross-redundancy (2.11)        | Validates val against the OTHER variable's copy |
| 4   | Non-inlined `verify_delay()` call               | Branch Separation (2.5)        | Prevents single glitch spanning checks 3+5      |
| 5   | `validate_secure(a)`                            | Self-consistency (2.11)        | Catches single-field corruption of secure_uint  |
| 6   | Non-inlined `verify_copies_match(&a, &b)`       | Non-Inlined Tail Call (2.5)    | Requires independent glitch to bypass           |
| 7   | `success_condition = 0x11111111` inside if-body | Condition-Gated Success (2.13) | Fall-through and branch-skip produce wrong gate |
| 8   | Gate check in `start_success_handling()`        | Condition-Gated Success (2.13) | Second barrier requiring independent fault      |

**All elements are independently necessary.** Removing any one has been demonstrated to re-introduce exploitable vulnerabilities in fault injection simulation campaigns (single and double fault, across glitch/regbf/regfld/cmdbf attack types).

**When to use:**
- As the standard template for any security-critical comparison (password check, signature verification, access control)
- When the system must withstand both single and double fault attacks
- As a starting point that can be extended with additional techniques (Secure Loop, Checkpoint Handling, etc.) depending on the threat model

**Additional notes:**
- This pattern was validated against: NOP glitches (1–10 instructions), single-bit register flips (R0–R12), register floods (0x00000000/0xFFFFFFFF), and single-bit instruction opcode flips.
- The `volatile` keyword on struct fields and separator variables is critical to prevent compiler optimization from collapsing or reordering checks.
- For additional protection against `memcmp` size corruption: if using `memcmp`, load the size from memory twice (using `volatile`) and cross-check both loads before calling the comparison function.

---

## Summary Matrix

| #   | Technique                 | Attack Type  | Protects Against                     | Complexity |
| --- | ------------------------- | ------------ | ------------------------------------ | ---------- |
| 1   | Secure Memory Compare     | Observative  | Timing attacks on comparisons        | Low        |
| 2   | Secure Memory Copy        | Observative  | Hamming weight leakage during copy   | Medium     |
| 3   | Unconditional Flow        | Observative  | Branch-based side-channel leakage    | Medium     |
| 4   | Variable Initialization   | Observative  | Exploitation of uninitialized memory | Low        |
| 5   | Statistic Data Hiding     | Observative  | SPA/DPA on fixed algorithms          | High       |
| 6   | Mathematical Data Hiding  | Observative  | Power analysis of cryptographic ops  | High       |
| 7   | Random Delay Handling     | Observative  | Trace alignment for DPA/templates    | Low        |
| 8   | Secure Boolean            | Manipulative | Bit-flip attacks on boolean flags    | Low        |
| 9   | Secure Loop               | Manipulative | Loop counter corruption              | Low        |
| 10  | Secure Return Parameter   | Manipulative | Register corruption on return        | Low        |
| 11  | Checkpoint Handling       | Manipulative | Skipping steps in sequences          | Medium     |
| 12  | Branch Protection         | Manipulative | Branch skipping via PC corruption    | Low        |
| 13  | Causal Chain Check        | Manipulative | Wrong function execution context     | Medium     |
| 14  | Function Signature Check  | Manipulative | Unauthorized function calls          | Medium     |
| 15  | Caller Gate Check         | Manipulative | ROP/JOP attacks                      | High       |
| 16  | Redundancy Call           | Manipulative | DFA on cryptographic operations      | Medium     |
| 17  | Sentinel Handling         | Manipulative | Address bus manipulation             | Medium     |
| 18  | Data Integrity Protection | Manipulative | Data/key tampering in memory         | Medium     |
| 19  | Pre-Penalization          | Manipulative | Countermeasure disruption            | Low        |
| 20  | Condition-Gated Success   | Manipulative | Branch skip reaching success path    | Medium     |
| 21  | Hardened Comparison       | Manipulative | Single + double fault on comparisons | High       |
