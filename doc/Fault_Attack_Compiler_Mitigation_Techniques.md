# Fault Attack Compiler Mitigation Techniques

This document catalogs all **compiler-specific techniques** used to influence code generation for security countermeasures. Unlike the secure coding techniques document (algorithmic patterns and data flow design), this file focuses exclusively on how to **control the compiler** — through keywords, attributes, flags, directives, and linker configuration — to produce machine code that resists fault injection attacks.

---

## Table of Contents

- [Fault Attack Compiler Mitigation Techniques](#fault-attack-compiler-mitigation-techniques)
  - [Table of Contents](#table-of-contents)
  - [1. The `volatile` Keyword](#1-the-volatile-keyword)
    - [1.1 Preventing Optimization of Security-Critical Reads](#11-preventing-optimization-of-security-critical-reads)
    - [1.2 Preventing Removal of Initializations](#12-preventing-removal-of-initializations)
    - [1.3 Preventing Register Caching of Comparison Operands](#13-preventing-register-caching-of-comparison-operands)
    - [1.4 Volatile Compound Literals for Immediate Reloads](#14-volatile-compound-literals-for-immediate-reloads)
  - [2. Function Attributes for Inlining Control](#2-function-attributes-for-inlining-control)
    - [2.1 `__attribute__((noinline))` — Enforcing Branch Separation](#21-__attribute__noinline--enforcing-branch-separation)
    - [2.2 `__attribute__((always_inline))` — Forcing Inline Expansion](#22-__attribute__always_inline--forcing-inline-expansion)
    - [2.3 Global `-fno-inline` with Selective `always_inline`](#23-global--fno-inline-with-selective-always_inline)
    - [2.4 Non-Inlined Function Calls to Force Stack Reload of Security-Critical Values](#24-non-inlined-function-calls-to-force-stack-reload-of-security-critical-values)
  - [3. Function Attributes for Code Generation Control](#3-function-attributes-for-code-generation-control)
    - [3.1 `__attribute__((noreturn))` — Preventing Fall-Through After Panic](#31-__attribute__noreturn--preventing-fall-through-after-panic)
    - [3.2 `__attribute__((used))` — Preventing Dead Code Elimination](#32-__attribute__used--preventing-dead-code-elimination)
    - [3.3 `__attribute__((weak))` — Allowing Link-Time Override](#33-__attribute__weak--allowing-link-time-override)
    - [3.4 `__attribute__((packed))` — Preventing Struct Padding](#34-__attribute__packed--preventing-struct-padding)
    - [3.5 `__attribute__((section("name")))` — Explicit Memory Section Placement](#35-__attribute__sectionname--explicit-memory-section-placement)
  - [4. Macros Instead of Functions for Security-Critical Comparisons](#4-macros-instead-of-functions-for-security-critical-comparisons)
    - [4.1 Macro-Based Comparison Chains](#41-macro-based-comparison-chains)
    - [4.2 GCC Statement Expressions for Complex Macros](#42-gcc-statement-expressions-for-complex-macros)
  - [5. Compile-Time Constants via `#define` Instead of Memory-Stored Values](#5-compile-time-constants-via-define-instead-of-memory-stored-values)
  - [6. Inline Assembly](#6-inline-assembly)
    - [6.1 GCC Inline Assembly Syntax](#61-gcc-inline-assembly-syntax)
    - [6.2 The `volatile` Qualifier on Inline Assembly](#62-the-volatile-qualifier-on-inline-assembly)
    - [6.3 Embedding Labels in Binary (`FIH_LABEL`)](#63-embedding-labels-in-binary-fih_label)
    - [6.4 Redundant Branch Instructions for Panic Loops](#64-redundant-branch-instructions-for-panic-loops)
    - [6.5 Global Labels at Call Sites for Caller Gate Checks](#65-global-labels-at-call-sites-for-caller-gate-checks)
    - [6.6 Inline Assembly as a Compiler Optimization Barrier](#66-inline-assembly-as-a-compiler-optimization-barrier)
    - [6.7 Preventing Compiler Replacement of Security-Critical Sequences](#67-preventing-compiler-replacement-of-security-critical-sequences)
    - [6.8 Standalone Assembly Files for Entry Points](#68-standalone-assembly-files-for-entry-points)
  - [7. GCC Built-in Functions](#7-gcc-built-in-functions)
    - [7.1 `__builtin_return_address(0)` — Reading the Return Address](#71-__builtin_return_address0--reading-the-return-address)
  - [8. Compiler Flags for Security-Hardened Code Generation](#8-compiler-flags-for-security-hardened-code-generation)
    - [8.1 `-fno-inline` — Disable Global Inlining](#81--fno-inline--disable-global-inlining)
    - [8.2 `-fno-omit-frame-pointer` — Preserve Frame Pointer](#82--fno-omit-frame-pointer--preserve-frame-pointer)
    - [8.3 `-fno-ipa-cp-clone` and `-fno-ipa-cp` — Disable Interprocedural Constant Propagation](#83--fno-ipa-cp-clone-and--fno-ipa-cp--disable-interprocedural-constant-propagation)
    - [8.4 `-fno-common` — Prevent Tentative Definitions](#84--fno-common--prevent-tentative-definitions)
    - [8.5 `-fno-builtin` — Disable Built-in Function Replacement](#85--fno-builtin--disable-built-in-function-replacement)
    - [8.6 `-ffreestanding` — Freestanding Environment](#86--ffreestanding--freestanding-environment)
    - [8.7 `-fno-stack-protector` — Disable Stack Canaries](#87--fno-stack-protector--disable-stack-canaries)
    - [8.8 `-ftrivial-auto-var-init=zero` — Compiler-Driven Stack Variable Initialization](#88--ftrivial-auto-var-initzero--compiler-driven-stack-variable-initialization)
    - [8.9 `-fno-delete-null-pointer-checks` — Prevent Removal of Null Pointer Checks](#89--fno-delete-null-pointer-checks--prevent-removal-of-null-pointer-checks)
    - [8.10 `-fno-strict-overflow` / `-fwrapv` — Prevent Signed Overflow Optimization](#810--fno-strict-overflow---fwrapv--prevent-signed-overflow-optimization)
    - [8.11 `-fno-strict-aliasing` — Prevent Type-Based Alias Analysis](#811--fno-strict-aliasing--prevent-type-based-alias-analysis)
    - [8.12 `-fno-optimize-sibling-calls` — Disable Tail Call Optimization](#812--fno-optimize-sibling-calls--disable-tail-call-optimization)
    - [8.13 `-fno-jump-tables` — Prevent Jump Table Generation for Switch Statements](#813--fno-jump-tables--prevent-jump-table-generation-for-switch-statements)
    - [8.14 `-fno-reorder-blocks` / `-fno-reorder-functions` — Prevent Code Block Reordering](#814--fno-reorder-blocks---fno-reorder-functions--prevent-code-block-reordering)
    - [8.15 `-fhardened` — GCC Umbrella Hardening Flag (GCC 14+)](#815--fhardened--gcc-umbrella-hardening-flag-gcc-14)
  - [9. Linker Flags and Configuration](#9-linker-flags-and-configuration)
    - [9.1 `-nostartfiles` and `-nodefaultlibs` — No Default Runtime](#91--nostartfiles-and--nodefaultlibs--no-default-runtime)
    - [9.2 `-N` — Writable Text Segment](#92--n--writable-text-segment)
    - [9.3 `-Wl,--build-id=none` — Remove Build Metadata](#93--wl--build-idnone--remove-build-metadata)
    - [9.4 Custom Linker Script for Memory Layout Control](#94-custom-linker-script-for-memory-layout-control)
  - [10. The `register` Keyword](#10-the-register-keyword)
  - [11. Preprocessor-Driven Security Profile Selection](#11-preprocessor-driven-security-profile-selection)
  - [Summary Matrix](#summary-matrix)

---

## 1. The `volatile` Keyword

The `volatile` keyword is the most fundamental compiler technique for fault injection hardening. It prevents the compiler from optimizing away security-critical memory accesses, ensuring that every read and write in the source code translates to an actual load/store instruction in the generated machine code.

---

### 1.1 Preventing Optimization of Security-Critical Reads

**Problem:** When a variable is read multiple times (e.g., in a double-check pattern), the compiler may optimize away the second read and reuse the cached register value. This defeats branch protection because both checks use the same potentially-corrupted register value.

**Solution:** Declare security-critical variables as `volatile` to force the compiler to generate a memory load for every access.

**Code Pattern:**

```c
// WITHOUT volatile — compiler may cache the value in a register
uint32_t fPassComp = PasswordCheck();
if (fPassComp == SEC_TRUE) {
    if (fPassComp == SEC_TRUE)  // Compiler may optimize this away!
        LoadFile();
}

// WITH volatile — compiler generates a fresh memory load each time
volatile uint32_t fPassComp = PasswordCheck();
if (fPassComp == SEC_TRUE) {
    if (fPassComp == SEC_TRUE)  // Forces re-read from memory
        LoadFile();
}
```

**When to use:**
- All variables involved in double-check / branch protection patterns
- Security decision variables (pass/fail flags)
- Any variable where register caching could mask a fault

**Assembly impact:** Without `volatile`, two consecutive reads compile to one `ldr` + reuse. With `volatile`, each read compiles to a separate `ldr` instruction from memory.

---

### 1.2 Preventing Removal of Initializations

**Problem:** The compiler may remove variable initializations it considers redundant (e.g., a variable set to a safe default that is immediately overwritten by a function return value). An attacker exploiting uninitialized memory depends on the compiler removing such initializations.

**Solution:** Use `volatile` on the initialization to prevent the compiler from optimizing it away.

**Code Pattern:**

```c
// Compiler may remove this initialization if it sees PasswordCheck() always writes fRet
volatile BOOL DataResult = INIT;
DataResult = PasswordCheck();

// Gate variable must retain its non-success initial value
volatile uint32_t success_condition = 0x22222222;
```

**When to use:**
- Secure boolean variables initialized to INIT state
- Gate variables for condition-gated success patterns
- Key/hash buffers pre-filled with random data before use

---

### 1.3 Preventing Register Caching of Comparison Operands

**Problem:** In redundant data types (value + XOR-masked copy), the compiler may optimize a consistency check by comparing against a cached register value rather than re-loading from memory. A single fault corrupting the register defeats both checks.

**Solution:** Declare struct fields as `volatile` to force each access to generate its own memory load instruction.

**Code Pattern:**

```c
typedef struct {
    volatile uint32_t val;       // Forces fresh load for each access
    volatile uint32_t val_copy;  // Forces fresh load for each access
} secure_uint;

// The volatile fields ensure each comparison in this chain
// generates an independent ldr instruction:
if ((a.val == b.val) &&                        // ldr + ldr + cmp
    (a.val_copy == b.val_copy) &&              // ldr + ldr + cmp
    ((a.val ^ MASK) == (b.val ^ MASK)))        // ldr + ldr + eor + cmp
```

**When to use:**
- All fields of redundant data structures (`secure_uint`, `fih_uint`)
- Separator variables used between comparison checks
- Loop counter variables in secure loops

---

### 1.4 Volatile Compound Literals for Immediate Reloads

**Problem:** When a `#define` constant is used in multiple comparisons, the compiler may compute it once and reuse the register value. This creates a single point of failure.

**Solution:** Use volatile compound literals to force the compiler to regenerate the value for each use.

**Code Pattern:**

```c
// Standard #define — compiler may cache the value
#define success 0x01234567

// Volatile compound literal — forces fresh computation each use
#define success ((volatile uint32_t){0x01234567})

// Each use of 'success' now generates an independent mov/ldr instruction
if (DECISION_DATA == success) { ... }   // Fresh load of 0x01234567
if (DECISION_DATA != success) { ... }   // Another fresh load of 0x01234567
```

**When to use:**
- Comparison constants used in double-check patterns
- Any constant compared against security-critical data multiple times

---

## 2. Function Attributes for Inlining Control

Inlining control is critical for fault injection resistance. Whether a function is inlined or not determines the spatial layout of comparison instructions in the binary, which directly affects how many instructions an attacker must glitch simultaneously.

---

### 2.1 `__attribute__((noinline))` — Enforcing Branch Separation

**Problem:** If two comparison checks are adjacent in memory, a single NOP glitch spanning 2–3 instructions can skip both. The compiler may inline helper functions, placing all checks contiguously.

**Solution:** Mark separator functions and tail-call checks with `__attribute__((noinline))` to force the compiler to generate a `bl` (branch-and-link) instruction, creating spatial separation in the binary.

**Code Pattern:**

```c
// Separator function — forces a bl instruction between adjacent checks
__attribute__((noinline)) bool verify_delay(volatile uint32_t *v) {
    return (*v != 0);
}

// Tail-call check — requires an independent glitch to bypass
__attribute__((noinline)) bool verify_copies_match(secure_uint *a, secure_uint *b) {
    return a->val_copy == b->val_copy;
}

// Non-inlined utility functions preserve their own stack frame
int __attribute__((noinline))
memcmp(const void *str1, const void *str2, size_t count);

// Non-inlined panic handler
__attribute__((noinline))
void fih_panic_loop(void);

// Non-inlined activation function (prevents optimizer from removing the call)
__attribute__((used, noinline)) void decision_activation(void) {}
```

**When to use:**
- Branch separator functions inserted between security-critical comparisons
- Non-inlined tail calls at the end of comparison chains
- Functions that must create a code-location barrier (the `bl` instruction jumps to a different address range)
- Library functions (`memcmp`, `memcpy`, `memset`) that must not be replaced with inline sequences

**Assembly impact:** A `bl` instruction jumps to a completely different address in the binary. Glitching past it requires the attacker to know and target the specific function location, not just skip adjacent instructions.

---

### 2.2 `__attribute__((always_inline))` — Forcing Inline Expansion

**Problem:** When a security-critical comparison function is called normally (not inlined), ALL arguments must be pre-loaded into registers (`r0`–`r3`) BEFORE the `bl` instruction. This creates a concentrated vulnerability: glitching a single `ldm` or `ldr` instruction can cause the function to receive stale/wrong register values. Additionally, glitching the `bl` itself means the comparison never executes, and the stale `r0` (which may be truthy) is used as the result.

**Solution:** Force inline expansion with `__attribute__((always_inline))` so comparison logic is expanded directly in the caller. Arguments are loaded incrementally, one per check, and there is no single `bl` that can be glitched to skip all checks.

**Code Pattern:**

```c
// Validation function — MUST be inlined to avoid pre-loaded register vulnerability
__attribute__((always_inline)) static inline
bool fih_uint_validate(fih_uint x)
{
    uint32_t x_msk = FIH_UINT_VAL_MASK(x.msk);
    if (x.val != x_msk) {
        FIH_PANIC;
    }
    return true;
}

// Encoding/decoding — inlined to prevent function call overhead and vulnerability
__attribute__((always_inline)) static inline
uint32_t fih_uint_decode(fih_uint x) { ... }

__attribute__((always_inline)) static inline
fih_uint fih_uint_encode(uint32_t x) { ... }

// Arithmetic on hardened types — inlined for same reason
__attribute__((always_inline)) static inline
fih_uint fih_uint_add(fih_uint x, fih_uint y) { ... }

__attribute__((always_inline)) static inline
fih_uint fih_uint_or(fih_uint x, fih_uint y) { ... }
```

**When to use:**
- Self-consistency validation functions (`fih_uint_validate`)
- Encoding/decoding of hardened data types
- Arithmetic operations on hardened types
- Any function whose logic must be physically embedded in the caller's instruction stream

**Important note from the header:**
> *"For functions to be inlined outside their compilation unit they have to have the body in the header file. This is required as function calls are easy to skip."*

---

### 2.3 Global `-fno-inline` with Selective `always_inline`

**Strategy:** The project uses a two-layer inlining strategy:

1. **Globally disable inlining** via the `-fno-inline` compiler flag — this ensures that by default, no function is inlined, and every call generates a `bl` instruction
2. **Selectively force inlining** via `__attribute__((always_inline))` for specific security-critical functions that MUST be expanded in the caller

This gives precise control: separator functions stay as real function calls (creating spatial barriers), while validation/comparison logic is always expanded inline (avoiding the pre-loaded register vulnerability).

**From the Makefile:**

```make
CFLAGS = ... -fno-inline ...
CFLAGS_LD = ... -fno-inline ...
```

**Functions forced inline despite `-fno-inline`:**
- `fih_uint_validate()` — Self-consistency checks
- `fih_uint_decode()` / `fih_uint_encode()` — Type conversion
- `fih_uint_add()` / `fih_uint_or()` / `fih_uint_and()` — Arithmetic operations
- `fih_uint_val()` / `fih_uint_msk()` — Field accessors

**Functions kept non-inlined intentionally:**
- `verify_delay()` — Branch separator
- `verify_copies_match()` — Tail-call check
- `check_equal_mask()` — Non-inlined comparison check
- `fih_panic_loop()` — Panic handler
- `memcmp()`, `memcpy()`, `memset()` — Library functions
- `serial_putc()` — I/O function

---

### 2.4 Non-Inlined Function Calls to Force Stack Reload of Security-Critical Values

**Problem:** On ARM (and most architectures), the calling convention defines **caller-saved registers** (`r0`–`r3`, `r12` on ARM) that any called function is free to overwrite. When the compiler keeps security-critical values in these registers across a sequence of inline checks, a single register fault (bit-flip or flood) can corrupt the value for all subsequent checks. The compiler has no reason to reload the value from memory because, from its perspective, the register still holds the correct data.

**Solution:** Insert a `__attribute__((noinline))` function call between security-critical checks. The ARM calling convention forces the compiler to:

1. **Spill (save)** any caller-saved registers it still needs to the **stack** before the `bl` instruction
2. **Execute** the called function (which may freely overwrite `r0`–`r3`)
3. **Reload** the saved values from the **stack** back into registers after the function returns

This stack spill/reload cycle means that after the function call, the security-critical values are **freshly loaded from memory**, not carried over in potentially-corrupted registers. A register fault that occurred before the call is effectively "washed out" by the reload.

**How the ARM calling convention drives this:**

| Register | Convention     | Effect of `noinline` call                                              |
| -------- | -------------- | ---------------------------------------------------------------------- |
| `r0`–`r3`  | Caller-saved | Compiler must save to stack before call, reload after call             |
| `r4`–`r11` | Callee-saved | Called function saves/restores these — caller's values survive in registers, but the called function's prologue/epilogue creates a stack interaction |
| `r12` (IP)  | Scratch      | Destroyed by call — compiler reloads if needed                         |
| `r14` (LR)  | Link register | Overwritten by `bl` — pushed to stack in called function's prologue    |

**Code Pattern — `verify_delay()` as a register flush point:**

```c
__attribute__((noinline)) bool verify_delay(volatile uint32_t *v) {
    return (*v != 0);  // Always returns true in normal operation
}

// In a comparison chain:
if (
    (a.val == b.val) &&               // a.val, b.val loaded into r0-r3
    verify_delay(&sep) &&             // bl → compiler spills a, b to stack
                                      //       r0-r3 are now "dirty"
                                      //       after return: compiler reloads a, b from stack
    (a.val_copy == b.val_copy) &&     // Fresh ldr from stack — not stale register!
    verify_delay(&sep) &&             // Another spill/reload cycle
    validate_secure(a) &&             // Fresh values again
    verify_copies_match(&a, &b)       // Arguments loaded fresh for the call
)
```

**Generated assembly illustration (conceptual):**

```asm
; Check 1: a.val == b.val
ldr   r0, [sp, #offset_a_val]     ; load a.val
ldr   r1, [sp, #offset_b_val]     ; load b.val
cmp   r0, r1
bne   fail

; verify_delay() call — forces register spill/reload
str   r4, [sp, #save_area]        ; spill callee-saved regs if needed
ldr   r0, [sp, #offset_sep]       ; load argument for verify_delay
bl    verify_delay                 ; call — r0-r3 are now destroyed
                                   ; after return: must reload everything

; Check 2: a.val_copy == b.val_copy — values freshly loaded from stack
ldr   r0, [sp, #offset_a_copy]    ; FRESH load from stack, not stale register
ldr   r1, [sp, #offset_b_copy]    ; FRESH load from stack
cmp   r0, r1
bne   fail
```

**Why this defeats register-based fault attacks:**

- **Without the `noinline` call:** The compiler may keep `a.val` in `r4` across all checks. A single `regbf` (register bit-flip) on `r4` before the first check corrupts the value for ALL subsequent checks that reuse it.
- **With the `noinline` call:** After `verify_delay()` returns, the compiler must reload `a.val` (or whichever values it needs) from the stack. Even if `r4` was corrupted before the call, the reload fetches the uncorrupted value from memory. The attacker would need a **separate fault** targeting the reload or the stack memory itself.

**Combined effect with `volatile` struct fields:**

When the `secure_uint` fields are `volatile`, the compiler cannot keep them in registers at all — each access is a memory load. The `noinline` function call adds a second layer: even if the compiler temporarily caches a non-volatile intermediate value in a register, the call boundary forces it back to stack/memory.

**When to use:**
- Between security-critical comparison checks to force register refresh (the `verify_delay()` pattern)
- Before a final tail-call check to ensure arguments are loaded fresh from memory, not from stale registers
- In any comparison chain where the same data is checked multiple times — the function call between checks ensures each check operates on independently-loaded values
- When combining with branch separation — the `noinline` call provides both spatial separation AND register flush in one mechanism

**Additional notes:**
- This technique is a direct consequence of the ARM ABI (AAPCS) calling convention and works on any architecture with caller-saved registers
- The effect is strongest on ARM Cortex-M where `r0`–`r3` are caller-saved — these are exactly the registers used for function arguments and comparison operands
- Even callee-saved registers (`r4`–`r11`) benefit indirectly: the called function's prologue pushes them to stack, creating a stack write that could be verified
- The `volatile uint32_t *v` parameter in `verify_delay()` serves a dual purpose: it gives the function a side effect (memory read) that prevents the compiler from optimizing the call away, and it forces at least one register to carry the pointer argument

---

## 3. Function Attributes for Code Generation Control

---

### 3.1 `__attribute__((noreturn))` — Preventing Fall-Through After Panic

**Problem:** When a panic/failure function returns normally, the compiler generates code after the call site that may be reachable via fall-through. An attacker who glitches past the panic call lands on this unintended code.

**Solution:** Mark panic functions with `__attribute__((noreturn))` so the compiler knows no code after the call is reachable. The compiler will not generate fall-through instructions after calls to this function.

**Code Pattern:**

```c
__attribute__((noinline))
__attribute__((noreturn))
void fih_panic_loop(void)
{
    // Multiple redundant branch instructions (see Section 6.2)
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    // ...
    while (true) {} /* Satisfy noreturn */
}
```

**When to use:**
- All panic/failure handler functions
- Security alert functions that must halt the system
- Any function that should never return to its caller

---

### 3.2 `__attribute__((used))` — Preventing Dead Code Elimination

**Problem:** The compiler may remove functions or variables that appear unused in the current compilation unit, even if they are needed at runtime (e.g., called indirectly, referenced by the simulator, or required for side effects).

**Solution:** Mark such functions with `__attribute__((used))` to prevent the compiler from eliminating them.

**Code Pattern:**

```c
// The decision_activation function has an empty body but must exist in the binary
__attribute__((used, noinline)) void decision_activation(void) {}
```

**When to use:**
- Functions called by external tools (simulators, debuggers)
- Functions with empty bodies that serve as markers or hooks
- Variables or functions referenced only indirectly

---

### 3.3 `__attribute__((weak))` — Allowing Link-Time Override

**Problem:** A hardened library may provide a default panic handler, but the application may need to customize it (e.g., adding device-specific lockout behavior). Without `weak`, providing a second definition causes a linker error.

**Solution:** Mark the default implementation with `__attribute__((weak))` so the linker replaces it with any non-weak definition provided by the application.

**Code Pattern:**

```c
__attribute__((noinline))
__attribute__((noreturn))
__attribute__((weak))
void fih_panic_loop(void)
{
    // Default implementation — can be overridden by the application
    __asm volatile ("b fih_panic_loop");
    // ...
}
```

**When to use:**
- Default panic/security alert handlers in libraries
- Default configuration functions that applications may override
- Any function where the library provides a fallback but the application should be able to customize behavior

---

### 3.4 `__attribute__((packed))` — Preventing Struct Padding

**Problem:** The compiler may insert padding bytes between struct fields for alignment. In security-critical data structures, these padding bytes create hidden memory that an attacker could exploit (e.g., padding between fields could be corrupted without detection, or struct size assumptions in memcmp/memcpy could be wrong).

**Solution:** Use `__attribute__((packed))` to eliminate all padding, ensuring the struct layout is exactly as defined.

**Code Pattern:**

```c
#define DECISION_DATA_STRUCTURE(element_type, success, failure)                \
  typedef struct __attribute__((packed)) {                                     \
    uint32_t decision_element_size;                                            \
    element_type data_element;                                                 \
    element_type success_data_element;                                         \
    element_type failure_data_element;                                         \
  } decision_data;                                                             \
  decision_data decisiondata = {sizeof(element_type), failure, success, failure}
```

**When to use:**
- Data structures compared byte-by-byte (e.g., with `memcmp`)
- Structures whose exact memory layout is security-relevant
- Structures shared between different compilation units or architectures

---

### 3.5 `__attribute__((section("name")))` — Explicit Memory Section Placement

**Purpose:** Place specific functions or data in named linker sections to control their physical memory location. This gives fine-grained control over where code and data reside, complementing the custom linker script (Section 9.4).

**Security rationale:**
- Panic handlers can be placed in a separate section away from normal control flow, preventing an attacker from reaching them via simple fall-through glitches
- Security-critical lookup tables or constants can be placed in a read-only section in a different memory bank, making them harder to corrupt with a single fault
- Separation of security-critical code from normal code can be verified at link time or during post-build analysis

**Code Pattern:**

```c
// Place panic handler in a dedicated section
__attribute__((section(".security_critical"), noinline, noreturn))
void fih_panic_loop(void) {
    __asm volatile ("b fih_panic_loop");
    while (1) {}
}

// Place security constants in a specific read-only section
__attribute__((section(".security_rodata")))
static const uint32_t security_keys[] = { 0xDEADBEEF, 0xCAFEBABE };

// In the linker script, map these sections to specific memory regions:
// .security_critical : { *(.security_critical) } > SECURE_FLASH
// .security_rodata   : { *(.security_rodata) }   > SECURE_FLASH
```

**When to use:**
- Placing security-critical functions in separate memory banks for hardware isolation
- Placing constants in guaranteed read-only memory regions
- Separating security code from normal code for post-build verification
- Ensuring specific alignment or address placement of security routines

---

## 4. Macros Instead of Functions for Security-Critical Comparisons

---

### 4.1 Macro-Based Comparison Chains

**Problem:** A comparison function receives all arguments via registers before the `bl` instruction. A single glitch on the `bl` skips the entire comparison. Even if the function executes, all arguments are pre-loaded, creating a concentrated vulnerability window.

**Solution:** Use `#define` macros instead of functions for comparison chains. The preprocessor expands the macro directly in the caller's code, so each comparison operand is loaded incrementally, one per check. There is no single `bl` instruction that can be glitched to skip all checks.

**Code Pattern:**

```c
// Comparison as a MACRO — expands inline in the caller
#define fih_uint_eq(x, y)  \
    (fih_uint_validate(x)  && \
     fih_uint_validate(y) && \
     ((x).val == (y).val) && \
     fih_delay() && \
     ((x).msk == (y).msk) && \
     fih_delay() && \
     ((x).val == FIH_UINT_VAL_MASK((y).msk)))

// Custom comparison macro with non-inlined separator calls
#define fih_uint_eq_new(x, y)                  \
    ((x.val == y.val) &&                       \
     fih_delay() &&                            \
     ((y).val == FIH_UINT_VAL_MASK(x.msk)) && \
     fih_delay() &&                            \
     fih_uint_validate(x) &&                   \
     check_equal_mask(&x, &y))
```

**Why macros are preferred over functions for comparisons:**
- Each `&&` in the expanded macro generates a **separate branch instruction** in the caller
- Arguments are loaded incrementally from memory, not pre-loaded into registers
- There is no single `bl` instruction to glitch
- The final element can be a non-inlined function call (tail call), creating a function boundary

**When to use:**
- All hardened equality/inequality/comparison operations on redundant data types
- Any comparison chain that must be resistant to single-instruction glitches

---

### 4.2 GCC Statement Expressions for Complex Macros

**Problem:** Standard C macros with `&&` chains cannot easily store intermediate results or use control flow (if/else). The MISRA-C coding standard also requires specific code patterns that don't fit into simple expression macros.

**Solution:** Use GCC statement expressions (`({ ... })`) to create macros that behave like functions (with local variables and control flow) but still expand inline in the caller.

**Code Pattern:**

```c
#define fih_uint_eq(x, y)                                     \
    ({                                                        \
        bool register result;                                 \
                                                              \
        result = fih_uint_validate(x);                        \
                                                              \
        if (result)                                           \
        {                                                     \
            result = fih_uint_validate(y);                    \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val == (y).val);                    \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).msk == (y).msk);                    \
        }                                                     \
        /* ... more checks ... */                             \
                                                              \
        result;  /* Return value of the statement expression */\
    })
```

**When to use:**
- When MISRA-C compliance requires if/else instead of `&&` chains
- When intermediate state must be tracked within a comparison macro
- When the macro needs local variables

**Note:** GCC statement expressions are a GCC extension, not standard C. They are widely supported by GCC and Clang but not by all compilers.

---

## 5. Compile-Time Constants via `#define` Instead of Memory-Stored Values

**Problem:** If the "correct" value (e.g., expected password hash, success indicator) is stored in memory as a data variable, an attacker can corrupt a data pointer to read the success value instead of the actual data, or directly manipulate the reference data.

**Solution:** Use `#define` constants so the compiler encodes the value directly as an immediate operand in `cmp` or `mov` instructions. The value exists only in the instruction stream (`.text` section), never as addressable data in memory.

**Code Pattern:**

```c
// INSECURE: Stored in memory as data — addressable and corruptible
const uint32_t success_value = 0x01234567;
if (data == success_value) { ... }  // ldr r1, [success_value_addr]; cmp r0, r1

// SECURE: Encoded as instruction immediate — not stored in data memory
#define SUCCESS_VALUE 0x01234567
if (data == SUCCESS_VALUE) { ... }  // movw r1, #0x4567; movt r1, #0x0123; cmp r0, r1
```

**Assembly impact:** The constant becomes part of the instruction opcode itself. To change it, the attacker would need a command bit-flip (cmdbf) attack targeting the specific instruction, which is harder than corrupting a data pointer.

**When to use:**
- Reference values for security-critical comparisons
- Failure/success indicator constants
- Any constant where the attacker could benefit from it being stored as addressable data

---

## 6. Inline Assembly

GCC inline assembly (`__asm` / `asm`) allows embedding processor instructions directly inside C source code. In the context of fault injection hardening, inline assembly serves a fundamentally different role than in performance optimization: it provides **precise control over the generated machine code** in situations where the C language cannot guarantee the required instruction sequence, and it prevents the compiler from transforming security-critical code in unsafe ways.

---

### 6.1 GCC Inline Assembly Syntax

GCC inline assembly uses the extended syntax:

```c
__asm volatile ( "assembly template"
    : output operands       /* optional */
    : input operands        /* optional */
    : clobber list           /* optional */
);
```

**Components:**

| Component          | Purpose                                                                     | Example                     |
| ------------------ | --------------------------------------------------------------------------- | --------------------------- |
| Assembly template  | The actual assembly instruction(s) as a string literal                      | `"b fih_panic_loop"`        |
| Output operands    | C variables written by the assembly (after first `:`)                       | `"=r" (result)`             |
| Input operands     | C variables read by the assembly (after second `:`)                         | `"r" (value)`               |
| Clobber list       | Registers or resources modified by the assembly (after third `:`)           | `"memory"`, `"cc"`          |
| `volatile`         | Keyword preventing the compiler from removing, reordering, or duplicating the statement | —           |

**The `volatile` keyword on `__asm` is critical for security.** Without it, the compiler treats inline assembly as a pure computation and may:
- **Remove it** if the output appears unused
- **Move it** across other statements during optimization
- **Duplicate or merge** multiple identical `__asm` statements

For security-hardened code, virtually every inline assembly statement must be `volatile`.

**Minimal syntax variants used in this project:**

```c
// No operands — just emit an instruction, never optimize away
__asm volatile ("b fih_panic_loop");

// Empty operand lists (:: means no outputs, no inputs)
__asm volatile ("FIH_LABEL_SOME_NAME_0_%=:" ::);

// With .global directive and newline separators
asm(".global _symbol_name\n\t"
    "_symbol_name:\n\t");
```

---

### 6.2 The `volatile` Qualifier on Inline Assembly

**Problem:** The compiler's optimizer treats non-volatile inline assembly as a black-box computation. If the result is unused, the entire assembly block is removed. If two blocks are identical, they may be merged. For security countermeasures, every single assembly statement must execute exactly as written.

**Solution:** Always use `__asm volatile` for security-relevant inline assembly.

**Example — why `volatile` matters for redundant branches:**

```c
// WITHOUT volatile — compiler may reduce 9 identical branches to 1
__asm ("b fih_panic_loop");  // Compiler: "These are all the same, keep one"
__asm ("b fih_panic_loop");
__asm ("b fih_panic_loop");

// WITH volatile — compiler must emit all 9 branches exactly as written
__asm volatile ("b fih_panic_loop");  // All three are emitted
__asm volatile ("b fih_panic_loop");
__asm volatile ("b fih_panic_loop");
```

**Example — why `volatile` matters for labels:**

```c
// WITHOUT volatile — compiler may remove this "dead" label
__asm ("FIH_LABEL_SOME_NAME:" ::);

// WITH volatile — label is always emitted into the binary
__asm volatile ("FIH_LABEL_SOME_NAME:" ::);
```

**Rule:** In this codebase, `__asm volatile` is used for every inline assembly statement. There are no cases where non-volatile inline assembly is appropriate for security code.

---

### 6.3 Embedding Labels in Binary (`FIH_LABEL`)

**Purpose:** Embed human-readable markers into the compiled binary that can be found by testing tools (fault simulators, debuggers) without requiring debug symbols. The labels are encoded as assembly labels with a specific naming convention.

**Code Pattern:**

```c
#define FIH_LABEL(str) __asm volatile ("FIH_LABEL_" str "_0_%=:" ::)
#define FIH_LABEL_CRITICAL_POINT() FIH_LABEL("FIH_CRITICAL_POINT")

// Usage in macro wrappers:
#define FIH_UCALL(f, ret, ...) \
    do { \
        FIH_LABEL("FIH_CALL_START_" # f); \
        /* ... function call with CFI ... */ \
        FIH_LABEL("FIH_CALL_END"); \
    } while (false)
```

**Key details:**
- `__asm volatile` prevents the compiler from removing or reordering the label
- `%=` generates a unique number per expansion, avoiding duplicate labels when the macro is used multiple times
- The `::` (empty output and input operand lists) tells the compiler this assembly has no data dependencies on C variables
- Labels are parsable from the ELF symbol table without debug symbols
- C preprocessor string concatenation (`"FIH_LABEL_" str "_0_%=:"`) builds the label name at compile time — the `str` parameter and `#f` (stringification operator) are expanded before the string is passed to the assembler

**How the preprocessor and assembler interact:**

```c
// Given this call:
FIH_LABEL("FIH_CALL_START_" # func1);

// Step 1 — Preprocessor stringification: # func1 → "func1"
// Step 2 — Preprocessor string concatenation:
//   "FIH_LABEL_" "FIH_CALL_START_" "func1" "_0_%=:"
//   → "FIH_LABEL_FIH_CALL_START_func1_0_%=:"
// Step 3 — GCC replaces %= with a unique number (e.g., 42):
//   → "FIH_LABEL_FIH_CALL_START_func1_0_42:"
// Step 4 — Assembler emits this as a local label in the .text section
```

---

### 6.4 Redundant Branch Instructions for Panic Loops

**Problem:** A single `b` (branch) instruction for a panic loop can be glitched (NOP'd), allowing execution to continue past the loop. The attacker only needs to skip one instruction.

**Solution:** Emit multiple redundant `b` instructions via inline assembly. To escape the loop, the attacker would need to glitch all of them simultaneously.

**Code Pattern:**

```c
__attribute__((noinline))
__attribute__((noreturn))
void fih_panic_loop(void)
{
    FIH_LABEL("FAILURE_LOOP");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    __asm volatile ("b fih_panic_loop");
    while (true) {}
}
```

**Why 9 `b` instructions:** Each `b` instruction is 2 or 4 bytes (Thumb mode). The largest NOP glitch in the simulator skips 10 instructions. With 9 redundant branches, even a 10-instruction glitch still leaves at least one branch intact (depending on alignment). The `while(true)` at the end also serves as a fallback.

**Why inline assembly instead of C loops:** A C `while(1){}` loop compiles to a single `b` instruction. Writing `while(1){}` nine times would likely be merged by the compiler into one branch. Each `__asm volatile` is an opaque, non-removable instruction — the compiler cannot merge, reorder, or optimize them.

**When to use:**
- All panic/security alert infinite loops
- Any code path that must guarantee the CPU never proceeds past it

---

### 6.5 Global Labels at Call Sites for Caller Gate Checks

**Purpose:** Place a known symbol at the exact instruction address following a function call, so the called function can verify its return address matches an authorized caller.

**Code Pattern:**

```c
void func_a(void)
{
    func_b();
    // Label placed at the return address
    asm(".global _func_a_call_return_func_b\n\t"
        "_func_a_call_return_func_b:\n\t");
}
```

**Inline assembly details:**
- `.global _symbol_name` is an assembler directive that exports the label to the ELF symbol table, making it visible to other compilation units and accessible via `extern void symbol_name()`
- `\n\t` are newline and tab characters that format the assembly output (each directive needs its own line)
- The label is placed immediately after the `bl` instruction generated by `func_b()`, so it points to the exact return address

**When to use:**
- High-security functions that must only be callable from specific locations
- Protection against ROP/JOP attacks

---

### 6.6 Inline Assembly as a Compiler Optimization Barrier

**Purpose:** Inline assembly acts as an opaque barrier that the compiler cannot see through. The compiler must assume that `__asm volatile` statements may read or write any memory (when a `"memory"` clobber is used) and cannot reorder C code across them.

**Security application — preventing reordering of security operations:**

```c
// The compiler is free to reorder these two C statements:
sentinel_check();
read_key(dest);

// With an inline assembly barrier, the order is guaranteed:
sentinel_check();
__asm volatile ("" ::: "memory");  // Memory barrier — compiler cannot reorder across this
read_key(dest);
```

**The `"memory"` clobber:** Tells the compiler that the assembly may read or write any memory location. This forces the compiler to:
1. **Flush** all cached values to memory before the `__asm` statement
2. **Reload** all values from memory after the `__asm` statement
3. **Not reorder** memory operations across the barrier

**Code Pattern — empty instruction as a pure barrier:**

```c
// No actual instruction emitted — only constrains the compiler's optimizer
__asm volatile ("" ::: "memory");
```

This generates zero machine instructions but prevents the compiler from moving loads/stores across the barrier. This is useful when the order of security operations matters (e.g., checking a sentinel before reading a key, or incrementing a checkpoint counter before calling a function).

**When to use:**
- Enforcing strict ordering of security-critical operations that the compiler might otherwise reorder
- Preventing the compiler from caching values across a security boundary
- Complementing `volatile` variables when memory ordering (not just variable access) must be guaranteed

---

### 6.7 Preventing Compiler Replacement of Security-Critical Sequences

**Problem:** The compiler may recognize certain instruction patterns and replace them with "equivalent" but less secure alternatives. For example:
- A constant-time comparison loop might be replaced with a SIMD instruction
- A randomized copy order might be rearranged into sequential access
- A specific branch pattern might be converted to a conditional move

**Solution:** Implement the critical sequence directly in inline assembly, where the compiler cannot transform it.

**Code Pattern — security-critical operations that should be implemented in assembly when maximum security is required:**

```c
// C version — compiler may reorder the copy operations
void CopyKeyData(uint8_t *dest, uint8_t *source) {
    uint16_t wXorMask = rand() & (KEY_LENGTH - 1);
    for (uint16_t i = 0; i < KEY_LENGTH; i++) {
        dest[i ^ wXorMask] = source[i ^ wXorMask];
    }
}

// Inline assembly version — exact instruction sequence is guaranteed
// (Conceptual — architecture-specific implementation required)
void CopyKeyData(uint8_t *dest, uint8_t *source) {
    uint16_t wXorMask = rand() & (KEY_LENGTH - 1);
    for (uint16_t i = 0; i < KEY_LENGTH; i++) {
        uint16_t idx = i ^ wXorMask;
        __asm volatile (
            "ldrb r2, [%[src], %[idx]]  \n\t"
            "strb r2, [%[dst], %[idx]]  \n\t"
            :                                        /* no outputs */
            : [src] "r" (source),                    /* input: source pointer */
              [dst] "r" (dest),                      /* input: dest pointer */
              [idx] "r" ((uint32_t)idx)              /* input: XOR-masked index */
            : "r2", "memory"                         /* clobbers: r2 register and memory */
        );
    }
}
```

**Operand constraint details:**
- `[src] "r" (source)` — named operand `%[src]`, constrained to a general-purpose register (`"r"`), bound to the C variable `source`
- `: "r2", "memory"` — clobber list telling the compiler that register `r2` is overwritten and memory is modified
- The compiler will allocate registers for `source`, `dest`, and `idx`, but will not transform the `ldrb`/`strb` sequence

**When to use:**
- Secure memory copy with randomized access order (Hamming weight hiding)
- Constant-time comparison where the compiler might introduce early exits
- Any sequence where the exact instruction ordering and instruction choice is security-critical

---

### 6.8 Standalone Assembly Files for Entry Points

**Purpose:** For code that must be under complete control — with no compiler interference whatsoever — standalone assembly files (`.S`) are used. The compiler processes these only through the assembler, applying no C-level optimizations.

**Code Pattern (from `entry.S`):**

```asm
.globl _start
# Jump to entrypoint
    bl  main
    b .
```

**Key details:**
- `.globl _start` exports the `_start` symbol so the linker can use it as the entry point
- `bl main` calls the C `main()` function — this is the only transition from assembly to C
- `b .` is an infinite loop (branch to self) that catches the case where `main()` returns — the CPU must never proceed past this point
- The linker script places `entry.o` first in the `.text` section, guaranteeing `_start` is at the beginning of FLASH

**Security rationale:**
- The entry sequence contains no compiler-generated code — it is exactly the two instructions written
- No C runtime startup code (constructors, `.init` sections, `__libc_start_main`) executes before `main()`
- The `b .` fallback ensures the CPU halts if `main()` unexpectedly returns
- Combined with `-nostartfiles` and `-nodefaultlibs`, this gives complete control over the first instructions executed after reset

---

## 7. GCC Built-in Functions

---

### 7.1 `__builtin_return_address(0)` — Reading the Return Address

**Purpose:** Read the return address stored on the stack to verify the calling location. This is a compiler built-in that generates efficient code to access the link register or stack-saved return address.

**Code Pattern:**

```c
void func_b(void)
{
    // Verify the caller is an authorized location
    if (__builtin_return_address(0) != (void *)func_a_call_return_func_b)
        SecurityAlert();
    // ... proceed with operation
}
```

**When to use:**
- Caller gate checks (see Section 6.3)
- Detecting ROP/JOP attacks
- Any function restricted to specific callers

**Compiler interaction:** The compiler knows about this built-in and generates the correct code for the target architecture (e.g., reading `lr` on ARM).

---

## 8. Compiler Flags for Security-Hardened Code Generation

These flags are set globally in the Makefile and affect how the compiler generates code for the entire project.

---

### 8.1 `-fno-inline` — Disable Global Inlining

**Purpose:** Prevents the compiler from inlining any function by default. This ensures that every function call generates a `bl` instruction, creating natural code-location barriers in the binary.

**Security rationale:** Without this flag, the compiler at `-O3` aggressively inlines functions. This can:
- Collapse separator functions into the caller, removing spatial barriers
- Merge adjacent comparison checks into optimized sequences that are easier to glitch
- Eliminate function call boundaries that serve as fault injection barriers

**Combined with `always_inline`:** Functions that MUST be inlined (see Section 2.2) override this flag with `__attribute__((always_inline))`.

```make
CFLAGS = ... -fno-inline ...
CFLAGS_LD = ... -fno-inline ...
```

---

### 8.2 `-fno-omit-frame-pointer` — Preserve Frame Pointer

**Purpose:** Forces the compiler to maintain the frame pointer (`fp` / `r11` on ARM) in every function, even when optimization would normally eliminate it.

**Security rationale:**
- Preserves the stack frame chain, making it harder for an attacker to corrupt the call stack without detection
- Enables reliable `__builtin_return_address()` lookups for caller gate checks
- Makes stack-based debugging and post-mortem analysis possible

```make
CFLAGS = ... -fno-omit-frame-pointer ...
```

---

### 8.3 `-fno-ipa-cp-clone` and `-fno-ipa-cp` — Disable Interprocedural Constant Propagation

**Purpose:** Prevents the compiler from analyzing function arguments across call sites and creating specialized clones of functions based on constant arguments.

**Security rationale:**
- **Constant propagation** can cause the compiler to fold security checks that compare against known constants, potentially eliminating runtime comparisons entirely
- **Function cloning** creates multiple versions of a function with different optimizations, making the binary layout unpredictable and potentially creating unintended code paths
- These optimizations can cause `volatile` reads to be optimized in unexpected ways when the compiler proves a value is constant across all call sites

```make
CFLAGS = ... -fno-ipa-cp-clone -fno-ipa-cp ...
```

---

### 8.4 `-fno-common` — Prevent Tentative Definitions

**Purpose:** Disables the C "common" symbol behavior where uninitialized global variables can be merged across compilation units.

**Security rationale:**
- Ensures each global variable has exactly one definition, preventing accidental symbol merging that could cause two security-critical variables to share the same memory location
- Makes the memory layout deterministic — each variable occupies its own space in `.bss` or `.data`
- Without this, the linker may merge two identically-named global variables from different files, creating hard-to-diagnose security vulnerabilities

```make
CFLAGS = ... -fno-common ...
```

---

### 8.5 `-fno-builtin` — Disable Built-in Function Replacement

**Purpose:** Prevents the compiler from replacing calls to standard library functions (`memcmp`, `memcpy`, `memset`, etc.) with built-in optimized sequences.

**Security rationale:**
- The compiler's built-in `memcmp` may be timing-dependent (early exit on mismatch), defeating constant-time comparison implementations
- Built-in `memcpy` may use SIMD or block-transfer instructions that have different side-channel profiles than the intended byte-by-byte implementation
- The project provides its own security-hardened implementations of these functions; the compiler must not replace them with its own versions

```make
CFLAGS = ... -fno-builtin ...
```

**Interaction with custom implementations:** The project defines its own `memcmp`, `memcpy`, and `memset` in `utils.c` with `__attribute__((noinline))`. Without `-fno-builtin`, the compiler would ignore these and generate inline code for `memcmp(a, b, 16)` calls.

---

### 8.6 `-ffreestanding` — Freestanding Environment

**Purpose:** Tells the compiler that the code runs in a freestanding environment (no operating system, no standard library runtime). The compiler cannot assume that standard library functions exist or behave according to the C standard.

**Security rationale:**
- Prevents the compiler from assuming properties of standard functions (e.g., that `memcmp` returns 0 for equal data) and optimizing based on those assumptions
- Disables compiler transformations that assume a hosted environment (e.g., replacing loops with `memset` calls)
- Reinforces `-fno-builtin` by signaling that no standard library is available

```make
CFLAGS = ... -ffreestanding ...
```

---

### 8.7 `-fno-stack-protector` — Disable Stack Canaries

**Purpose:** Disables the compiler's automatic stack buffer overflow protection (stack canaries / stack smashing protection).

**Context for embedded security:** In the fault injection simulation context, the standard stack protector is disabled because:
- The embedded target has no standard library providing `__stack_chk_fail`
- Stack protection in fault injection contexts is handled by custom mechanisms (checkpoint handling, function signature checks)
- The canary mechanism itself could introduce timing side-channels

```make
CFLAGS = ... -fno-stack-protector ...
```

**Note:** In production embedded systems, stack protection should be replaced with a custom implementation suitable for the target platform, not simply disabled.

---

### 8.8 `-ftrivial-auto-var-init=zero` — Compiler-Driven Stack Variable Initialization

**Purpose:** Instructs the compiler to automatically zero-initialize all stack-allocated (automatic) variables that lack an explicit initializer. Available since GCC 12 and Clang 8.

**Security rationale:**
- Complements the manual `volatile BOOL DataResult = INIT` pattern — the compiler guarantees no stack variable is ever left uninitialized, closing the gap where a developer forgets to initialize a security-critical local
- Prevents fault attacks that exploit uninitialized stack memory containing stale values from previous function calls
- A variable that was supposed to be initialized to a "fail-safe" default but was missed by the developer will still start at zero rather than an attacker-favorable random value

**Code pattern prevented:**

```c
// Developer forgets volatile initialization:
uint32_t result;                // Uninitialized — stale stack value may equal SEC_TRUE!
result = SecurityCheck();       // If SecurityCheck() is glitched (skipped), result keeps stale value

// With -ftrivial-auto-var-init=zero:
// result is guaranteed to be 0 before SecurityCheck() runs
```

```make
CFLAGS = ... -ftrivial-auto-var-init=zero ...
```

**Trade-offs:**
- Adds initialization instructions for every uninitialized stack variable, increasing binary size and execution time
- May mask bugs during testing that would otherwise be caught by `-Wuninitialized` or sanitizers — GCC still reports uninitialized warnings even when this flag is active
- In highly constrained embedded environments, the binary size increase may be unacceptable

**Recommendation:** Use `zero` for production code (defense in depth), use `pattern` during development (makes uninitialized access more visible).

---

### 8.9 `-fno-delete-null-pointer-checks` — Prevent Removal of Null Pointer Checks

**Purpose:** Prevents the compiler from removing null pointer checks that it considers redundant based on prior pointer usage. Available since GCC 3.0 and Clang 7.

**Security rationale:**
- If a pointer is dereferenced before being checked for null, the compiler may infer the pointer is non-null and remove the subsequent null check entirely
- In security code, this can silently eliminate safety checks — the source code shows a null check, but the compiled binary does not contain one
- Particularly dangerous in fault injection contexts where a glitch could cause a pointer to become null between its dereference and the check

**Example (from the Linux kernel):**

```c
struct agnx_priv *priv = dev->priv;  // Dereference implies dev != NULL
if (!dev) return;                      // Compiler removes this check!
```

With `-fno-delete-null-pointer-checks`, the null check is preserved in the binary even though the compiler could theoretically prove it is unnecessary.

```make
CFLAGS = ... -fno-delete-null-pointer-checks ...
```

**Note:** Used by the Linux kernel. Has negligible performance impact as null checks are extremely fast.

---

### 8.10 `-fno-strict-overflow` / `-fwrapv` — Prevent Signed Overflow Optimization

**Purpose:** Prevents the compiler from optimizing away code paths based on the assumption that signed integer overflow never occurs. Available since GCC 4.2 (`-fno-strict-overflow`) and GCC 3.4 (`-fwrapv`).

**Security rationale:**
- The C standard declares signed integer overflow as undefined behavior, which allows the compiler to assume it never happens
- Security-critical checks like checkpoint counter overflow detection `if (counter + 1 < counter)` may be silently removed by the compiler
- Secure loop counters that check for wraparound to detect fault-induced skipping can be optimized away

**Example of vulnerable optimization:**

```c
volatile uint32_t checkpoint_counter = 0;

void increment_checkpoint(void) {
    int32_t old = checkpoint_counter;
    checkpoint_counter++;
    // Compiler may remove this: "signed overflow can't happen"
    if (checkpoint_counter < old) {
        fih_panic();  // Overflow detection — compiler may remove!
    }
}
```

With `-fwrapv`, signed overflow is defined as two's complement wrapping, and the overflow check is preserved.

```make
CFLAGS = ... -fno-strict-overflow ...
# or equivalently:
CFLAGS = ... -fwrapv ...
```

**Note:** Since GCC 8.5, `-fno-strict-overflow` is equivalent to `-fwrapv -fwrapv-pointer`. Used by the Linux kernel.

---

### 8.11 `-fno-strict-aliasing` — Prevent Type-Based Alias Analysis

**Purpose:** Prevents the compiler from assuming that pointers of different types never point to the same memory location (strict aliasing rule). Available since GCC 2.95 and Clang 18.

**Security rationale:**
- When casting between types (e.g., `fih_uint` struct fields accessed through byte pointers, or security structures compared byte-by-byte), the compiler may assume the pointers don't alias and optimize away memory accesses
- This can defeat `volatile`-like protections in hardened data types when the same memory is accessed through different pointer types
- Custom `memcmp` implementations that cast data to `uint8_t *` may not see updates made through the original typed pointer

**Example:**

```c
typedef struct {
    volatile uint32_t val;
    volatile uint32_t msk;
} fih_uint;

fih_uint counter;
counter.val = 5;
counter.msk = 5 ^ FIH_MASK;

// Byte-wise comparison — compiler may assume uint8_t* doesn't alias fih_uint*
uint8_t *p = (uint8_t *)&counter;
secure_memcmp(p, expected, sizeof(fih_uint));  // May see stale data!
```

```make
CFLAGS = ... -fno-strict-aliasing ...
```

**Note:** Used by the Linux kernel. Generally has minimal performance impact for security-focused embedded code.

---

### 8.12 `-fno-optimize-sibling-calls` — Disable Tail Call Optimization

**Purpose:** Prevents the compiler from replacing `bl`+`bx lr` (call + return) with a single `b` (branch) when the last operation in a function is a call to another function. Available since GCC 3.0.

**Security rationale:**
- Tail call optimization removes the current function's stack frame before jumping to the callee, eliminating the return address from the stack
- This defeats `__builtin_return_address(0)` caller gate checks because the return address no longer points to the actual calling function
- The function boundary that `__attribute__((noinline))` was meant to enforce is undermined — the callee effectively "replaces" the caller
- In fault injection contexts, the missing stack frame removes a layer of return address verification

**Example:**

```c
__attribute__((noinline))
int security_wrapper(void) {
    // With tail call optimization, the compiler may compile this as:
    //   b security_check     (no stack frame, no return address saved)
    // Instead of:
    //   bl security_check    (stack frame created, return address on stack)
    //   bx lr
    return security_check();
}
```

```make
CFLAGS = ... -fno-optimize-sibling-calls ...
```

**Interaction with other techniques:** This flag strengthens `__builtin_return_address(0)` caller gate checks (Section 7.1) and the `noinline` stack reload technique (Section 2.4).

---

### 8.13 `-fno-jump-tables` — Prevent Jump Table Generation for Switch Statements

**Purpose:** Forces the compiler to implement `switch` statements as if-else chains rather than generating jump tables. Available since GCC 4.0.

**Security rationale:**
- Jump tables are stored in data memory (`.rodata`) and contain addresses of code blocks — a data fault on a jump table entry can redirect execution to an arbitrary address
- Without jump tables, switch statements compile to explicit `cmp`/`b` instruction pairs, where each branch is individually verifiable and glitch-resistant
- A glitch on a jump table load (`ldr pc, [table + offset]`) causes arbitrary code execution; a glitch on a conditional branch (`beq target`) causes a known fall-through to the next comparison

**Example:**

```c
// WITH jump table (default at high optimization):
//   ldr r0, [pc, r1, lsl #2]   <-- Single fault = arbitrary jump
//   bx r0
//
// WITHOUT jump table (-fno-jump-tables):
//   cmp r0, #1                  <-- Fault here = falls to next cmp
//   beq case_1
//   cmp r0, #2
//   beq case_2
//   ...

switch (security_state) {
    case STATE_LOCKED:   handle_locked();   break;
    case STATE_UNLOCKED: handle_unlocked(); break;
    case STATE_ERROR:    handle_error();    break;
}
```

```make
CFLAGS = ... -fno-jump-tables ...
```

**Trade-off:** If-else chains are larger in code size and slower for large switch statements, but each case is independently guarded by a comparison instruction.

---

### 8.14 `-fno-reorder-blocks` / `-fno-reorder-functions` — Prevent Code Block Reordering

**Purpose:** Prevents the compiler from reordering basic blocks within functions or reordering functions based on profiling data. Available since GCC 3.0.

**Security rationale:**
- The compiler may reorder basic blocks to optimize branch prediction, potentially placing failure and success paths adjacent to each other
- Adjacent placement can create fall-through vulnerabilities: a glitch that skips a branch instruction lands directly in the success path
- Disabling reordering keeps the source-code-order layout, where the programmer intentionally separates success and failure paths

**Example:**

```c
if (fPassComp == SEC_TRUE) {
    // SUCCESS path — compiler may move this adjacent to the check
    LoadFile();
} else {
    // FAILURE path — programmer placed this between check and success
    fih_panic();
}
```

With default optimization:
```asm
; Compiler may reorder to: check → success → failure (adjacent success)
    cmp r0, #SEC_TRUE
    bne .failure         ; Single NOP glitch on bne → falls into success!
    bl  LoadFile
    ...
.failure:
    bl  fih_panic
```

With `-fno-reorder-blocks`:
```asm
; Source order preserved: check → failure → success
    cmp r0, #SEC_TRUE
    beq .success
    bl  fih_panic        ; Failure path immediately follows
    ...
.success:
    bl  LoadFile
```

```make
CFLAGS = ... -fno-reorder-blocks -fno-reorder-functions ...
```

**Note:** These flags reduce compiler optimization opportunities, but for security-critical code the predictable layout is more important than branch prediction performance.

---

### 8.15 `-fhardened` — GCC Umbrella Hardening Flag (GCC 14+)

**Purpose:** Enables a pre-determined set of hardening options in a single flag. Available since GCC 14.

**What it enables (GCC 14):**
- `-D_FORTIFY_SOURCE=3` (requires `-O1` or higher)
- `-fstack-protector-strong`
- `-fstack-clash-protection`
- `-fcf-protection=full` (on x86_64)
- `-fPIE -pie`

**Security rationale:**
- Provides a convenient baseline for hardening without manually specifying each flag
- Represents the compiler vendor's evolving view of recommended security defaults
- Options explicitly specified on the command line take precedence over `-fhardened` implied options

**Applicability to embedded:**
- Most sub-options of `-fhardened` are targeted at Linux userspace (ASLR, RELRO, FORTIFY_SOURCE with glibc)
- For bare-metal embedded, many of these are irrelevant or conflict with the freestanding environment
- The flag is useful as a reference for what GCC considers hardening best practices, and individual sub-options (like `-fstack-clash-protection`) can be selectively adopted

```make
# Desktop/Linux context:
CFLAGS = ... -fhardened ...

# Embedded context — select individual options instead:
CFLAGS = ... -fstack-protector-strong ...   # If custom __stack_chk_fail is provided
```

**GCC diagnostic:** When `-fhardened` sub-options are overridden on the command line, GCC issues `-Whardened` warnings to inform the developer.

---

## 9. Linker Flags and Configuration

---

### 9.1 `-nostartfiles` and `-nodefaultlibs` — No Default Runtime

**Purpose:** Prevents the linker from including default C runtime startup code (`crt0.o`) and default standard libraries (`libc`, `libgcc` runtime).

**Security rationale:**
- Gives complete control over the binary's entry point and initialization sequence — no hidden code executes before `main()`
- Eliminates unknown library code that could introduce vulnerabilities or unpredictable behavior
- The project provides its own entry point (`entry.S`) that directly calls `main`
- Ensures the binary contains only explicitly included code

```make
CFLAGS_LD = ... -nostartfiles -nodefaultlibs ...
```

---

### 9.2 `-N` — Writable Text Segment

**Purpose:** The `-N` linker flag marks the text (code) segment as writable, disabling the read-only protection of the code section.

**Context:** This flag is used specifically for the fault injection simulation environment where the simulator may need to modify code at runtime (for code patching). In production firmware, the text segment should remain read-only.

```make
CFLAGS_LD = -N ...
```

---

### 9.3 `-Wl,--build-id=none` — Remove Build Metadata

**Purpose:** Removes the `.note.gnu.build-id` section from the binary, which normally contains a unique hash identifying the build.

**Security rationale:**
- Minimizes binary metadata that could be used for fingerprinting or reverse engineering
- Reduces binary size for constrained embedded targets
- Eliminates a section that has no security function and could interfere with precise memory layout control

```make
CFLAGS_LD = ... -Wl,--build-id=none ...
```

---

### 9.4 Custom Linker Script for Memory Layout Control

**Purpose:** A custom linker script (`victim.lds`) provides precise control over where code, data, and stack are placed in memory.

**Security-relevant aspects:**

```ld
OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)

STACK_SIZE = 0x1000;

MEMORY
{
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K
  RAM (rw)   : ORIGIN = 0x20000000, LENGTH = 64K
}

SECTIONS
{
    /* Entry point placed first in FLASH */
    .text : {
        bin/aarch32/obj/entry.o (.text)  /* Entry code at known location */
        *(.text)
        *(.text*)
    } > FLASH

    /* Constants in FLASH (read-only in production) */
    .rodata : { *(.rodata) *(.rodata*) } > FLASH

    /* Mutable data in RAM */
    .data : { *(.data) *(.data*) } > RAM

    /* Uninitialized data in RAM */
    .bss : { *(.bss) *(.bss*) *(COMMON) } > RAM

    /* Stack at end of RAM with explicit size */
    .stack (NOLOAD) : {
        . = ORIGIN(RAM) + LENGTH(RAM) - STACK_SIZE;
        _estack = .;
        . += STACK_SIZE;
    } > RAM
}
```

**Security-relevant features:**
- **Explicit entry point placement:** `entry.o` is placed first in `.text`, ensuring the entry point is at a known, predictable address
- **Separation of code and data:** Code in FLASH (`rx`), data in RAM (`rw`) — in production, FLASH should be read-only
- **Explicit stack bounds:** Stack has a defined size and location, preventing overlap with `.bss` data
- **No gaps between sections:** `.bss` and `.data` are contiguous in RAM, minimizing exploitable gaps

---

## 10. The `register` Keyword

**Purpose:** Hints to the compiler that a variable should be stored in a CPU register rather than on the stack, reducing the window where its value is in memory and accessible to fault injection.

**Code Pattern:**

```c
#define fih_uint_eq(x, y)                                     \
    ({                                                        \
        bool register result;  /* Keep result in a register */ \
        result = fih_uint_validate(x);                        \
        /* ... */                                             \
        result;                                               \
    })
```

**Security rationale:**
- A register value is harder to target with memory-based fault injection than a stack variable
- Reduces the number of `ldr`/`str` instructions, shrinking the attack surface for NOP glitches on load/store operations

**Note:** The `register` keyword is a hint, not a guarantee. Modern compilers may ignore it. It is primarily used for MISRA-C compliance and as documentation of intent.

---

## 11. Preprocessor-Driven Security Profile Selection

**Purpose:** Use preprocessor defines (`-D` compiler flags) to select different security hardening profiles at compile time, enabling the same codebase to be compiled with different levels of hardening.

**Code Pattern (from Makefile):**

```make
CFLAGS = ... -DMCUBOOT_FIH_PROFILE_ON -DMCUBOOT_FIH_PROFILE_HIGH -DFAULT_INJECTION_TEST
```

**How it works in the code:**

```c
// Conditional compilation based on security profile
#ifdef FIH_ENABLE_DOUBLE_VARS
    // Use XOR-masked redundant variables
    fih_cfi_ctr.val = fih_cfi_ctr.val + cnt;
    fih_cfi_ctr.msk = ((fih_cfi_ctr.msk ^ FIH_UINT_MASK_VALUE) + cnt) ^ FIH_UINT_MASK_VALUE;
#else
    // Single variable (lower security)
    fih_cfi_ctr = fih_uint_encode(fih_uint_decode(fih_cfi_ctr) + cnt);
#endif

// Test-specific behavior
#ifdef FAULT_INJECTION_TEST
    do {
        *((volatile unsigned int *)(0xAA01000)) = 0x2;
    } while (1);
#else
    // Production panic loop with redundant branches
    __asm volatile ("b fih_panic_loop");
    // ...
#endif
```

**Security profiles:**
- `MCUBOOT_FIH_PROFILE_ON` — Enable fault injection hardening
- `MCUBOOT_FIH_PROFILE_HIGH` — Use the highest security level (double variables, CFI, delays)
- `FIH_ENABLE_DOUBLE_VARS` — Enable XOR-masked redundant storage
- `FIH_ENABLE_CFI` — Enable control flow integrity counters
- `FAULT_INJECTION_TEST` — Enable simulator hooks (not for production)

**When to use:**
- To support multiple security tiers from a single codebase
- To enable/disable expensive hardening based on the threat model
- To separate test instrumentation from production code

---

## Summary Matrix

| #   | Technique                                          | Type              | Security Purpose                                                     |
| --- | -------------------------------------------------- | ----------------- | -------------------------------------------------------------------- |
| 1   | `volatile` keyword                                 | C keyword         | Prevent optimization of security-critical reads/writes               |
| 2   | `__attribute__((noinline))`                        | GCC attribute     | Enforce branch separation via function call boundaries               |
| 3   | `__attribute__((always_inline))`                   | GCC attribute     | Prevent pre-loaded register vulnerability in comparisons             |
| 4   | `-fno-inline` + selective `always_inline`          | Strategy          | Two-layer inlining control for precise code layout                   |
| 4b  | `noinline` calls for stack spill/reload            | ABI + attribute   | Force compiler to reload values from stack after function call       |
| 5   | `__attribute__((noreturn))`                        | GCC attribute     | Prevent fall-through code after panic handlers                       |
| 6   | `__attribute__((used))`                            | GCC attribute     | Prevent dead code elimination of security hooks                      |
| 7   | `__attribute__((weak))`                            | GCC attribute     | Allow link-time override of default security handlers                |
| 8   | `__attribute__((packed))`                          | GCC attribute     | Eliminate struct padding that could be exploited                      |
| 9   | Macro-based comparison chains                      | Preprocessor      | Expand comparisons inline to avoid single-bl vulnerability           |
| 10  | GCC statement expressions                          | GCC extension     | Complex inline macros with local variables for MISRA compliance      |
| 11  | `#define` compile-time constants                   | Preprocessor      | Encode values in instruction stream, not data memory                 |
| 12  | `__asm volatile` qualifier                         | Inline ASM        | Prevent compiler from removing/reordering ASM statements             |
| 13  | `FIH_LABEL` inline assembly                        | Inline ASM        | Embed parsable labels in binary for testing tools                    |
| 14  | Redundant `b` instructions                         | Inline ASM        | Make panic loops resistant to NOP glitches                           |
| 15  | Global labels at call sites                        | Inline ASM        | Enable return address verification for caller gate checks            |
| 16  | Empty `__asm volatile` memory barrier              | Inline ASM        | Enforce strict ordering of security-critical operations              |
| 17  | Full inline ASM for security sequences             | Inline ASM        | Prevent compiler transformation of security-critical instruction sequences |
| 18  | Standalone `.S` assembly entry point               | Assembly file     | Complete control over entry code with zero compiler interference     |
| 19  | `__builtin_return_address(0)`                      | GCC built-in      | Read stack return address for caller verification                    |
| 20  | `-fno-inline`                                      | Compiler flag     | Disable automatic inlining globally                                  |
| 21  | `-fno-omit-frame-pointer`                          | Compiler flag     | Preserve stack frame chain for return address checks                 |
| 22  | `-fno-ipa-cp-clone` / `-fno-ipa-cp`               | Compiler flag     | Prevent interprocedural optimization that removes runtime checks     |
| 23  | `-fno-common`                                      | Compiler flag     | Prevent variable merging across compilation units                    |
| 24  | `-fno-builtin`                                     | Compiler flag     | Prevent replacement of custom security functions with built-ins      |
| 25  | `-ffreestanding`                                   | Compiler flag     | Disable standard library assumptions in optimization                 |
| 26  | `-fno-stack-protector`                             | Compiler flag     | Disable default stack canaries (replaced by custom mechanisms)       |
| 27  | `-nostartfiles` / `-nodefaultlibs`                 | Linker flag       | Full control over binary contents, no hidden startup code            |
| 28  | `-Wl,--build-id=none`                              | Linker flag       | Remove build metadata from binary                                    |
| 29  | Custom linker script                               | Linker config     | Precise memory layout control for code, data, and stack placement    |
| 30  | `register` keyword                                 | C keyword         | Hint to keep security variables in registers, not stack              |
| 31  | Preprocessor security profiles (`-D`)              | Preprocessor      | Compile-time selection of hardening levels                           |
| 32  | Volatile compound literals                         | C + `volatile`    | Force fresh value computation for each use of a constant             |
| 33  | `__attribute__((section("name")))`                 | GCC attribute     | Explicit memory section placement for hardware isolation             |
| 34  | `-ftrivial-auto-var-init=zero`                     | Compiler flag     | Auto-zero-initialize stack variables as defense in depth             |
| 35  | `-fno-delete-null-pointer-checks`                  | Compiler flag     | Prevent compiler from removing null pointer safety checks            |
| 36  | `-fno-strict-overflow` / `-fwrapv`                 | Compiler flag     | Prevent signed overflow optimization on counter checks               |
| 37  | `-fno-strict-aliasing`                             | Compiler flag     | Prevent type-based aliasing optimization on security data types      |
| 38  | `-fno-optimize-sibling-calls`                      | Compiler flag     | Preserve stack frames and return addresses for caller gate checks    |
| 39  | `-fno-jump-tables`                                 | Compiler flag     | Force if-else chains instead of data-corruptible jump tables         |
| 40  | `-fno-reorder-blocks` / `-fno-reorder-functions`   | Compiler flag     | Prevent adjacent placement of success/failure paths                  |
| 41  | `-fhardened` (GCC 14+)                             | Compiler flag     | Umbrella flag for compiler vendor recommended hardening defaults     |
