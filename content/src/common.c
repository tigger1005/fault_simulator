#include "common.h"

// ------------------------------------------------------------
// Framework variable and functions

// Flow Control Counter
fih_uint glob_cfi_counter;

// Global variable definition
const fih_uint image_good_val = FIH_SUCCESS;

// Success condition
volatile unsigned int success_condition = 0x22222222;

// Function implementation
__attribute__((used, noinline)) void decision_activation(void) {}
