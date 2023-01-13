#include "common.h"

// ------------------------------------------------------------
// Framework variable and functions

// Flow Control Counter
fih_uint glob_cfi_counter;

// Global variable definition
const fih_uint image_good_val = FIH_UINT_INIT(0x12345678);

// Success condition
volatile unsigned char success_condition = 0x02;

// Function implementation
__attribute__((used, noinline)) void flash_load_img(void) {}
