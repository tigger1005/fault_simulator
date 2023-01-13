#ifndef H_COMMON
#define H_COMMON

#include "bootutil/fault_injection_hardening.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ------------------------------------------------------------
// Framework defines and macros definitions
extern const fih_uint image_good_val;

#define IMG_LOAD_ADDR ((void *)0x32000000)
#define UART_OUT_BUF_ADDR ((void *)0x11000000)
#define IMAGE_VALUE (*(uint32_t *)IMG_LOAD_ADDR)

#ifdef FIH_ENABLE_DOUBLE_VARS
// Macro to remove initial warning for fih template project
#define FIH_IF_UINT_EQUAL(x, y) if (x.val == y.val)
#define FIH_IF_UINT_EQUAL_BODY_CHECK(x, y)                                     \
  {                                                                            \
    fih_uint_validate(x);                                                      \
    fih_delay();                                                               \
    if (x.msk != y.msk || x.val != y.val) {                                    \
      FIH_PANIC;                                                               \
    }                                                                          \
  }

#define FIH_IF_INT_EQUAL(x, y) if (x.val == y.val)
#define FIH_IF_INT_EQUAL_BODY_CHECK(x, y)                                      \
  {                                                                            \
    fih_int_validate(x);                                                       \
    fih_delay();                                                               \
    if (x.msk != y.msk || x.val != y.val) {                                    \
      FIH_PANIC;                                                               \
    }                                                                          \
  }
#else
#define FIH_IF_UINT_EQUAL(x, y) if (x == y)
#define FIH_IF_UINT_EQUAL_BODY_CHECK(x, y)                                     \
  {                                                                            \
    fih_uint_validate(x);                                                      \
    fih_delay();                                                               \
    if (x != y) {                                                              \
      FIH_PANIC;                                                               \
    }                                                                          \
  }

#define FIH_IF_INT_EQUAL(x, y) if (x == y)
#define FIH_IF_INT_EQUAL_BODY_CHECK(x, y)                                      \
  {                                                                            \
    fih_int_validate(x);                                                       \
    fih_delay();                                                               \
    if (x != y) {                                                              \
      FIH_PANIC;                                                               \
    }                                                                          \
  }
#endif

extern fih_uint glob_cfi_counter;

#define CHECKPOINT_INIT()                                                      \
  glob_cfi_counter = fih_uint_encode(GLOBAL_CFI_START_VALUE);

#define CHECKPOINT()                                                           \
  glob_cfi_counter.val--;                                                      \
  glob_cfi_counter.msk = (((glob_cfi_counter.msk ^ FIH_UINT_MASK_VALUE) - 1) ^ \
                          FIH_UINT_MASK_VALUE)

#define CHECKPOINT_VALUE(decrement)                                            \
  glob_cfi_counter.val -= decrement;                                           \
  glob_cfi_counter.msk =                                                       \
      (((glob_cfi_counter.msk ^ FIH_UINT_MASK_VALUE) - decrement) ^            \
       FIH_UINT_MASK_VALUE)

#define VALIDATE_CHECKPOINT(x)                                                 \
  fih_uint_validate(glob_cfi_counter);                                         \
  fih_delay();                                                                 \
  if (glob_cfi_counter.val + x != GLOBAL_CFI_START_VALUE) {                    \
    FIH_PANIC;                                                                 \
  }

#define VALIDATE_FINAL_CHECKPOINT()                                            \
  FIH_IF_UINT_EQUAL_BODY_CHECK(glob_cfi_counter,                               \
                               fih_uint_encode(GLOBAL_CFI_END_VALUE))

// Dummy functions
extern void flash_load_img(void);

extern volatile unsigned char success_condition;

#define __SET_SIM_SUCCESS()                                                    \
  do {                                                                         \
    *((volatile unsigned int *)(0xAA01000)) = 0x1;                             \
  } while (1);

#define __SET_SIM_CONDITION_TRUE() success_condition = 0x01
#define __SET_SIM_CONDITION_FALSE() success_condition = 0x02

#define __SET_SIM_SUCCESS_WITH_CONDITION()                                     \
  do {                                                                         \
    *((volatile unsigned int *)(0xAA01000)) = success_condition;               \
  } while (1);

#define __SET_SIM_FAILED()                                                     \
  do {                                                                         \
    *((volatile unsigned int *)(0xAA01000)) = 0x2;                             \
  } while (1);

// ------------------------------------------------------------

#endif
