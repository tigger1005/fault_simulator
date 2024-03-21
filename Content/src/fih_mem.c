#include "fih_mem.h"
#include "bootutil/fault_injection_hardening.h"
#include <stddef.h>
#include <stdint.h>

fih_uint fih_memcpy(fih_uint dst, fih_uint src, fih_uint length) {
  // Validate given parameters
  fih_uint_validate(dst);
  fih_uint_validate(src);
  fih_uint_validate(length);

  // Copy all full uint32_t chunks
  size_t length1 = fih_uint_val(length);
  uint32_t *dst32 = (uint32_t *)(uintptr_t)fih_uint_val(dst);
  uint32_t *src32 = (uint32_t *)(uintptr_t)fih_uint_val(src);
  {
    while (length1 >= sizeof(uint32_t)) {
      *dst32++ = *src32++;
      length1 -= sizeof(uint32_t);
    }

    if ((uint32_t)(uintptr_t)dst32 !=
        fih_uint_msk(dst) +
            fih_uint_msk(length) / sizeof(uint32_t) * sizeof(uint32_t)) {
      FIH_PANIC;
    }
    if ((uint32_t)(uintptr_t)src32 !=
        fih_uint_msk(src) +
            fih_uint_msk(length) / sizeof(uint32_t) * sizeof(uint32_t)) {
      FIH_PANIC;
    }
  }

  // Copy all remaining bytes
  uint8_t *dst8 = (uint8_t *)dst32;
  uint8_t *src8 = (uint8_t *)src32;
  {
    while (length1 > 0) {
      *dst8++ = *src8++;
      length1--;
    }

    if ((uint32_t)(uintptr_t)dst8 != fih_uint_msk(dst) + fih_uint_msk(length)) {
      FIH_PANIC;
    }
    if ((uint32_t)(uintptr_t)src8 != fih_uint_msk(src) + fih_uint_msk(length)) {
      FIH_PANIC;
    }
  }

  // Return final destination address as fih_uint
  fih_uint ret = {(uint32_t)(uintptr_t)dst8,
                  (fih_uint_msk(dst) + fih_uint_msk(length)) ^ FIH_UINT_MASK_VALUE};
  return ret;
}

fih_uint fih_memcmp(fih_uint data1, fih_uint data2, fih_uint length) {
  fih_uint ret = FIH_UINT_INIT(FIH_FALSE);
  fih_uint_validate(length);
  {
    size_t u = 0;
    uint32_t len = fih_uint_val(length);
    for (u = 0; u < len; u++) {
      if (((uint8_t *)(uintptr_t)fih_uint_val(data1))[u] !=
          ((uint8_t *)(uintptr_t)fih_uint_val(data2))[u]) {
        break;
      }
    }

    if (u != len || fih_uint_val(data1) == fih_uint_val(data2)) {
      return fih_uint_encode(FIH_FALSE);
    }
    ret.val = FIH_TRUE;
  }
  fih_uint_validate(data1);
  {
    size_t u = 0;
    uint32_t len = fih_uint_msk(length);
    for (u = 0; u < len; u++) {
      if (((uint8_t *)(uintptr_t)fih_uint_msk(data1))[u] !=
          ((uint8_t *)(uintptr_t)fih_uint_msk(data2))[u]) {
        break;
      }
    }

    if (u != len || fih_uint_msk(data1) == fih_uint_msk(data2)) {
      FIH_PANIC;
    }
    ret.msk = FIH_TRUE;
  }
  fih_uint_validate(data2);
  {
    size_t u = 0;
    uint32_t len = fih_uint_val(length);
    for (u = 0; u < len; u++) {
      if (((uint8_t *)(uintptr_t)fih_uint_val(data1))[u] !=
          ((uint8_t *)(uintptr_t)fih_uint_msk(data2))[u]) {
        break;
      }
    }

    if (u != len || fih_uint_msk(data1) == fih_uint_val(data2)) {
      FIH_PANIC;
    }
    ret.msk ^= FIH_UINT_MASK_VALUE;
  }
  fih_uint_validate(ret);
  return ret;
}
