#include "fih_mem.h"
#include "bootutil/fault_injection_hardening.h"
#include <stddef.h>
#include <stdint.h>

fih_uint fih_memcpy(fih_uint dst, fih_uint src, fih_uint length)
{
    // Validate given parameters
    fih_uint_validate(dst);
    fih_uint_validate(src);
    fih_uint_validate(length);

    // Copy all full uint32_t chunks
    size_t length1 = fih_uint_val(length);
    uint32_t *dst32 = (uint32_t *)(uintptr_t)fih_uint_val(dst);
    uint32_t *src32 = (uint32_t *)(uintptr_t)fih_uint_val(src);
    {
        while (length1 >= sizeof(uint32_t))
        {
            *dst32++ = *src32++;
            length1 -= sizeof(uint32_t);
        }

        if ((uint32_t)(uintptr_t)dst32 !=
            fih_uint_msk(dst) +
                fih_uint_msk(length) / sizeof(uint32_t) * sizeof(uint32_t))
        {
            FIH_PANIC;
        }
        if ((uint32_t)(uintptr_t)src32 !=
            fih_uint_msk(src) +
                fih_uint_msk(length) / sizeof(uint32_t) * sizeof(uint32_t))
        {
            FIH_PANIC;
        }
    }

    // Copy all remaining bytes
    uint8_t *dst8 = (uint8_t *)dst32;
    uint8_t *src8 = (uint8_t *)src32;
    {
        while (length1 > 0)
        {
            *dst8++ = *src8++;
            length1--;
        }

        if ((uint32_t)(uintptr_t)dst8 !=
            fih_uint_msk(dst) + fih_uint_msk(length))
        {
            FIH_PANIC;
        }
        if ((uint32_t)(uintptr_t)src8 !=
            fih_uint_msk(src) + fih_uint_msk(length))
        {
            FIH_PANIC;
        }
    }

    // Return final destination address as fih_uint
#ifdef FIH_ENABLE_DOUBLE_VARS
    fih_uint ret = { (uint32_t)(uintptr_t)dst8,
                     (fih_uint_msk(dst) + fih_uint_msk(length)) ^
                         FIH_MASK_VALUE };
#else
    fih_uint ret = (fih_uint)dst8;
#endif
    return ret;
}


fih_int fih_memcmp(fih_uint data1, fih_uint data2, fih_uint length)
{
    fih_int result = FIH_INT_INIT(FIH_FALSE);

    size_t u = 0;
    size_t len = (size_t)fih_uint_val(length);
    size_t d = (size_t)fih_uint_val(length);
    for (; u < len && d > 0; u++, --d)
    {
        if (((uint8_t *)(uintptr_t)fih_uint_val(data1))[u] != ((uint8_t *)(uintptr_t)fih_uint_val(data2))[u])
        {
            break;
        }
        if (((uint8_t *)(uintptr_t)fih_uint_msk(data1))[d - 1] != ((uint8_t *)(uintptr_t)fih_uint_msk(data2))[d - 1])
        {
            break;
        }
        if (u + d != len) { FIH_PANIC; }
    }

    fih_uint_validate(length);
    if (u == len) {
#ifdef FIH_ENABLE_DOUBLE_VARS
        result.val = FIH_TRUE;
#else
        result = FIH_TRUE;
#endif
    }
    fih_uint_validate(data1);
    if (fih_uint_val(data1) == fih_uint_val(data2)) { FIH_PANIC; }
    fih_uint_validate(data2);

#ifdef FIH_ENABLE_DOUBLE_VARS
    if (fih_uint_msk(data1) == fih_uint_msk(data2)) { FIH_PANIC; }
    len = (size_t)fih_uint_msk(length);
    for (u = 0; u < len; u++)
    {
        if (((uint8_t *)(uintptr_t)fih_uint_msk(data1))[u] != ((uint8_t *)(uintptr_t)fih_uint_msk(data2))[u])
        {
            break;
        }
    }
    
    if (u == len)
    {
        result.msk = FIH_TRUE ^ FIH_MASK_VALUE;
    }
    // Recheck of first loop
    if (d != 0 && result.val == FIH_TRUE) { FIH_PANIC; }
#endif

    fih_int_validate(result);
    return result;
}
