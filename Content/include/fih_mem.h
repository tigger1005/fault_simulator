#ifndef FIH_MEM_H
#define FIH_MEM_H

#include "bootutil/fault_injection_hardening.h"
#include <stddef.h>
#include <stdint.h>

#define FIH_UINT_INVALID ((fih_uint) { 0xAFFEDEAD, 0xDEADAFFE })
#define FIH_INT_INVALID ((fih_int) { 0xAFFEDEAD, 0xDEADAFFE })

__attribute__((always_inline)) static inline uint32_t fih_uint_msk(fih_uint x)
{
#ifdef FIH_ENABLE_DOUBLE_VARS
    return x.msk ^ FIH_UINT_MASK_VALUE;
#else
    return x;
#endif
}

__attribute__((always_inline)) static inline uint32_t fih_uint_val(fih_uint x)
{
#ifdef FIH_ENABLE_DOUBLE_VARS
    return x.val;
#else
    return x;
#endif
}

/**
 * Validate return value of fih_memcpy.
 *
 * \param result Return value given by \p fih_memcpy
 * \param dst Original destination
 * \param length Original length
 */
__attribute__((always_inline)) static inline void fih_memcpy_validate(
    fih_uint result,
    fih_uint dst,
    fih_uint length)
{
    // Check mask part
    if (fih_uint_msk(result) != fih_uint_msk(dst) + fih_uint_msk(length))
    {
        FIH_PANIC;
    }

    // Validate result
    fih_uint_validate(result);

    // Check value part
    if (fih_uint_val(result) != fih_uint_val(dst) + fih_uint_val(length))
    {
        FIH_PANIC;
    }
}

/**
 * Memcpy using fih types.
 *
 * Usage example:
 * ```c
 * fih_uint result = FIH_UINT_INVALID;
 * fih_uint destination = FIH_UINT_INIT(0x10000000);
 * fih_uint source = FIH_UINT_INIT(0x20000000);
 * fih_uint length = FIH_UINT_INIT(32);

 * result = fih_memcpy(destination, source, length);
 * fih_memcpy_validate(result, destination, length);
 * ```
 *
 * \param[out] dst Destination
 * \param[in] src Source
 * \param[in] length Length
 * \return fih_uint Destination address after copying
 */
fih_uint fih_memcpy(fih_uint dst, fih_uint src, fih_uint length);

/**
 * Memcmp using fih types.
 *
 * Usage example:
 * ```c
 * fih_int result = FIH_INT_INVALID;
 * fih_uint data_1 = FIH_UINT_INIT(0x10000000);
 * fih_uint data_2 = FIH_UINT_INIT(0x20000000);
 * fih_uint length = FIH_UINT_INIT(32);

 * result = fih_memcmp(destination, source, length);
 * FIH_IF_INT_EQUAL(result, fih_int_encode(FIH_TRUE)) {
 *     FIH_IF_INT_EQUAL_BODY_CHECK(result, fih_int_encode(FIH_TRUE));
 *     ...
 *     FIH_IF_INT_EQUAL_BODY_CHECK(result, fih_int_encode(FIH_TRUE));
 * }
 * ```
 *
 * \param[in] data1 First data buffer
 * \param[in] data2 Second data buffer
 * \param[in] length Length
 * \return fih_int Either fih_int_encode(FIH_TRUE) or fih_int_encode(FIH_FALSE)
 */
fih_int fih_memcmp(fih_uint data1, fih_uint data2, fih_uint length);

#endif
