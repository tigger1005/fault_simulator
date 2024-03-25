/*******************************************************************************
 * File Name: fault_injection_hardening.h
 *
 *******************************************************************************
* Copyright 2024, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
*
* This software, including source code, documentation and related
* materials ("Software") is owned by Cypress Semiconductor Corporation
* or one of its affiliates ("Cypress") and is protected by and subject to
* worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software
* source code solely for use in connection with Cypress's
* integrated circuit products.  Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*******************************************************************************/

#ifndef FAULT_INJECTION_HARDENING_H
#define FAULT_INJECTION_HARDENING_H


#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#if defined(IFX_L1_USE_LOCAL_SE_FIH_EQ)
#include "ifx_se_fih.h"
#endif /* defined(IFX_L1_USE_LOCAL_SE_FIH_EQ) */

/* Where possible, glue the FIH_TRUE from two components. */
#define FIH_TRUE_1              (0x300AUL)
#define FIH_TRUE_2              (0x0C50UL)
#define FIH_TRUE                (0x3C5AUL) /* i.e., FIH_TRUE_1 | FIH_TRUE_2 */
#define FIH_FALSE               (0xA5C3UL)

#define FIH_POSITIVE_VALUE      (0x5555AAAAUL)
#define FIH_NEGATIVE_VALUE      (0xAAAA5555UL)

/*
 * A volatile mask is used to prevent compiler optimization - the mask is XORed
 * with the variable to create the backup and the integrity can be checked with
 * another xor. The mask value doesn't _really_ matter that much, as long as
 * it has reasonably high Hamming weight.
 */

#define FIH_UINT_MASK_VALUE     (0xA5C35A3CUL)

#define FIH_UINT_VAL_MASK(val) ((val) ^ FIH_UINT_MASK_VALUE)

/*
 * All ints are replaced with two int - the normal one and a backup which is
 * XORed with the mask.
 * THIS STRUCTURE IS NOT USED IN THE L1-BOOT CODE BUT
 * IT IS REQUIRED BY SOME .H FILES FROM MCUBOOT LIBRARY.
 */

typedef struct {
    volatile uint32_t val;
    volatile uint32_t msk;
} fih_uint;

#define FIH_UINT_INIT(x)        ((fih_uint){(x), FIH_UINT_VAL_MASK(x)})

#define FIH_SUCCESS     (FIH_UINT_INIT(FIH_POSITIVE_VALUE))
#define FIH_FAILURE     (FIH_UINT_INIT(FIH_NEGATIVE_VALUE))
#define FIH_UINT_ZERO   (FIH_UINT_INIT(0UL))
#define FIH_UINT_MAX    (FIH_UINT_INIT(0xFFFFFFFFUL))

void fih_panic_loop(void);
#define FIH_PANIC fih_panic_loop()

/*
 * NOTE: for functions to be inlined outside their compilation unit they have to
 * have the body in the header file. This is required as function calls are easy
 * to skip.
 */

/**
 * @brief Set up the RNG for use with random delays. Called once at startup.
 */
void fih_delay_init(void);

/**
 * Get a random uint32_t value from an RNG seeded with an entropy source.
 * NOTE: do not directly call this function!
 *
 * @return   random value.
 */
uint32_t fih_delay_random(void);

/**
 * Delaying logic, with randomness from a CSPRNG.
 */

bool fih_delay(void);
/**
 * Validate fih_uint for tampering.
 *
 * @param x  fih_uint value to be validated.
 */

__attribute__((always_inline)) static inline
bool fih_uint_validate(fih_uint x)
{
    uint32_t x_msk = FIH_UINT_VAL_MASK(x.msk);

    if (x.val != x_msk)
    {
        FIH_PANIC;
    }

    return true;
}

/**
 * Convert a fih_uint to an unsigned int. Validate for tampering.
 *
 * @param x  fih_uint value to be converted.
 *
 * @return   Value converted to unsigned int.
 */

__attribute__((always_inline)) static inline
uint32_t fih_uint_decode(fih_uint x)
{
    (void)fih_uint_validate(x);
    return x.val;
}

/**
 * Convert an unsigned int to a fih_uint, can be used to encode specific error
 * codes.
 *
 * @param x  Unsigned integer value to be converted.
 *
 * @return   Value converted to fih_uint.
 */
__attribute__((always_inline)) static inline
fih_uint fih_uint_encode(uint32_t x)
{
    fih_uint ret = FIH_UINT_INIT(x);
    return ret;
}

/**
 * Standard equality for fih_uint values.
 *
 * @param x  1st fih_uint value to be compared.
 * @param y  2nd fih_uint value to be compared.
 *
 * @return   FIH_TRUE if x == y, other otherwise.
 */

#define fih_uint_eq(x, y)  \
         (fih_uint_validate(x)  && \
          fih_uint_validate(y) && \
          ((x).val == (y).val) && \
          fih_delay() && \
          ((x).msk == (y).msk) && \
          fih_delay() && \
          ((x).val == FIH_UINT_VAL_MASK((y).msk))  \
        )

/**
 * Standard non-equality for fih_uint values.
 *
 * @param x  1st fih_uint value to be compared.
 * @param y  2nd fih_uint value to be compared.
 *
 * @return   FIH_TRUE if x != y, FIH_FALSE otherwise.
 */
#if defined(IFX_L1_FIH_FIX_MISRA)
#define fih_uint_not_eq(x, y)                                 \
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
            result = ((x).val != (y).val);                    \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).msk != (y).msk);                    \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val != FIH_UINT_VAL_MASK((y).msk)); \
        }                                                     \
                                                              \
        result;                                               \
    })

#else

#define fih_uint_not_eq(x, y) \
        ( fih_uint_validate(x) && \
          fih_uint_validate(y) && \
          ((x).val != (y).val) && \
          fih_delay() && \
          ((x).msk != (y).msk) && \
          fih_delay() && \
          ((x).val != FIH_UINT_VAL_MASK((y).msk)) \
        )

#endif /* defined(IFX_L1_FIH_FIX_MISRA) */


#if defined(IFX_L1_USE_LOCAL_SE_FIH_EQ)

__attribute__((always_inline)) static inline
bool ifx_l1_se_fih_uint_validate(ifx_se_fih_uint x)
{
    uint32_t x_msk = x.msk ^ IFX_SE_FIH_MASK_VALUE;

    if (x.val != x_msk)
    {
        FIH_PANIC;
    }

    return true;
}

#if defined(IFX_L1_FIH_FIX_MISRA)
#define ifx_l1_se_fih_uint_eq(x, y)                           \
    ({                                                        \
        bool register result;                                 \
                                                              \
        result = ifx_l1_se_fih_uint_validate(x);              \
                                                              \
        if (result)                                           \
        {                                                     \
            result = ifx_l1_se_fih_uint_validate(y);          \
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
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val == ((y).msk ^ IFX_SE_FIH_MASK_VALUE)); \
        }                                                     \
                                                              \
        result;                                               \
    })

#else

#define ifx_l1_se_fih_uint_eq(x, y) \
        ( ifx_l1_se_fih_uint_validate(x) && \
          ifx_l1_se_fih_uint_validate(y) && \
          ((x).val == (y).val) && \
          fih_delay() && \
          ((x).msk == (y).msk) && \
          fih_delay() && \
          ((x).val == ((y).msk ^ IFX_SE_FIH_MASK_VALUE)) \
        )

#endif /* defined(IFX_L1_FIH_FIX_MISRA) */

#else

#define ifx_l1_se_fih_uint_eq(x, y) ifx_se_fih_uint_eq((x), (y))

#endif /* defined(IFX_L1_USE_LOCAL_SE_FIH_EQ) */


/**
 * Standard greater than comparison for fih_uint values.
 *
 * @param x  1st fih_uint value to be compared.
 * @param y  2nd fih_uint value to be compared.
 *
 * @return   FIH_TRUE if x > y, FIH_FALSE otherwise.
 */
#if defined(IFX_L1_FIH_FIX_MISRA)
#define fih_uint_gt(x, y)                                     \
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
            result = ((x).val > (y).val);                     \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = (FIH_UINT_VAL_MASK((x).msk) > FIH_UINT_VAL_MASK((y).msk)); \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val > FIH_UINT_VAL_MASK((y).msk));  \
        }                                                     \
                                                              \
        result;                                               \
    })

#else

#define fih_uint_gt(x, y) \
        ( fih_uint_validate(x)  && \
          fih_uint_validate(y) && \
          ((x).val > (y).val) && \
          fih_delay() && \
          (FIH_UINT_VAL_MASK((x).msk) > FIH_UINT_VAL_MASK((y).msk)) && \
          fih_delay() && \
          ((x).val > FIH_UINT_VAL_MASK((y).msk)) \
        )

#endif /* defined(IFX_L1_FIH_FIX_MISRA) */


/**
 * Standard greater than or equal comparison for fih_uint values.
 *
 * @param x  1st fih_uint value to be compared.
 * @param y  2nd fih_uint value to be compared.
 *
 * @return   FIH_TRUE if x >= y, FIH_FALSE otherwise.
 */
#if defined(IFX_L1_FIH_FIX_MISRA)
#define fih_uint_ge(x, y)                                     \
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
            result = ((x).val >= (y).val);                    \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = (FIH_UINT_VAL_MASK((x).msk) >= FIH_UINT_VAL_MASK((y).msk)); \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val >= FIH_UINT_VAL_MASK((y).msk)); \
        }                                                     \
                                                              \
        result;                                               \
    })


#else

#define fih_uint_ge(x, y) \
        ( fih_uint_validate(x)  && \
          fih_uint_validate(y) && \
          ((x).val >= (y).val) && \
          fih_delay() && \
          (FIH_UINT_VAL_MASK((x).msk) >= FIH_UINT_VAL_MASK((y).msk)) && \
          fih_delay() && \
          ((x).val >= FIH_UINT_VAL_MASK((y).msk)) \
        )

#endif /* defined(IFX_L1_FIH_FIX_MISRA) */

/**
 * Standard less than comparison for fih_uint values.
 *
 * @param x  1st fih_uint value to be compared.
 * @param y  2nd fih_uint value to be compared.
 *
 * @return   FIH_TRUE if x < y, FIH_FALSE otherwise.
 */
#if defined(IFX_L1_FIH_FIX_MISRA)
#define fih_uint_lt(x, y)                                     \
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
            result = ((x).val < (y).val);                     \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = (FIH_UINT_VAL_MASK((x).msk) < FIH_UINT_VAL_MASK((y).msk)); \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val < FIH_UINT_VAL_MASK((y).msk));  \
        }                                                     \
                                                              \
        result;                                               \
    })

#else

#define fih_uint_lt(x, y) \
        ( fih_uint_validate(x)  && \
          fih_uint_validate(y) && \
          ((x).val < (y).val) && \
          fih_delay() && \
          (FIH_UINT_VAL_MASK((x).msk) < FIH_UINT_VAL_MASK((y).msk)) && \
          fih_delay() && \
          ((x).val < FIH_UINT_VAL_MASK((y).msk)) \
        )

#endif /* defined(IFX_L1_FIH_FIX_MISRA) */

/**
 * Standard less than or equal comparison for fih_uint values.
 *
 * @param x  1st fih_uint value to be compared.
 * @param y  2nd fih_uint value to be compared.
 *
 * @return   FIH_TRUE if x <= y, FIH_FALSE otherwise.
 */
#if defined(IFX_L1_FIH_FIX_MISRA)
#define fih_uint_le(x, y)                                     \
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
            result = ((x).val < (y).val);                     \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = (FIH_UINT_VAL_MASK((x).msk) <= FIH_UINT_VAL_MASK((y).msk)); \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = fih_delay();                             \
        }                                                     \
        if (result)                                           \
        {                                                     \
            result = ((x).val < FIH_UINT_VAL_MASK((y).msk));  \
        }                                                     \
                                                              \
        result;                                               \
    })

#else

#define fih_uint_le(x, y) \
        ( fih_uint_validate(x)  && \
          fih_uint_validate(y) && \
          ((x).val <= (y).val) && \
          fih_delay() && \
          (FIH_UINT_VAL_MASK((x).msk) <= FIH_UINT_VAL_MASK((y).msk)) && \
          fih_delay() && \
          ((x).val <= FIH_UINT_VAL_MASK((y).msk)) \
        )

#endif /* defined(IFX_L1_FIH_FIX_MISRA) */

/**
 * Standard logical OR for fih_uint values.
 *
 * @param x  1st fih_uint value to be ORed.
 * @param y  2nd fih_uint value to be ORed.
 *
 * @return   ORed value
 */
__attribute__((always_inline)) static inline
fih_uint fih_uint_or(fih_uint x, fih_uint y)
{
    uint32_t y_val, y_msk;
    volatile fih_uint rc = {0};

    y_val = y.val;
    rc.val = x.val | y_val;

    y_msk = y.msk;
    rc.msk = FIH_UINT_VAL_MASK(FIH_UINT_VAL_MASK(x.msk) | FIH_UINT_VAL_MASK(y_msk));

    return rc;
}


/**
 * Standard logical AND for fih_uint values.
 *
 * @param x  1st fih_uint value to be ORed.
 * @param y  2nd fih_uint value to be ORed.
 *
 * @return   ANDed value
 */
__attribute__((always_inline)) static inline
fih_uint fih_uint_and(fih_uint x, fih_uint y)
{
    uint32_t y_val, y_msk;
    volatile fih_uint rc = {0};

    y_val = y.val;
    rc.val = x.val & y_val;

    y_msk = y.msk;
    rc.msk = FIH_UINT_VAL_MASK(FIH_UINT_VAL_MASK(x.msk) & FIH_UINT_VAL_MASK(y_msk));

    return rc;
}

/*******************************************************************************
 * Function Name:  fih_uint_add
 *******************************************************************************
 * \brief Adding of two fih_uint values.
 *
 * \param x  1st fih_uint value to be added.
 * \param y  2nd fih_uint value to be added.
 *
 * \return   result of add operation.
 *
 ******************************************************************************/
__attribute__((always_inline)) static inline
fih_uint fih_uint_add(fih_uint x, fih_uint y)
{
    fih_uint rc = FIH_UINT_INIT(0U);

    rc.val = x.val + y.val;
    rc.msk = FIH_UINT_VAL_MASK(FIH_UINT_VAL_MASK(x.msk) + FIH_UINT_VAL_MASK(y.msk));

    return rc;
}

/* Global Control Flow Integrity counter */
extern fih_uint fih_cfi_ctr;

/**
 * Increment the CFI counter by input counter and return the value before the
 * increment.
 * NOTE: this function shall not be called directly.
 *
 * @param x  Increment value.
 *
 * @return   Previous value of the CFI counter.
 */
fih_uint fih_cfi_get_and_increment(uint8_t cnt);

/**
 * Validate that the saved precall value is the same as the value of the global
 * counter. For this to be the case, a fih_ret must have been called between
 * these functions being executed. If the values aren't the same then panic.
 * NOTE: this function shall not be called directly.
 *
 * @param saved  Saved value.
 */
void fih_cfi_validate(fih_uint saved);

/**
 * Decrement the global CFI counter by one, so that it has the same value as
 * before the cfi_precall.
 * NOTE: this function shall not be called directly.
 */
void fih_cfi_decrement(void);

/*
 * Macro wrappers for functions - Even when the functions have zero body this
 * saves a few bytes on noop functions as it doesn't generate the call/ret
 *
 * CFI precall function saves the CFI counter and then increments it - the
 * postcall then checks if the counter is equal to the saved value. In order for
 * this to be the case a FIH_RET must have been performed inside the called
 * function in order to decrement the counter, so the function must have been
 * called.
 */
#define FIH_CFI_PRECALL_BLOCK \
        fih_uint fih_cfi_precall_saved_value = fih_cfi_get_and_increment(1u)

#define FIH_CFI_POSTCALL_BLOCK \
        fih_cfi_validate(fih_cfi_precall_saved_value)

#define FIH_CFI_PRERET \
        fih_cfi_decrement()

/*
 * Marcos to support protect the control flow integrity inside a function.
 *
 * The FIH_CFI_PRECALL_BLOCK/FIH_CFI_POSTCALL_BLOCK pair mainly protect function
 * calls from fault injection. Fault injection may attack a function to skip its
 * critical steps which are not function calls. It is difficult for the caller
 * to dectect the injection as long as the function successfully returns.
 *
 * The following macros can be called in a function to track the critical steps,
 * especially those which are not function calls.
 */

/*
 * FIH_CFI_STEP_INIT() saves the CFI counter and increase the CFI counter by the
 * number of the critical steps. It should be called before execution starts.
 */
#define FIH_CFI_STEP_INIT(x) \
        fih_uint fih_cfi_step_saved_value = fih_cfi_get_and_increment(x)

/*
 * FIH_CFI_STEP_DECREMENT() decrease the CFI counter by one. It can be called
 * after each critical step execution completes.
 */
#define FIH_CFI_STEP_DECREMENT() \
        fih_cfi_decrement()

/*
 * FIH_CFI_STEP_ERR_RESET() resets the CFI counter to the previous value saved
 * by FIH_CFI_STEP_INIT(). It shall be called only when a functionality error
 * occurs and forces the function to exit. It can enable the caller to capture
 * the functionality error other than being trapped in fault injection error
 * handling.
 */
#define FIH_CFI_STEP_ERR_RESET() \
        do { \
            fih_cfi_ctr = fih_cfi_step_saved_value; \
            (void)fih_uint_validate(fih_cfi_ctr); \
        } while(0)


/*
 * Label for interacting with FIH testing tool. Can be parsed from the elf file
 * after compilation. Does not require debug symbols.
 */
#define FIH_LABEL(str) __asm volatile ("FIH_LABEL_" str "_0_%=:" ::)
#define FIH_LABEL_CRITICAL_POINT() FIH_LABEL("FIH_CRITICAL_POINT")

/*
 * Main FIH calling macro. return variable is second argument. Does some setup
 * before and validation afterwards. Inserts labels for use with testing script.
 *
 * First perform the precall step - this gets the current value of the CFI
 * counter and saves it to a local variable, and then increments the counter.
 *
 * Then set the return variable to FIH_FAILURE as a base case.
 *
 * Then perform the function call. As part of the function FIH_RET must be
 * called which will decrement the counter.
 *
 * The postcall step gets the value of the counter and compares it to the
 * previously saved value. If this is equal then the function call and all child
 * function calls were performed.
 */
#define FIH_UCALL(f, ret, ...) \
    do { \
        FIH_LABEL("FIH_CALL_START_" # f); \
        FIH_CFI_PRECALL_BLOCK; \
        (ret) = FIH_UINT_ZERO; \
        (void)fih_delay(); \
        (ret) = (f)(__VA_ARGS__); \
        FIH_CFI_POSTCALL_BLOCK; \
        (void)fih_uint_validate(ret); \
        FIH_LABEL("FIH_CALL_END"); \
    } while (false)


/*
 * Similar to FIH_UCALL, but return value is ignored, like (void)f(...)
 */
#define FIH_VOID(f, ...) \
    do { \
        FIH_CFI_PRECALL_BLOCK; \
        (void)fih_delay(); \
        (void)(f)(__VA_ARGS__); \
        FIH_CFI_POSTCALL_BLOCK; \
        FIH_LABEL("FIH_CALL_END"); \
    } while (false)

/*
 * FIH return changes the state of the internal state machine. If you do a
 * FIH_UCALL then you need to do a FIH_RET else the state machine will detect
 * tampering and panic.
 */
#define FIH_RET(ret) \
    do { \
        FIH_CFI_PRERET; \
        return ret; \
    } while (false)


#endif /* FAULT_INJECTION_HARDENING_H */
