/**
 * @file main_5.c
 * @author Roland Ebrecht
 * @brief Demonstration of "--no-check" command line parameter. This switch deactivate the verification 
 * of the program flow for the positive and the negative case. With this the DECISION_DATA_STRUCTURE is 
 * not required to hold the positive data value and the decision_activation() function can be removed.
 * @version 0.1
 * @date 2024-04-29
 *
 */

 #include "bootutil/fault_injection_hardening.h"
#include "common.h"
 #include "utils.h"
 
 void start_success_handling(void);
 
 // When "--no-check" is activated, a SUCCESS data value is not necessary and reduces false-positive findings.
DECISION_DATA_STRUCTURE(fih_uint, FIH_FAILURE, FIH_FAILURE);
//DECISION_DATA_STRUCTURE(fih_uint, FIH_SUCCESS, FIH_FAILURE);
 
//  __attribute__((noinline)) fih_uint get_value(fih_uint *t)
//  {
//      return *t;
//  }
 
//  __attribute__((noinline)) bool check_equal(fih_uint *a, fih_uint *b)
//  {
//      return a->val == b->val;
//  }
 
__attribute__((noinline)) bool check_equal_mask(fih_uint *a, fih_uint *b)
{
    return a->msk == b->msk;
}

//  __attribute__((noinline)) bool check_address(fih_uint *a, fih_uint *b)
//  {
//      return a != b;
//  }

#define fih_uint_eq_new(x, y)                   \
    ((x.val == y.val) &&                        \
    fih_delay() &&                              \
    ((y).val == FIH_UINT_VAL_MASK(x.msk)) &&    \
    fih_delay() &&                              \
    fih_uint_validate(x) &&                     \
    check_equal_mask(&x,&y))
 
 /*******************************************************************************
  * Function Name:  main
  *******************************************************************************
  * \brief This is the main function executed at start.
  *
  *******************************************************************************/
 int main()
 {
    int ret = -1;

    serial_puts("Some code 1...\n");

    if (fih_uint_eq_new(DECISION_DATA, FIH_SUCCESS))
    {
    // Fix for linker problem (success_handling is directly behind the return function)
    __SET_SIM_CONDITION_TRUE();

        serial_puts("Verification positive path : OK\n");
        start_success_handling();
        ret = 0;
    }
    else
    {

        serial_puts("Verification negative path : OK\n");
        __SET_SIM_FAILED();
        ret = 1;
    }
    return ret;
 }
 
 /*******************************************************************************
  * Function Name:  start_success_handling
  *******************************************************************************
  * \brief This function launch CM33 OEM RAM App.
  *
  * \param secure_boot_policy    The policy secure boot value.
  * \param ram_app_start_addr    The start address of RAM App.
  *
  *******************************************************************************/
void start_success_handling(void)
{
    __SET_SIM_SUCCESS_WITH_CONDITION();
}
 