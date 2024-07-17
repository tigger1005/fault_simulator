/**
 * @file main_5.c
 * @author Roland Ebrecht
 * @brief 
 * @version 0.1
 * @date 2024-04-29
 *
 */

#include "common.h"
#include "utils.h"

void start_success_handling(void);

DECISION_DATA_STRUCTURE(fih_uint, FIH_SUCCESS, FIH_FAILURE);

__attribute__((noinline)) fih_uint get_value(fih_uint *t) {
  return * t;
}

#define fih_uint_eq_new(x, y)  \
  (fih_uint_validate(x)  && \
    (get_value(&x).val == (y).val) && \
    fih_delay() && \
    (get_value(&x).msk == (y).msk) && \
    fih_delay() && \
    ((y).val == FIH_UINT_VAL_MASK(get_value(&x).msk))  \
  )


/*******************************************************************************
 * Function Name:  main
 *******************************************************************************
 * \brief This is the main function executed at start.
 *
 *******************************************************************************/
 int main() {
  decision_activation();

  serial_puts("Some code 1...\n");

  if (fih_uint_eq_new(DECISION_DATA, FIH_SUCCESS)) {
    serial_puts("Verification positive path : OK\n");
    
    // Changed to "with_condition" because of linker problem (start_success_handling() is directly located after get_value()). 
    __SET_SIM_CONDITION_TRUE();

    start_success_handling();
  } else {
    serial_puts("Verification negative path : OK\n");
    __SET_SIM_FAILED();
  }
  return 0;
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
void start_success_handling(void) { 
    __SET_SIM_SUCCESS_WITH_CONDITION();
}
