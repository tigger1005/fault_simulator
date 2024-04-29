/**
 * @file main_3.c
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

/*******************************************************************************
 * Function Name:  main
 *******************************************************************************
 * \brief This is the main function executed at start.
 *
 *******************************************************************************/
int main() {
  decision_activation();

  serial_puts("Some code 1...\n");

  if (fih_uint_eq(DECISION_DATA, FIH_SUCCESS)) {
    serial_puts("Verification positive path : OK\n");
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
void start_success_handling(void) { __SET_SIM_SUCCESS(); }
