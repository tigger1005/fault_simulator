#include "common.h"
#include "utils.h"

void launch_oem_ram_app(void);

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
    launch_oem_ram_app();
  } else {
    serial_puts("Verification negative path : OK\n");
    __SET_SIM_FAILED();
  }
  return 0;
}

/*******************************************************************************
 * Function Name:  launch_oem_ram_app
 *******************************************************************************
 * \brief This function launch CM33 OEM RAM App.
 *
 * \param secure_boot_policy    The policy secure boot value.
 * \param ram_app_start_addr    The start address of RAM App.
 *
 *******************************************************************************/
void launch_oem_ram_app(void) { __SET_SIM_SUCCESS(); }
