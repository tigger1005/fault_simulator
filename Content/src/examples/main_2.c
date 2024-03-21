#include "common.h"
#include "fih_mem.h"
#include "utils.h"

void launch_oem_ram_app(void);

#define success 0x01234567
#define failure 0xFEFEFEFE

DECISION_DATA_STRUCTURE(volatile uint32_t, success, failure);

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

/*******************************************************************************
 * Function Name:  main
 *******************************************************************************
 * \brief This is the main function executed at start.
 *
 *******************************************************************************/
int main() {
  decision_activation();

  serial_puts("Some code 1...\n");

  if (DECISION_DATA == success) {
    serial_puts("Verification positive path  : OK\n");
    if (DECISION_DATA != success || DECISION_DATA == failure) {
      FIH_PANIC;
    }

    launch_oem_ram_app();
  } else {
    serial_puts("Verification negative path : OK\n");
    FIH_PANIC;
  }
  return 0;
}
