#include "common.h"
#include "utils.h"

void launch_oem_ram_app(void);

int main() {
  fih_uint var_a_global = (*(fih_uint *)IMG_LOAD_ADDR);
  fih_uint var_b_global = FIH_SUCCESS;

  flash_load_img();

  serial_puts("Some code ...\n");
  serial_puts("Some code ...\n");

  if (fih_uint_eq(var_a_global, var_b_global)) {
    //    if (fih_uint_eq(var_a_global, FIH_SUCCESS)) {
    launch_oem_ram_app();
    //    }
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
