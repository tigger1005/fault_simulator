#include "bootutil/fault_injection_hardening.h"
#include "common.h"
#include "fih_mem.h"
#include "utils.h"

void launch_oem_ram_app(void);

#define val1 (*(uint32_t *)IMG_LOAD_ADDR)
#define val2 (*(uint32_t *)&image_good_val)

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
  flash_load_img();
  fih_uint value_1 = FIH_UINT_INIT(val1);
  fih_uint value_2 = FIH_UINT_INIT(val2);

  if (fih_uint_eq(value_1, value_2) == FIH_TRUE) {
    serial_puts("Verification positive path  : OK\n");
    if (fih_uint_eq(value_1, value_2) != FIH_TRUE) {
      FIH_PANIC;
    }
    launch_oem_ram_app();
  } else {
    serial_puts("Verification negative path : OK\n");
    __SET_SIM_FAILED();
  }
  return 0;
}
