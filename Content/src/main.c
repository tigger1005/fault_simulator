#include "common.h"
#include "fih_mem.h"
#include "utils.h"

void launch_oem_ram_app(void);

#define GLOBAL_CFI_START_VALUE 0x123B
#define GLOBAL_CFI_END_VALUE (GLOBAL_CFI_START_VALUE - 3)

int main() {
  flash_load_img();
  CHECKPOINT_INIT();
  CHECKPOINT();
  fih_uint addr1 = FIH_UINT_INIT((uint32_t)IMG_LOAD_ADDR);
  fih_uint length = FIH_UINT_INIT(4);
  fih_uint addr2 = FIH_UINT_INIT((uint32_t)&image_good_val);
  fih_int res = FIH_UINT_INIT(FIH_FALSE);
  CHECKPOINT();

  res = fih_memcmp(addr1, addr2, length);
  FIH_IF_INT_EQUAL(res, fih_int_encode(FIH_TRUE)) {
    FIH_IF_INT_EQUAL_BODY_CHECK(res, fih_int_encode(FIH_TRUE));
    CHECKPOINT();
    FIH_IF_INT_EQUAL_BODY_CHECK(res, fih_int_encode(FIH_TRUE));
    serial_puts("Verification positive path  : OK\n");
    launch_oem_ram_app();
  }
  else {
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
void launch_oem_ram_app(void) {
  // This could be for example a specific MPU setting to allow execution
  __SET_SIM_CONDITION_TRUE();
  /* Validate and run CM33 OEM RAM Application. */
  VALIDATE_FINAL_CHECKPOINT();
  //__SET_SIM_SUCCESS();
  __SET_SIM_SUCCESS_WITH_CONDITION();
}
