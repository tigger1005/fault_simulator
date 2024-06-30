/**
 * @file main.c
 * @author Roland Ebrecht
 * @brief 
 * @version 0.1
 * @date 2024-04-29
 *
 */

#include "common.h"
#include "fih_mem.h"
#include "utils.h"

void start_success_handling(void);

typedef struct {
  uint8_t val[24];
} data_el;

#define SUCCESS_DATA                                                           \
  {                                                                            \
    {                                                                          \
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,  \
          0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,    \
          0x18                                                                 \
    }                                                                          \
  }
#define FAILED_DATA                                                            \
  {                                                                            \
    {                                                                          \
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,  \
          0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x14, 0x16, 0x17,    \
          0x18                                                                 \
    }                                                                          \
  }

DECISION_DATA_STRUCTURE(data_el, SUCCESS_DATA, FAILED_DATA);

/*******************************************************************************
 * Function Name:  main
 *******************************************************************************
 * \brief This is the main function executed at start.
 *
 *******************************************************************************/
int main() {
  decision_activation();

  int res = memcmp(&decisiondata.data_element, 
                   &decisiondata.success_data_element, 
                   decisiondata.decision_element_size);
  if (res == 0) {
    serial_puts("Verification positive path  : OK\n");

    start_success_handling();
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
void start_success_handling(void) {
  int res = memcmp(&decisiondata.data_element, 
                   &decisiondata.success_data_element, 
                   decisiondata.decision_element_size);
  if (res != 0)
  {
    __SET_SIM_FAILED();
  }
  __SET_SIM_SUCCESS(); 
}
