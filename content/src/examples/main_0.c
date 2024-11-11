/**
 * @file main_0.c
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

#define success 0x01234567
#define failure 0xFEFEFEFE

DECISION_DATA_STRUCTURE(uint32_t, success, failure);

/*******************************************************************************
 * Function Name:  main
 *******************************************************************************
 * \brief This is the main function executed at start.
 *
 *******************************************************************************/
int main()
{
    int ret = -1;
    decision_activation();

    serial_puts("Some code 1...\n");

    if (DECISION_DATA == success)
    {
        serial_puts("Verification positive path  : OK\n");
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
    __SET_SIM_SUCCESS();
}
