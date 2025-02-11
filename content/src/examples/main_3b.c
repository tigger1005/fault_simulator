/**
 * @file main_3.c
 * @author Roland Ebrecht
 * @brief Demonstration of "--no-check" command line parameter. This switch deactivate the verification 
 * of the program flow for the positive and the negative case. With this the DECISION_DATA_STRUCTURE is 
 * not required to hold the positive data value and the decision_activation() function can be removed.
 * @version 0.1
 * @date 2024-04-29
 *
 */

#include "common.h"
#include "utils.h"

void start_success_handling(void);

// When "--no-check" is activated, a SUCCESS data value is not necessary and reduces false-positive findings.
DECISION_DATA_STRUCTURE(fih_uint, FIH_FAILURE, FIH_FAILURE);
//DECISION_DATA_STRUCTURE(fih_uint, FIH_SUCCESS, FIH_FAILURE);

/*******************************************************************************
 * Function Name:  main
 *******************************************************************************
 * \brief This is the main function executed at start.
 *
 *******************************************************************************/
int main()
{
    int ret = -1;
    // When "--no-check" is activated, this trigger is not necessary
    //decision_activation();

    serial_puts("Some code 1...\n");

    if (fih_uint_eq(DECISION_DATA, FIH_SUCCESS))
    {
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
    __SET_SIM_SUCCESS();
}
