/**
 * @file test.c
 * @author Roland Ebrecht
 * @brief Source of the pre-built integration test binary `tests/bin/test.elf`.
 *
 * This is not a hardening example. It deliberately reads from 0x30000000, which is
 * not part of any ELF segment, so it only runs when that area is mapped through a
 * configuration (see `tests/test_config_memory_region.json5`) and always needs
 * `--no-check`, because the baseline behaviour check cannot pass without the
 * mapping. It exercises `memory_regions`, `code_patches`, `initial_registers` and
 * `result_checks` against an otherwise uninstrumented binary.
 *
 * Rebuild after a change with the target C project Makefile and copy the result
 * to `tests/bin/test.elf`.
 *
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


// Simple function that reads from unmapped memory
volatile uint32_t *unmapped_ptr = (volatile uint32_t *)0x30000000;


/*******************************************************************************
 * Function Name:  check_secret
 *******************************************************************************
 * \brief This function checks a secret value from unmapped memory.
 *
 *******************************************************************************/
int check_secret() {
    uint32_t value = *unmapped_ptr;  // This will fault without memory init
    if (value == 0x12345678) {
        return 1;  // Success
    }
    return 0;  // Failure
}

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

    if (check_secret())
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
