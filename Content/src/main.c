#include "../include/common.h"
#include "../include/utils.h"

const uint32_t img_value = 0x12345678;
void __attribute__((noinline)) flash_load_img(void){};

void __attribute__((noinline)) boot_next_stage(void) {
  // Indicate we successfully bypassed the signature verification
  __SET_SIM_SUCCESS();
}

int main(void) {
  serial_puts("Start Secure Boot...\n");
  flash_load_img();

  uint32_t *image = (uint32_t *)IMG_LOAD_ADDR;

  if (memcmp(&img_value, image, sizeof(uint32_t))) {
    serial_puts("Negative program flow!\n");
    __SET_SIM_FAILED();
  }

  serial_puts("Positive program flow\n");

  boot_next_stage();

  while (true) {
  };

  return 0;
}
