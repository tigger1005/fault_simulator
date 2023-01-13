#include "common.h"

int __attribute__((noinline))
memcmp(const void *str1, const void *str2, size_t count) {
  const unsigned char *s1 = (const unsigned char *)str1;
  const unsigned char *s2 = (const unsigned char *)str2;

  while (count-- > 0) {
    if (*s1++ != *s2++)
      return s1[-1] < s2[-1] ? -1 : 1;
  }

  return 0;
}

void *__attribute__((noinline))
memcpy(void *dst, const void *src, size_t count) {
  unsigned char *d = (unsigned char *)dst;
  const unsigned char *s = (const unsigned char *)src;

  while (count-- > 0) {
    *d++ = *s++;
  }
  return d;
}

void *__attribute__((noinline)) memset(void *dst, int val, size_t count) {
  unsigned char *d = (unsigned char *)dst;

  while (count-- > 0) {
    *d++ = val;
  }
  return d;
}

void __attribute__((noinline)) serial_putc(char c) {
  *(char *)UART_OUT_BUF_ADDR = c;
}

void serial_puts(char *s) {
  while (*s) {
    serial_putc(*s);

    s++;
  }
}