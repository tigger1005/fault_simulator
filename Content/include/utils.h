#ifndef H_UTILS
#define H_UTILS

#include "common.h"

int memcmp(const void *str1, const void *str2, size_t count);
void memcpy(void *dst, const void *src, size_t count);
void __attribute__((noinline)) memset(void *dst, uint8_t val, size_t count);
void __attribute__((noinline)) serial_putc(char c);
void serial_puts(char *s);

#endif // H_UTILS