/* su_stub.c - Stub for embedded su when not available */
#include <stdint.h>

/* Empty stub - su daemon not embedded */
__attribute__((visibility("default")))
const uint8_t embedded_su_start[] = { 0 };

__attribute__((visibility("default")))
const uint8_t embedded_su_end[] = { 0 };
