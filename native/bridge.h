#ifndef TQKTLS_BRIDGE_H
#define TQKTLS_BRIDGE_H

#include <stdint.h>

/* Transport callbacks implemented by the C# side (read/write ciphertext, close). */
typedef int (*tqk_read_cb)(void *ctx, uint8_t *buf, int len);
typedef int (*tqk_write_cb)(void *ctx, uint8_t *buf, int len);
typedef void (*tqk_close_cb)(void *ctx);

/* Trampolines: Go cannot call a C function pointer directly, so it calls these. */
int tqk_call_read(tqk_read_cb f, void *ctx, uint8_t *buf, int len);
int tqk_call_write(tqk_write_cb f, void *ctx, uint8_t *buf, int len);
void tqk_call_close(tqk_close_cb f, void *ctx);

#endif /* TQKTLS_BRIDGE_H */
