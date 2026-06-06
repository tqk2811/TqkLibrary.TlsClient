#include "bridge.h"

int tqk_call_read(tqk_read_cb f, void *ctx, uint8_t *buf, int len) { return f(ctx, buf, len); }
int tqk_call_write(tqk_write_cb f, void *ctx, uint8_t *buf, int len) { return f(ctx, buf, len); }
void tqk_call_close(tqk_close_cb f, void *ctx) { if (f) f(ctx); }
