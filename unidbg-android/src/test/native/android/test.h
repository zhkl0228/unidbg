#include <stdio.h>

static void hex(char *buf, void *ptr, size_t size) {
  const char *data = (const char *) ptr;
  int idx = 0;
  for(int i = 0; i < size; i++) {
    idx += sprintf(&buf[idx], "%02x", data[i] & 0xff);
  }
}
