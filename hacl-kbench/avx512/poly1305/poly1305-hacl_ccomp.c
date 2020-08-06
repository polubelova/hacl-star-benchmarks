#include "kbench-common.h"

extern void Hacl_Poly1305_32_poly1305_mac_ccomp(
  uint8_t *tag, uint32_t len1, uint8_t *text, uint8_t *key
);

void poly1305_hacl_ccomp(uint8_t *tag, uint8_t *text, uint32_t len1, uint8_t *key)
{
  Hacl_Poly1305_32_poly1305_mac_ccomp(tag,len1,text,key);
}
