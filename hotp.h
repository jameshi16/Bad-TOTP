/*
 * RFC 4226
 */

#ifndef HOTP_H
#define HOTP_H

#include <stdlib.h>
#include <math.h>
#include "hmac.h"

struct hotp_context {
  uint64_t counter;
  const uint8_t* secret;
  size_t secretSize;

  void* (*hashFn)(const void*, size_t);
  size_t blockSize;
  size_t outputLength;
};

uint32_t hotp_DT(const uint8_t* data, size_t len) {
  uint8_t offset = data[len - 1] & 0x0f;
  uint32_t p = (data[offset] & 0x7f) << 24 
    | data[offset + 1] << 16 
    | data[offset + 2] << 8
    | data[offset + 3];

  return p;
}

uint32_t hotp(hotp_context *ctx, uint8_t digits = 6) {
  if (!ctx) {
    return 0;
  }

  uint8_t counter[8];
  counter[0] = ctx->counter >> 56;
  counter[1] = ctx->counter >> 48;
  counter[2] = ctx->counter >> 40;
  counter[3] = ctx->counter >> 32;
  counter[4] = ctx->counter >> 24;
  counter[5] = ctx->counter >> 16;
  counter[6] = ctx->counter >> 8;
  counter[7] = ctx->counter;

  uint8_t* hs = hmac(counter, sizeof(counter), ctx->secret, ctx->secretSize, ctx->hashFn, ctx->blockSize, ctx->outputLength);

  uint32_t Snum = hotp_DT(hs, ctx->outputLength);
  free(hs);
  return Snum % (uint32_t) pow(10, digits);
}

#endif
