/*
 * RFC 6238
 */
#ifndef TOTP_H
#define TOTP_H

#include <time.h>
#include "hotp.h"

#define T0 0
#define X 30 // time step

uint32_t totp(hotp_context *ctx, uint8_t digits = 6) {
  time_t now = time(NULL);
  ctx->counter = (now - T0) / X;
  
  return hotp(ctx, digits);
}

#endif
