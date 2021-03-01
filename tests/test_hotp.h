#include "../hotp.h"
#include "../sha1.h"

#include <stdio.h>

int test_hotp() {
  const uint8_t secret[] = "12345678901234567890";
  const uint32_t expected[] = {
    755224, 287082, 359152, 969429, 338314,
    254676, 287922, 162583, 399871, 520489
  };

  hotp_context ctx;
  ctx.counter = 0;
  ctx.secret = secret;
  ctx.secretSize = sizeof(secret) - 1;
  ctx.hashFn = (void* (*) (const void*, size_t))method_two;
  ctx.blockSize = 64;
  ctx.outputLength = 20; 

  int failedOnce = 0;
  for (int i = 0; i < 10; i++) {
    ctx.counter = i;
    uint32_t otp = hotp(&ctx);
    printf("Count: %d, Expected: %d, Actual: %d\n", i, expected[i], hotp(&ctx));

    if (otp != expected[i]) {
      failedOnce = 1;
    }
  }
  failedOnce ? printf("Failed.\n") : printf("Passed.\n");

  return failedOnce;
}
