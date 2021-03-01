# Bad-TOTP

[![Tests](https://github.com/jameshi16/Bad-TOTP/actions/workflows/tests.yml/badge.svg)](https://github.com/jameshi16/Bad-TOTP/actions/workflows/tests.yml)

Prefixed with "Bad" because this is not meant to be used in production.

Bad-TOTP is a small educational-only project that I decided to do in a weekend to learn about Time-based One Time Passwords (TOTP), and how they work. I then made the decision to implement everything required for TOTPs from scratch (i.e. using nothing but standard C and some standard library functions), including the SHA-1 hash algorithm (and its brothers, SHA-256 and SHA-512), Hash-based Message Authentication Code (HMAC), and Hash-based One Time Passwords (HOTP).

This repository contains all the code created from the aftermath.

## Usage

This project uses header files only. Default parameters from [RFC 6238](https://tools.ietf.org/html/rfc6238) are used, such as the time step (30 seconds), and `T0 = 0`; these parameters are widely used in all forms of TOTPs on the internet. 

You would minimally need `totp.h`, `hotp.h`, and one of `sha1.h`, `sha256.h` or `sha512.h`. Here is sample code utilizing `sha1.h` as the hash header:

```c
#include "sha1.h"
#include "hotp.h"
#include "totp.h"

#include <stdio.h>

int main() {
  const char secret[] = "a very secret key!!!";

  hotp_context ctx;
  ctx.secret = (const uint8_t*) secret;
  ctx.secretSize = sizeof(secret) - 1;
  ctx.hashFn = (void* (*) (const void*, size_t)) method_two;
  ctx.blockSize = 64;
  ctx.outputLength = 20;

  printf("%d\n", totp(&ctx, 6));
  return 0;
}
```

Given that your secret is the perfect length, i.e. divisible by the output length of the hash function, this OTP should be consistent with other RFC6238 implementations. However, if the secret isn't aligned to the output length perfectly, 0s will be padded to the end of the string until the output length is perfect-lengthed (as defined in [RFC2104 page 3](https://tools.ietf.org/html/rfc2104#page-3)).

## Relevant blog post

Coming soon.
