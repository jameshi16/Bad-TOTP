/*
 * SHA-1 self-implemented according to RFC3174
 * Exit codes:
 * 1: Function f impossible case
 * 2: Function K impossible case
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* We want exact 32bits; uint_fast32_t sometimes assign a type larger than 32bits */
#define SHA1_WORD uint32_t

SHA1_WORD sha1_f(uint8_t t, SHA1_WORD B, SHA1_WORD C, SHA1_WORD D) {
  if (t <= 19) {
    return (B & C) | ((~B) & D);
  } else if (t <= 39) {
    return B ^ C ^ D;
  } else if (t <= 59) {
    return (B & C) | (B & D) | (C & D);
  } else if (t <= 79) {
    return B ^ C ^ D;
  }

  exit(1); // impossible case
}

SHA1_WORD sha1_K(uint8_t t) {
  if (t <= 19) {
    return 0x5A827999;
  } else if (t <= 39) {
    return 0x6ED9EBA1;
  } else if (t <= 59) {
    return 0x8F1BBCDC;
  } else {
    return 0xCA62C1D6;
  }

  exit(2); // impossible case
}

SHA1_WORD sha1_Sn(SHA1_WORD X, uint8_t n) {
  return (X << n) | (X >> 32 - n);
}

// return copy of array that is padded
uint8_t* sha1_pad(const void* msg, size_t size, size_t* newSize) {
  if (!msg) {
    return 0;
  }

  size_t toPad = 64 - (size % 64);
  if (toPad < 9) { // spillover
    toPad += 64;
  }

  uint8_t* newArr = (uint8_t*) malloc(size + toPad);
  memcpy(newArr, msg, size);
  newArr[size] = 0x80;
  memset(newArr + size + 1, 0x00, toPad - 8); // -8 for 2 words at the back

  /*
   * This code relies too much on the endianess of the system, so we won't be using it
   * uint64_t* ref = (uint64_t*) (newArr + size + toPad - 8);
   * ref = size * 8;
   */

  const uint64_t sizeInBits = size * 8;
  const uint8_t ptr = size + toPad - 8;
  newArr[ptr] = sizeInBits >> 56;
  newArr[ptr + 1] = sizeInBits >> 48;
  newArr[ptr + 2] = sizeInBits >> 40;
  newArr[ptr + 3] = sizeInBits >> 32;
  newArr[ptr + 4] = sizeInBits >> 24;
  newArr[ptr + 5] = sizeInBits >> 16;
  newArr[ptr + 6] = sizeInBits >> 8;
  newArr[ptr + 7] = sizeInBits;

  if (newSize) {
    *newSize = size + toPad;
  }

  return newArr;
}

uint8_t* method_one(const void* msg, size_t size) {
  SHA1_WORD h0 = 0x67452301;
  SHA1_WORD h1 = 0xefcdab89;
  SHA1_WORD h2 = 0x98badcfe;
  SHA1_WORD h3 = 0x10325476;
  SHA1_WORD h4 = 0xc3d2e1f0;

  size_t messageSize = 0;
  uint8_t* message = sha1_pad(msg, size, &messageSize);
  for (int i = 0; i < messageSize; i += 64) {
    int t = 0;
    uint8_t* block = message + i;
    SHA1_WORD W[80];

    for (t = 0; t < 16; t++) {
      W[t] = block[t * 4] << 24;
      W[t] |= block[t * 4 + 1] << 16;
      W[t] |= block[t * 4 + 2] << 8;
      W[t] |= block[t * 4 + 3];
    }

    for (t = 16; t < 80; t++) {
      W[t] =  sha1_Sn(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    SHA1_WORD A = h0;
    SHA1_WORD B = h1;
    SHA1_WORD C = h2;
    SHA1_WORD D = h3;
    SHA1_WORD E = h4;
    SHA1_WORD TEMP = 0;

    for (t = 0; t < 80; t++) {
      TEMP = sha1_Sn(A, 5) + sha1_f(t, B, C, D) + E + W[t] + sha1_K(t);
      E = D;
      D = C;
      C = sha1_Sn(B, 30);
      B = A;
      A = TEMP;
    }

    h0 += A;
    h1 += B;
    h2 += C;
    h3 += D;
    h4 += E;
  }

  free(message);

  uint8_t* retVal = (uint8_t*) malloc(20);
  SHA1_WORD* retValView = (SHA1_WORD*) retVal;
  retValView[0] = h0;
  retValView[1] = h1;
  retValView[2] = h2;
  retValView[3] = h3;
  retValView[4] = h4;

  for (int i = 0; i < 5; i++) {
    SHA1_WORD temp = retValView[i];
    retVal[i * 4] = temp >> 24;
    retVal[i * 4 + 1] = temp >> 16;
    retVal[i * 4 + 2] = temp >> 8;
    retVal[i * 4 + 3] = temp;
  }

  return retVal;
}

uint8_t* method_two(const void* msg, size_t size) {
  SHA1_WORD MASK = 0x0000000F;
  SHA1_WORD h0 = 0x67452301;
  SHA1_WORD h1 = 0xefcdab89;
  SHA1_WORD h2 = 0x98badcfe;
  SHA1_WORD h3 = 0x10325476;
  SHA1_WORD h4 = 0xc3d2e1f0;

  size_t messageSize = 0;
  uint8_t* message = sha1_pad(msg, size, &messageSize);
  for (int i = 0; i < messageSize; i += 64) {
    int t = 0;
    uint8_t* block = message + i;
    SHA1_WORD W[80];

    for (t = 0; t < 16; t++) {
      W[t] = block[t * 4] << 24;
      W[t] |= block[t * 4 + 1] << 16;
      W[t] |= block[t * 4 + 2] << 8;
      W[t] |= block[t * 4 + 3];
    }

    SHA1_WORD A = h0;
    SHA1_WORD B = h1;
    SHA1_WORD C = h2;
    SHA1_WORD D = h3;
    SHA1_WORD E = h4;
    SHA1_WORD TEMP;

    for (t = 0; t < 80; t++) {
      int s = t & MASK;
      if (t >= 16) {
        W[s] = sha1_Sn(W[(s + 13) & MASK] ^ W[(s + 8) & MASK] ^ W[(s + 2) & MASK] ^ W[s], 1);
      }

      TEMP = sha1_Sn(A, 5) + sha1_f(t, B, C, D) + E + W[s] + sha1_K(t);

      E = D;
      D = C;
      C = sha1_Sn(B, 30);
      B = A;
      A = TEMP;
    }

    h0 += A;
    h1 += B;
    h2 += C;
    h3 += D;
    h4 += E;
  }

  free(message);

  uint8_t* retVal = (uint8_t*) malloc(20);
  SHA1_WORD* retValView = (SHA1_WORD*) retVal;
  retValView[0] = h0;
  retValView[1] = h1;
  retValView[2] = h2;
  retValView[3] = h3;
  retValView[4] = h4;

  for (int i = 0; i < 5; i++) {
    SHA1_WORD temp = retValView[i];
    retVal[i * 4] = temp >> 24;
    retVal[i * 4 + 1] = temp >> 16;
    retVal[i * 4 + 2] = temp >> 8;
    retVal[i * 4 + 3] = temp;
  }

  return retVal;
}

#define sha1(msg, size) method_two(msg, size)

#endif
