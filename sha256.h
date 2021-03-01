/*
 * SHA-256 self-implemented according to RFC6234
 */

#ifndef SHA2_H
#define SHA2_H

#include <cstring>
#include <stdint.h>
#include <stdlib.h>

#define SHA2_WORD uint32_t

const SHA2_WORD SHA2_K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA2_WORD sha2_ROTR(SHA2_WORD X, uint8_t n) {
  return (X >> n) | (X << (32 - n));
}

SHA2_WORD sha2_CH(SHA2_WORD X, SHA2_WORD Y, SHA2_WORD Z) {
  return (X & Y) ^ ((~X) & Z);
}

SHA2_WORD sha2_MAJ(SHA2_WORD X, SHA2_WORD Y, SHA2_WORD Z) {
  return (X & Y) ^ (X & Z) ^ (Y & Z);
}

SHA2_WORD sha2_BSIG0(SHA2_WORD X) {
  return sha2_ROTR(X, 2) ^ sha2_ROTR(X, 13) ^ sha2_ROTR(X, 22);
}

SHA2_WORD sha2_BSIG1(SHA2_WORD X) {
  return sha2_ROTR(X, 6) ^ sha2_ROTR(X, 11) ^ sha2_ROTR(X, 25);
}

SHA2_WORD sha2_SSIG0(SHA2_WORD X) {
  return sha2_ROTR(X, 7) ^ sha2_ROTR(X, 18) ^ (X >> 3);
}

SHA2_WORD sha2_SSIG1(SHA2_WORD X) {
  return sha2_ROTR(X, 17) ^ sha2_ROTR(X, 19) ^ (X >> 10);
}

uint8_t* sha2_pad(const void* msg, size_t size, size_t* newSize = NULL) {
  if (!msg) {
    return 0;
  }

  size_t toPad = 64 - (size % 64);
  if (toPad < 9) {
    toPad += 64;
  }

  uint8_t* newArr = (uint8_t*) malloc(size + toPad);
  memcpy(newArr, msg, size);
  newArr[size] = 0x80;
  memset(newArr + size + 1, 0x00, toPad - 8);

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

uint8_t* sha256(const void* msg, size_t size) {
  SHA2_WORD h0 = 0x6a09e667;
  SHA2_WORD h1 = 0xbb67ae85;
  SHA2_WORD h2 = 0x3c6ef372;
  SHA2_WORD h3 = 0xa54ff53a;
  SHA2_WORD h4 = 0x510e527f;
  SHA2_WORD h5 = 0x9b05688c;
  SHA2_WORD h6 = 0x1f83d9ab;
  SHA2_WORD h7 = 0x5be0cd19;

  size_t messageSize;
  const uint8_t* message = sha2_pad(msg, size, &messageSize);
  for (int i = 0; i < messageSize; i += 64) {
    int t;
    const uint8_t* block = message + i;
    SHA2_WORD W[64];
    for (t = 0; t < 16; t++) {
      W[t] = block[t * 4] << 24;
      W[t] |= block[t * 4 + 1] << 16;
      W[t] |= block[t * 4 + 2] << 8;
      W[t] |= block[t * 4 + 3];
    }

    for (t = 16; t < 64; t++) {
      W[t] = sha2_SSIG1(W[t - 2]) + W[t - 7] + sha2_SSIG0(W[t - 15]) + W[t - 16];
    }

    SHA2_WORD A = h0;
    SHA2_WORD B = h1;
    SHA2_WORD C = h2;
    SHA2_WORD D = h3;
    SHA2_WORD E = h4;
    SHA2_WORD F = h5;
    SHA2_WORD G = h6;
    SHA2_WORD H = h7;
    SHA2_WORD T1, T2;

    for (t = 0; t < 64; t++) {
      T1 = H + sha2_BSIG1(E) + sha2_CH(E, F, G) + SHA2_K[t] + W[t];
      T2 = sha2_BSIG0(A) + sha2_MAJ(A, B, C);
      H = G;
      G = F;
      F = E;
      E = D + T1;
      D = C;
      C = B;
      B = A;
      A = T1 + T2;
    }

    h0 += A;
    h1 += B;
    h2 += C;
    h3 += D;
    h4 += E;
    h5 += F;
    h6 += G;
    h7 += H;
  }

  delete message;
  uint8_t* retVal = (uint8_t*) malloc(32);
  SHA2_WORD* retValView = (SHA2_WORD*) retVal;
  retValView[0] = h0;
  retValView[1] = h1;
  retValView[2] = h2;
  retValView[3] = h3;
  retValView[4] = h4;
  retValView[5] = h5;
  retValView[6] = h6;
  retValView[7] = h7;

  // platform agnostic big-endian
  for (int i = 0; i < 8; i++) {
    SHA2_WORD temp = retValView[i];
    retVal[i * 4 + 3] = temp;
    retVal[i * 4 + 2] = temp >> 8;
    retVal[i * 4 + 1] = temp >> 16;
    retVal[i * 4] = temp >> 24;
  }

  return retVal; 
}

#endif
