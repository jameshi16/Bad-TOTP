/*
 * SHA-512 self-implemented according to RFC6234
 */

#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SHA512_WORD uint64_t

const SHA512_WORD sha512_K[] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

SHA512_WORD sha512_ROTR(SHA512_WORD X, uint8_t n) {
  return (X >> n) | (X << (64 - n));
}

SHA512_WORD sha512_CH(SHA512_WORD X, SHA512_WORD Y, SHA512_WORD Z) {
  return (X & Y) ^ ((~X) & Z);
}

SHA512_WORD sha512_MAJ(SHA512_WORD X, SHA512_WORD Y, SHA512_WORD Z) {
  return (X & Y) ^ (X & Z) ^ (Y & Z);
}

SHA512_WORD sha512_BSIG0(SHA512_WORD X) {
  return sha512_ROTR(X, 28) ^ sha512_ROTR(X, 34) ^ sha512_ROTR(X, 39);
}

SHA512_WORD sha512_BSIG1(SHA512_WORD X) {
  return sha512_ROTR(X, 14) ^ sha512_ROTR(X, 18) ^ sha512_ROTR(X, 41);
}

SHA512_WORD sha512_SSIG0(SHA512_WORD X) {
  return sha512_ROTR(X, 1) ^ sha512_ROTR(X, 8) ^ (X >> 7);
}

SHA512_WORD sha512_SSIG1(SHA512_WORD X) {
  return sha512_ROTR(X, 19) ^ sha512_ROTR(X, 61) ^ (X >> 6);
}

uint8_t* sha512_pad(const void* msg, size_t size, size_t* newSize) {
  if (!msg) {
    return 0;
  }

  size_t toPad = 128 - (size % 128);
  if (toPad < 17) {
    toPad += 128;
  }

  uint8_t* newArr = (uint8_t*) malloc(size + toPad);
  memcpy(newArr, msg, size);
  newArr[size] = 0x80;
  memset(newArr + size + 1, 0x00, toPad - 16);

  const uint64_t lowerSizeInBits = size * 8; // whatever can be captured will be captured
  const uint64_t upperSizeInBits = size >> 61; // this is (size >> 64) * 8

  const uintptr_t ptr = size + toPad - 16;
  newArr[ptr] = upperSizeInBits >> 56;
  newArr[ptr + 1] = upperSizeInBits >> 48;
  newArr[ptr + 2] = upperSizeInBits >> 40;
  newArr[ptr + 3] = upperSizeInBits >> 32;
  newArr[ptr + 4] = upperSizeInBits >> 24;
  newArr[ptr + 5] = upperSizeInBits >> 16;
  newArr[ptr + 6] = upperSizeInBits >> 8;
  newArr[ptr + 7] = upperSizeInBits;
  newArr[ptr + 8] = lowerSizeInBits >> 56;
  newArr[ptr + 9] = lowerSizeInBits >> 48;
  newArr[ptr + 10] = lowerSizeInBits >> 40;
  newArr[ptr + 11] = lowerSizeInBits >> 32;
  newArr[ptr + 12] = lowerSizeInBits >> 24;
  newArr[ptr + 13] = lowerSizeInBits >> 16;
  newArr[ptr + 14] = lowerSizeInBits >> 8;
  newArr[ptr + 15] = lowerSizeInBits; 

  if (newSize) {
    *newSize = size + toPad;
  }

  return newArr;
}

uint8_t* sha512(const void* msg, size_t size) {
  SHA512_WORD h0 = 0x6a09e667f3bcc908;
  SHA512_WORD h1 = 0xbb67ae8584caa73b;
  SHA512_WORD h2 = 0x3c6ef372fe94f82b;
  SHA512_WORD h3 = 0xa54ff53a5f1d36f1;
  SHA512_WORD h4 = 0x510e527fade682d1;
  SHA512_WORD h5 = 0x9b05688c2b3e6c1f;
  SHA512_WORD h6 = 0x1f83d9abfb41bd6b;
  SHA512_WORD h7 = 0x5be0cd19137e2179;
  
  size_t messageSize;
  uint8_t* message = sha512_pad(msg, size, &messageSize);
  for (int i = 0; i < messageSize; i += 128) {
    int t;
    const uint8_t* block = message + i;
    SHA512_WORD W[80];

    for (t = 0; t < 16; t++) {
      W[t] = (SHA512_WORD) block[t * 8] << 56;
      W[t] |= (SHA512_WORD) block[t * 8 + 1] << 48;
      W[t] |= (SHA512_WORD) block[t * 8 + 2] << 40;
      W[t] |= (SHA512_WORD) block[t * 8 + 3] << 32;
      W[t] |= (SHA512_WORD) block[t * 8 + 4] << 24;
      W[t] |= (SHA512_WORD) block[t * 8 + 5] << 16;
      W[t] |= (SHA512_WORD) block[t * 8 + 6] << 8;
      W[t] |= (SHA512_WORD) block[t * 8 + 7];
    }

    for (t = 16; t < 80; t++) {
      W[t] = sha512_SSIG1(W[t - 2]) + W[t - 7] + sha512_SSIG0(W[t - 15]) + W[t - 16];
    }

    SHA512_WORD A = h0;
    SHA512_WORD B = h1;
    SHA512_WORD C = h2;
    SHA512_WORD D = h3;
    SHA512_WORD E = h4;
    SHA512_WORD F = h5;
    SHA512_WORD G = h6;
    SHA512_WORD H = h7;
    SHA512_WORD T1, T2;

    for (t = 0; t < 80; t++) {
      T1 = H + sha512_BSIG1(E) + sha512_CH(E, F, G) + sha512_K[t] + W[t];
      T2 = sha512_BSIG0(A) + sha512_MAJ(A, B, C); 
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

  free(message);
  uint8_t* retVal = (uint8_t*) malloc(128);
  SHA512_WORD* retValView = (SHA512_WORD*) retVal;
  retValView[0] = h0;
  retValView[1] = h1;
  retValView[2] = h2;
  retValView[3] = h3;
  retValView[4] = h4;
  retValView[5] = h5;
  retValView[6] = h6;
  retValView[7] = h7;

  for (int i = 0; i < 8; i++) {
    SHA512_WORD temp = retValView[i];
    retVal[i * 8] = temp >> 56;
    retVal[i * 8 + 1] = temp >> 48;
    retVal[i * 8 + 2] = temp >> 40;
    retVal[i * 8 + 3] = temp >> 32;
    retVal[i * 8 + 4] = temp >> 24;
    retVal[i * 8 + 5] = temp >> 16;
    retVal[i * 8 + 6] = temp >> 8;
    retVal[i * 8 + 7] = temp;
  }

  return retVal;
}

#endif
