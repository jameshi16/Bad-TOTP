/*
 * Self-implemented RFC 2104
 */
#ifndef HMAC_H
#define HMAC_H

#include <stdlib.h>
#include <string.h>

uint8_t* hmac_pad(uint8_t* input, size_t size, size_t blockSize) {
  uint8_t* retVal = (uint8_t*) malloc(blockSize);
  memcpy(retVal, input, size);
  memset(retVal + size, 0x00, blockSize - size);
  
  return retVal;
}

uint8_t* hmac(const void* msg, size_t size, const void* K, size_t keySize, void* (*H)(const void*, size_t), size_t blockSize, size_t outputLength) {
  uint8_t* workingKey = (uint8_t*) K; 

  if (keySize > blockSize) {
    uint8_t *temp = (uint8_t*) H(K, keySize);
    workingKey = hmac_pad(temp, outputLength, blockSize);
    delete temp;
  } else {
    workingKey = hmac_pad(workingKey, keySize, blockSize);
  }

  uint8_t *intermediate1 = (uint8_t*) malloc(blockSize);
  uint8_t *intermediate2 = (uint8_t*) malloc(blockSize);
  for (int i = 0; i < blockSize; i++) {
    intermediate1[i] = workingKey[i] ^ 0x36;
    intermediate2[i] = workingKey[i] ^ 0x5c;
  }

  uint8_t *intermediate3 = (uint8_t*) malloc(blockSize + size);
  memcpy(intermediate3, intermediate1, blockSize);
  memcpy(intermediate3 + blockSize, msg, size);

  uint8_t *intermediate4 = (uint8_t*) H(intermediate3, blockSize + size);
  uint8_t *intermediate5 = (uint8_t*) malloc(blockSize + outputLength);
  memcpy(intermediate5, intermediate2, blockSize);
  memcpy(intermediate5 + blockSize, intermediate4, outputLength);

  uint8_t *result = (uint8_t*) H(intermediate5, blockSize + outputLength);
  free(intermediate1);
  free(intermediate2);
  free(intermediate3);
  free(intermediate4);
  free(intermediate5);
  free(workingKey);

  return result;
}

#endif
