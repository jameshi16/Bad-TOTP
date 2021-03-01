#ifndef TEST_SHA512
#define TEST_SHA512

#include "../sha512.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int test_sha512_helper(const void* msg, size_t size, const char* expected) {
  printf("Message: %s\n", (const char*) msg);
  printf("Expected: %s\n", expected);

  uint8_t* data = sha512(msg, size);
  char result[128];
  for (int i = 0; i < 64; i++) {
    sprintf(result + i * 2, "%02x", data[i]);
  }
  printf("Actual:   %s\n", result);

  int compareResult = strcmp(result, expected);
  compareResult ? printf("Failed\n\n") : printf("Passed\n\n");
  free(data);
  return compareResult;
}

int test_sha512() {
  const char message1[] = "abc";
  const char message2[] = "";
  const char message3[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  const char message4[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

  const char result1[] = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
  const char result2[] = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
  const char result3[] = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445";
  const char result4[] = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

  int result = 0;

  result += test_sha512_helper(message1, sizeof(message1) - 1, result1) ? 1 : 0;
  result <<= 1;
  result += test_sha512_helper(message2, sizeof(message2) - 1, result2) ? 1 : 0;
  result <<= 1;
  result += test_sha512_helper(message3, sizeof(message3) - 1, result3) ? 1 : 0;
  result <<= 1;
  result += test_sha512_helper(message4, sizeof(message4) - 1, result4) ? 1 : 0;
  result <<= 1;

  return result;
}

#endif
