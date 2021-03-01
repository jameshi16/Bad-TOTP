#ifndef TEST_SHA256
#define TEST_SHA256

#include "../sha256.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int test_sha256_helper(const void* msg, size_t size, const char* expected) {
  printf("Message: %s\n", (const char*) msg);
  printf("Expected: %s\n", expected);

  uint8_t* data = sha256(msg, size);
  char result[64];
  for (int i = 0; i < 32; i++) {
    sprintf(result + i * 2, "%02x", data[i]);
  }
  printf("Actual:   %s\n", result);

  int compareResult = strcmp(result, expected);
  compareResult ? printf("Failed\n\n") : printf("Passed\n\n");
  free(data);
  return compareResult;
}

int test_sha256() {
  const char message1[] = "abc";
  const char message2[] = "";
  const char message3[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  const char message4[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

  const char result1[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const char result2[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const char result3[] = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
  const char result4[] = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";

  int result = 0;

  result += test_sha256_helper(message1, sizeof(message1) - 1, result1) ? 1 : 0;
  result <<= 1;
  result += test_sha256_helper(message2, sizeof(message2) - 1, result2) ? 1 : 0;
  result <<= 1;
  result += test_sha256_helper(message3, sizeof(message3) - 1, result3) ? 1 : 0;
  result <<= 1;
  result += test_sha256_helper(message4, sizeof(message4) - 1, result4) ? 1 : 0;
  result <<= 1;

  return result;
}

#endif
