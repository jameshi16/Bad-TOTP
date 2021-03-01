#ifndef TEST_SHA1
#define TEST_SHA1

#include "../sha1.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int test_sha1_helper(const void* msg, size_t size, const char* expected) {
  printf("Message: %s\n", (const char*) msg);
  printf("Expected: %s\n", expected);
 
  uint8_t* data = method_two(msg, size);
  char result[40];
  for (int i = 0; i < 20; i++) {
    sprintf(result + i * 2, "%02x", data[i]);
  }
  printf("Actual:   %s\n", result);

  int compareResult = strcmp(result, expected);
  compareResult ? printf("Failed\n\n") : printf("Passed\n\n");
  free(data);
  return compareResult;
}

int test_sha1() {
  const char message1[] = "abc";
  const char message2[] = "";
  const char message3[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  const char message4[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

  const char result1[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
  const char result2[] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
  const char result3[] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
  const char result4[] = "a49b2446a02c645bf419f995b67091253a04a259";

  int result = 0;

  result += test_sha1_helper(message1, sizeof(message1) - 1, result1) ? 1 : 0;
  result <<= 1;
  result += test_sha1_helper(message2, sizeof(message2) - 1, result2) ? 1 : 0;
  result <<= 1;
  result += test_sha1_helper(message3, sizeof(message3) - 1, result3) ? 1 : 0;
  result <<= 1;
  result += test_sha1_helper(message4, sizeof(message4) - 1, result4) ? 1 : 0;
  result <<= 1;

  return result;
}

#endif
