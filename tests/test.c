#include "test_sha1.h"
#include "test_sha256.h"
#include "test_sha512.h"
#include "test_hmac_sha1.h"
#include "test_hmac_sha256.h"
#include "test_hmac_sha512.h"
#include "test_hotp.h"

#include <stdio.h>

int main() {
  int hasFailed = 0;

  printf("===[SHA1]===\n");
  int testResult = test_sha1();
  if (testResult) {
    printf("SHA1 Test failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("SHA1 Test passed.\n");
  };

  printf("\n===[SHA256]===\n");
  testResult = test_sha256();
  if (testResult) {
    printf("SHA256 Test failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("SHA256 Test passed.\n");
  };

  printf("\n===[SHA512]===\n");
  testResult = test_sha512();
  if (testResult) {
    printf("SHA512 Test failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("SHA512 Test passed.\n");
  };

  printf("\n===[HMAC-SHA1]===\n");
  testResult = test_hmac_sha1();
  if (testResult) {
    printf("HMAC-SHA1 Test failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("HMAC-SHA1 Test passed.\n");
  };

  printf("\n===[HMAC-SHA256]===\n");
  testResult = test_hmac_sha256();
  if (testResult) {
    printf("HMAC-SHA256 Test failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("HMAC-SHA256 Test passed.\n");
  };

  printf("\n===[HMAC-SHA512]===\n");
  testResult = test_hmac_sha512();
  if (testResult) {
    printf("HMAC-SHA512 Test failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("HMAC-SHA512 Test passed.\n");
  };

  printf("\n===[HOTP]===\n");
  testResult = test_hotp();
  if (testResult) {
    printf("HOTP failed: %d\n", testResult);
    hasFailed = 1;
  } else {
    printf("HOTP passed.\n");
  }

  hasFailed ? printf("\n\nSome tests failed\n") : printf("\n\nAll tests passed\n");
  return hasFailed;
}
