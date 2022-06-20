#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "lightecdh.h"
#include "lightecdh_random.h"
#include "lightecdh_curves.h"

void genkeys() {
  static u32 publ_a[ECC_PUB_KEY_SIZE];
  static u32 priv_a[ECC_PRV_KEY_SIZE];
  static u32 secr_a[ECC_PUB_KEY_SIZE];
  static u32 publ_b[ECC_PUB_KEY_SIZE];
  static u32 priv_b[ECC_PRV_KEY_SIZE];
  static u32 secr_b[ECC_PUB_KEY_SIZE];
  static int initialized = 0;

  lightecdh_curves_set(NIST_K163);

  if (!initialized) {
    prng_init((u32)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
    initialized = 1;
  }

  // 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob.
  for (u32 i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    priv_a[i] = prng_next();
  }
  lightecdh_keygen(publ_a, priv_a);

  // 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice.
  for (u32 i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    priv_b[i] = prng_next();
  }
  lightecdh_keygen(publ_b, priv_b);

  // 3. Alice calculates S = a * Q = a * (b * g)
  assert(lightecdh_shared_secret(priv_a, publ_b, secr_a));

  // 4. Bob calculates T = b * P = b * (a * g).
  assert(lightecdh_shared_secret(priv_b, publ_a, secr_b));

  // 5. Assert equality, i.e. check that both parties calculated the same value.
  for (u32 i = 0; i < ECC_PUB_KEY_SIZE; ++i) {
    assert(secr_a[i] == secr_b[i]);
  }
}

void verify() {
  static u32 publ_a[ECC_PUB_KEY_SIZE];
  static u32 priv_a[ECC_PRV_KEY_SIZE];
  static u32 publ_b[ECC_PUB_KEY_SIZE];
  static u32 priv_b[ECC_PRV_KEY_SIZE];
  static u32 msg[ECC_PRV_KEY_SIZE];
  static u32 sign[ECC_PUB_KEY_SIZE];
  static u32 k[ECC_PRV_KEY_SIZE];
  static int initialized = 0;

  lightecdh_curves_set(NIST_K163);
  
  if (!initialized) {
    prng_init((u32)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
    initialized = 1;
  }

  // 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob.
  for (u32 i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    priv_a[i] = prng_next();
  }
  lightecdh_keygen(publ_a, priv_a);

  // 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice.
  for (u32 i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    priv_b[i] = prng_next();
  }
  lightecdh_keygen(publ_b, priv_b);

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    msg[i] = priv_a[i] ^ prng_next();
    k[i] = prng_next();
  }

  lightecdh_sign(priv_a, msg, k, sign);
  lightecdh_verify(publ_a, msg, sign);
}

int main() {
  genkeys(); // Works
  verify();  // does not work, guessing it has todo with size of keys/signatures and what not.

  printf("OK! (but we are not ok yet :))\n");
}
