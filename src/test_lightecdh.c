#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "lightecdh.h"
#include "lightecdh_random.h"
#include "lightecdh_curves.h"
#include "lightecdh_bitmath.h"


void genkeys() {
  cur* cc = lightecdh_curves_get(NIST_K163);
  u32 publ_a[(*cc).PUBL];
  u32 priv_a[(*cc).PRIV];
  u32 secr_a[(*cc).PUBL];
  u32 publ_b[(*cc).PUBL];
  u32 priv_b[(*cc).PRIV];
  u32 secr_b[(*cc).PUBL];
  int initialized = 0;

  if (!initialized) {
    prng_init((u32)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
    initialized = 1;
  }

  // 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob.
  for (u32 i = 0; i < (u32)(*cc).PRIV; ++i) {
    priv_a[i] = prng_next();
  }
  lightecdh_keygen(publ_a, priv_a, cc);

  // 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice.
  for (u32 i = 0; i < (u32)(*cc).PRIV; ++i) {
    priv_b[i] = prng_next();
  }
  lightecdh_keygen(publ_b, priv_b, cc);

  // 3. Alice calculates S = a * Q = a * (b * g)
  assert(lightecdh_shared_secret(priv_a, publ_b, secr_a, cc));

  // 4. Bob calculates T = b * P = b * (a * g).
  assert(lightecdh_shared_secret(priv_b, publ_a, secr_b, cc));

  // 5. Assert equality, i.e. check that both parties calculated the same value.
  for (u32 i = 0; i < (u32)(*cc).PUBL; ++i) {
    assert(secr_a[i] == secr_b[i]);
  }
  lightecdh_curves_end(cc);
}

void verify() {
  cur* cc = lightecdh_curves_get(NIST_K163);
  u32 publ_a[(*cc).PUBL];
  u32 priv_a[(*cc).PRIV];
  u32 msg[(*cc).PRIV];
  u32 sign[(*cc).PUBL];
  u32 k[(*cc).PRIV];

  srand(time(0));
  srand(42);

  for (int i = 0; i < (*cc).PRIV; ++i) {
    priv_a[i] = rand();
    msg[i] = priv_a[i] ^ rand();
    k[i] = rand();
  }

  lightecdh_keygen(publ_a, priv_a, cc);

  lightecdh_sign_wikipedia(priv_a, msg, k, sign, cc);
  lightecdh_verify_wikipedia(publ_a, msg, sign, cc);
  lightecdh_curves_end(cc);
}

int main(int argc, char **argv) {
  genkeys(); // Works
  verify();  // does not work, guessing it has todo with size of keys/signatures and what not.

  printf("OK! (but we are not ok yet :))\n");
  u64 sig[LEE_B*2], h[LEE_B*2], pubkey[LEE_B+1], privkey[LEE_B], sec[LEE_B];

  prng_init((u64)(0xea1 ^ 0x31ee7 ^ 42) | 0xe1ee77ee | 31337);
  for (int i = 0; i < LEE_B; ++i) {
    usleep(10); h[i] = prng_next();
  }

  if (argc == 2 && argv) {
    if (strcmp(argv[1], "keys") == 0) {
      usleep(1); assert(lee_make_keys(pubkey, privkey));
    } else if (strcmp(argv[1], "secret") == 0) {
      usleep(1); assert(lee_make_keys(pubkey, privkey));
      usleep(1); assert(lee_shar_secr(pubkey, privkey, sec));
    } else if (strcmp(argv[1], "sign") == 0) {
      usleep(1); assert(lee_make_keys(pubkey, privkey));
      usleep(1); assert(lee_shar_secr(pubkey, privkey, sec));
      usleep(1); assert(lee_sign(privkey, h, sig));
    } else if (strcmp(argv[1], "verify") == 0) {
      usleep(1); assert(lee_make_keys(pubkey, privkey));
      usleep(1); assert(lee_shar_secr(pubkey, privkey, sec));
      usleep(1); assert(lee_sign(privkey, h, sig));
      usleep(1); assert(lee_vrfy(pubkey, h, sig));
    }
  }
}
