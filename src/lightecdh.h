#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh_curves.h"

#ifndef LIGHTECDH_H 
#define LIGHTECDH_H 1

// Defines
// NIST_K163 || NIST_B163
#define CURVE_DEGREE       163
#define ECC_PRV_KEY_SIZE    24

#define ECC_PUB_KEY_SIZE   (2 * ECC_PRV_KEY_SIZE)

#define BITVEC_MARGIN     3
#define BITVEC_NBITS      (CURVE_DEGREE + BITVEC_MARGIN)
#define BITVEC_NWORDS     ((BITVEC_NBITS + 31) / 32)
#define BITVEC_NBYTES     (sizeof(uint32_t) * BITVEC_NWORDS)

typedef uint8_t u08;
typedef uint32_t u32;
typedef uint32_t bit[BITVEC_NWORDS];
typedef uint32_t sig[ECC_PRV_KEY_SIZE];

void lightecdh_keygen(u32* pubkey, u32* privkey);
int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res);

void lightecdh_sign(const u32* privkey, u32* hash, u32* rnd, u32* sign);
void lightecdh_verify(const u32* publkey, u32* hash, u32* sign);

void lightecdh_sign_wikipedia(const u32* privkey, u32* hash, u32* rnd, u32* sign);
void lightecdh_verify_wikipedia(const u32* publkey, u32* hash, u32* sign);

void lightecdh_sign_pdf(const u32* privkey, u32* hash, u32* rnd, u32* sign);
void lightecdh_verify_pdf(const u32* publkey, u32* hash, u32* sign);
#endif
