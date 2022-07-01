#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh_curves.h"

#ifndef LIGHTECDH_H 
#define LIGHTECDH_H 1

// Typedefs
typedef uint8_t u08;
typedef uint32_t u32;
typedef uint32_t bit[571];
typedef uint32_t sig[72];
typedef struct curves cur;
typedef uint64_t u64;
typedef unsigned int uint;
typedef unsigned __int128 u128;

#define LEE_B 48             // Bytes //secp384r1
#define LEE_D (LEE_B / 8)    // Digits

#define EVEN(p) (!(p[0] & 1))

typedef struct lee_p {
  u64 x[LEE_D], y[LEE_D];
} lee_p;

#define Curve_P {0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe,\
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}
#define Curve_B {0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,\
  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4}
#define Curve_G {{0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38,\
  0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537}, {\
  0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0,\
  0xf8f41dbd289a147c, 0x5d9e98bf9292dc29, 0x3617de4a96262c6f}}
#define Curve_N {0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf,\
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}

static u64 curve_p[LEE_D] = Curve_P;
static u64 curve_b[LEE_D] = Curve_B;
static lee_p curve_g      = Curve_G;
static u64 curve_n[LEE_D] = Curve_N;

void lightecdh_keygen(u32* pubkey, u32* privkey, cur* cc);
int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res, cur* cc);

void lightecdh_sign(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc);
void lightecdh_verify(const u32* publkey, u32* hash, u32* sign, cur* cc);

void lightecdh_sign_wikipedia(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc);
void lightecdh_verify_wikipedia(const u32* publkey, u32* hash, u32* sign, cur* cc);

void lightecdh_sign_pdf(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc);
void lightecdh_verify_pdf(const u32* publkey, u32* hash, u32* sign, cur* cc);

uint lee_digits(u64 *p);
uint lee_bits(u64 *p);
int lee_iszero(u64 *p);
int lee_cmp(u64 *p, u64 *q);
void lee_clear(u64 *p);
void lee_set(u64 *r, const u64 *p);
u64 lee_isset(u64 *p, uint q);
#endif
