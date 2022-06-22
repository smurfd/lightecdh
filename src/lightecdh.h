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

void lightecdh_keygen(u32* pubkey, u32* privkey, cur* cc);
int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res, cur* cc);

void lightecdh_sign(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc);
void lightecdh_verify(const u32* publkey, u32* hash, u32* sign, cur* cc);

void lightecdh_sign_wikipedia(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc);
void lightecdh_verify_wikipedia(const u32* publkey, u32* hash, u32* sign, cur* cc);

void lightecdh_sign_pdf(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc);
void lightecdh_verify_pdf(const u32* publkey, u32* hash, u32* sign, cur* cc);
#endif
