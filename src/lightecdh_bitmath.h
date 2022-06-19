#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"

#ifndef LIGHTECDH_BITMATH_H 
#define LIGHTECDH_BITMATH_H 1

void print_bit(uint32_t* a, char* s, int len);
void lightecdh_bit_copy(bit x, const bit y);
void lightecdh_bit_clear(bit x, const u32 idx);
void lightecdh_bit_zero(bit x);
void lightecdh_bit_neg(bit x, const bit y);
void lightecdh_bit_neg1(bit x, const bit y);
void lightecdh_bit_mod(bit x, const bit y, const bit z);
/*void lightecdh_bit_mod_n(bit x, const bit y);
void lightecdh_bit_mod_p(bit x, const bit y);
void lightecdh_bit_mod_x(bit x, const bit y);
void lightecdh_bit_mod_b(bit x, const bit y);*/
int lightecdh_bit_is_zero(const bit x);
int lightecdh_bit_degree(const bit x);
void lightecdh_bit_add(bit z, const bit x, const bit y);
void lightecdh_bit_inc(bit x);
void lightecdh_bit_mul(bit z, const bit x, const bit y);
void lightecdh_bit_swap(bit x, bit y);
int lightecdh_bit_get(const bit x, const u32 idx);
void lightecdh_bit_inv(bit z, const bit x);
void lightecdh_bit_lshift(bit x, const bit y, int nb);
void lightecdh_bit_one(bit x);
int lightecdh_bit_is_one(const bit x);
int lightecdh_bit_equal(const bit x, const bit y);
#endif
