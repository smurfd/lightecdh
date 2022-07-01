#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"

void print_bit(uint32_t* a, char* s, int len) {
  printf("%s = [ ", s);
  for (int i = 0; i < len; ++i) {
    printf("0x%.8x ", (u32)a[i]);
  }
  printf("]\n");
}

// Copy bits
void lightecdh_bit_copy(bit x, const bit y, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {
    x[i] = y[i];
  }
}

void lightecdh_bit_mod(bit x, const bit y, const bit z, cur* cc) {
  // TODO: this is not working!
  if (y[0] % z[0] != 0) {
    for (int i = 0; i < (*cc).NWOR; ++i) {
      x[i] = y[i] % z[i];
    }
  } else {
    for (int i = 0; i < (*cc).NWOR; ++i) {
      x[i] = y[i];
    }
  }
}

void lightecdh_bit_mod1(bit x, const bit y, const bit z, cur* cc) {
  // if y is divisable in z, should be enough to check 1st digit
  if (y[0] >= z[0]) {
    u32 w = (u32)(y[0] / z[0]);
    for (int i = 0; i < (*cc).NWOR; ++i) {
      x[i] = y[i] - (z[i] * w);
    }
  } else {
    for (int i = 0; i < (*cc).NWOR; ++i) {
      x[i] = y[i];
    }
  }
}

void lightecdh_bit_neg(bit x, const bit y, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {
    x[i] = y[i]^(-1);
  }
}

void lightecdh_bit_neg1(bit x, const bit y, cur* cc) {
  int j = 0;
  for (int i = 0; i < (*cc).NWOR; ++i) {
    x[i] = y[i];
  }
  x[0] = x[0] * (-0xffffffffL);

  for (int i = (*cc).NWOR - 1; i >= 0; i--) {
    if (x[i] != 0) {
      j = i;
    }
  }
  x[j] = x[j] + 0x00000001UL;
}

// Clear bit
void lightecdh_bit_clear(bit x, const u32 idx) {
  x[idx / 32U] &= ~(1U << (idx & 31U));
}

// Set bits to zero
void lightecdh_bit_zero(bit x, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {
    x[i] = 0;
  }
}

int lightecdh_bit_is_zero(const bit x, cur* cc) {
  int ret = 1;
  for (int i = 0; i < (*cc).NWOR; ++i) {
    ret &= (x[i] == 0);
  }
  return ret;
}

// Return the number of the highest one-bit + 1
int lightecdh_bit_degree(const bit x, cur* cc) {
  int i = (*cc).NWOR * 32;
  // Start at the back of the vector (MSB)
  x += (*cc).NWOR;

  // Skip empty / zero words
  while ((i > 0) && (*(--x)) == 0) {
    i -= 32;
  }
  // Run through rest if count is not multiple of bitsize of DTYPE
  if (i != 0) {
    u32 u32mask = ((u32)1 << 31);
    while ((u32)((*x) & u32mask) == 0) {
      u32mask >>= 1;
      i -= 1;
    }
  }
  return i;
}

// galois field(2^m) addition is modulo 2, so XOR is used instead - 'z := a + b'
void lightecdh_bit_add(bit z, const bit x, const bit y, cur* cc) {
  for (int i = 0; i < (*cc).NWOR; ++i) {
    z[i] = (x[i] ^ y[i]);
  }
}

// increment element
void lightecdh_bit_inc(bit x) {
  x[0] ^= 1;
}

// field multiplication 'z := (x * y)'
void lightecdh_bit_mul(bit z, const bit x, const bit y, cur* cc) {
  bit tmp;
  assert(z != y);

  lightecdh_bit_copy(tmp, x, cc);

  // LSB set? Then start with x
  if (lightecdh_bit_get(y, 0) != 0) {
    lightecdh_bit_copy(z, x, cc);
  } else {
    lightecdh_bit_zero(z, cc);
  }

  // Then add 2^i * x for the rest
  for (int i = 1; i < (*cc).DEGR; ++i) {
    //extern bit ecdh_p;
    // lshift 1 - doubling the value of tmp
    lightecdh_bit_lshift(tmp, tmp, 1, cc);

    // Modulo reduction polynomial if degree(tmp) > CURVE_DEGREE
    if (lightecdh_bit_get(tmp, (*cc).DEGR)) {
      lightecdh_bit_add(tmp, tmp, (*cc).ecdh_p, cc);
    }

    // Add 2^i * tmp if this factor in y is non-zero
    if (lightecdh_bit_get(y, i)) {
      lightecdh_bit_add(z, z, tmp, cc);
    }
  }
}

void lightecdh_bit_swap(bit x, bit y, cur* cc) {
  bit tmp;
  lightecdh_bit_copy(tmp, x, cc);
  lightecdh_bit_copy(x, y, cc);
  lightecdh_bit_copy(y, tmp, cc);
}

int lightecdh_bit_get(const bit x, const u32 idx) {
  return ((x[idx / 32U] >> (idx & 31U) & 1U));
}

int lightecdh_bit_equal(const bit x, const bit y, cur* cc) {
  int ret = 1;
  for (int i = 0; i < (*cc).NWOR; ++i) {
    ret &= (x[i] == y[i]);
  }
  return ret;
}

// field inversion 'z := 1/x'
void lightecdh_bit_inv(bit z, const bit x, cur* cc) {
  bit u, v, g, h;
 // extern bit ecdh_p;

  lightecdh_bit_copy(u, x, cc);
  lightecdh_bit_copy(v, (*cc).ecdh_p, cc);
  lightecdh_bit_zero(g, cc);
  lightecdh_bit_one(z, cc);
  
  while (!lightecdh_bit_is_one(u, cc)) {
    int i = (lightecdh_bit_degree(u, cc) - lightecdh_bit_degree(v, cc));
    if (i < 0) {
      lightecdh_bit_swap(u, v, cc);
      lightecdh_bit_swap(g, z, cc);
      i = -i;
    }
    lightecdh_bit_lshift(h, v, i, cc);
    lightecdh_bit_add(u, u, h, cc);
    lightecdh_bit_lshift(h, g, i, cc);
    lightecdh_bit_add(z, z, h, cc);
  }
}

// left-shift by 'count' digits
void lightecdh_bit_lshift(bit x, const bit y, int nb, cur* cc) {
  int i, j;
  int nw = (nb / 32);

  // Shift whole words first if nwords > 0
  for (i = 0; i < nw; ++i) {
    // Zero-initialize from least-significant word until offset reached
    x[i] = 0;
  }
  j=0;
  // Copy to x output
  while (i < (*cc).NWOR) {
    x[i] = y[j];
    i += 1;
    j += 1;
  }

  // Shift the rest if count was not multiple of bitsize of DTYPE
  nb &= 31;
  if (nb != 0) {
    // Left shift rest
    for (int i = ((*cc).NWOR - 1); i > 0; --i) {
      x[i]  = (x[i] << nb) | (x[i - 1] >> (32 - nb));
    }
    x[0] <<= nb;
  }
}

// right-shift by 'count' digits (maby?)
void lightecdh_bit_rshift(bit x, const bit y, int nb, cur* cc) {
  int i, j;
  int nw = (nb / 32);

  // Shift whole words first if nwords > 0
  for (i = 0; i < nw; ++i) {
    // Zero-initialize from least-significant word until offset reached
    x[i] = 0;
  }
  j=0;
  // Copy to x output
  while (i < (*cc).NWOR) {
    x[i] = y[j];
    i += 1;
    j += 1;
  }

  // Shift the rest if count was not multiple of bitsize of DTYPE
  nb &= 31;
  if (nb != 0) {
    // Left shift rest
    for (int i = ((*cc).NWOR - 1); i > 0; --i) {
      x[i]  = (x[i] >> nb) | (x[i - 1] << (32 - nb));
    }
    x[0] >>= nb;
  }
}

void lightecdh_bit_one(bit x, cur* cc) {
  // Set first word to one
  x[0] = 1;
  // .. and the rest to zero
  for (int i = 1; i < (*cc).NWOR; ++i) {
    x[i] = 0;
  }
}

// constant-time check
int lightecdh_bit_is_one(const bit x, cur* cc) {
  int ret = 0;
  // Check if first word == 1
  if (x[0] == 1) {
    ret = 1;
  }
  // ...and if rest of words == 0
  for (int i = 1; i < (*cc).NWOR; ++i) {
    ret &= (x[i] == 0);
  }
  return ret;
}

// Computes p_result = p_in << c, returning car.
// Can modify in place (if p_result == p_in). 0 < p_shift < 64.
u64 lee_lshift(u64 *r, u64 *p, uint q) {
  u64 car = 0;
  for (uint8_t i = 0; i < LEE_D; ++i) {
    u64 temp = p[i];
    r[i] = (temp << q) | car;
    car = temp >> (64 - q);
  }

  return car;
}

// Computes p_vli = p_vli >> 1.
void lee_rshift1(u64 *p) {
  u64 *end = p;
  u64 car = 0;

  p += LEE_D;
  while (p-- > end) {
    u64 temp = *p;
    *p = (temp >> 1) | car;
    car = temp << 63;
  }
}

// Computes p_result = p_left + p_right, returning car.
// Can modify in place.
u64 lee_add(u64 *r, u64 *p, u64 *q) {
  u64 car = 0;
  for (uint8_t i = 0; i < LEE_D; ++i) {
    u64 sum = p[i] + q[i] + car;
    if (sum != p[i]) {
      car = (sum < p[i]);
    }
    r[i] = sum;
  }
  return car;
}

// Computes p_result = p_left - p_right, returning borrow.
// Can modify in place.
u64 lee_sub(u64 *r, u64 *p, u64 *q) {
  u64 borrow = 0;
  for (uint8_t i = 0; i < LEE_D; ++i) {
    u64 diff = p[i] - q[i] - borrow;
    if (diff != p[i]) {
      borrow = (diff > p[i]);
    }
    r[i] = diff;
  }
  return borrow;
}

// Computes p_result = p_left * p_right.
void lee_mul(u64 *r, u64 *p, u64 *q) {
  u128 r01 = 0;
  u64 r2 = 0;

  // Compute each digit of p_result in sequence, maintaining the carries.
  for (uint8_t k = 0; k < LEE_D * 2 - 1; ++k) {
    uint min = (k < LEE_D ? 0 : (k + 1) - LEE_D);
    for (uint8_t i = min; i <= k && i < LEE_D; ++i) {
      u128 product = (u128)p[i] * q[k-i];
      r01 += product;
      r2 += (r01 < product);
    }
    r[k] = (u64)r01;
    r01 = (r01 >> 64) | (((u128)r2) << 64);
    r2 = 0;
  }

  r[LEE_D * 2 - 1] = (u64)r01;
}

// Computes p_result = p_left^2.
void lee_sqr(u64 *r, u64 *p) {
  u128 r01 = 0;
  u64 r2 = 0;

  for (uint8_t k = 0; k < LEE_D * 2 - 1; ++k) {
    uint min = (k < LEE_D ? 0 : (k + 1) - LEE_D);
    for (uint8_t i = min; i <= k && i <= k - i; ++i) {
      u128 product = (u128)p[i] * p[k-i];
      if (i < k - i) {
        r2 += product >> 127;
        product *= 2;
      }
      r01 += product;
      r2 += (r01 < product);
    }
    r[k] = (u64)r01;
    r01 = (r01 >> 64) | (((u128)r2) << 64);
    r2 = 0;
  }

  r[LEE_D * 2 - 1] = (u64)r01;
}
