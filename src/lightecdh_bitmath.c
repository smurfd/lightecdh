#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"

void print_bit(uint32_t* a, char* s, int len) {
  printf("%s = [ ", s);
  for (int i = 0; i < len; ++i) {
    printf("0x%.8x ", (uint32_t)a[i]);
  }
  printf("]\n");
}

// Copy bits
void lightecdh_bit_copy(bit x, const bit y) {
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    x[i] = y[i];
  }
}

void lightecdh_bit_mod_n(bit x, const bit y) {
  extern bit ecdh_n;
  if (y[0] % ecdh_n[0] == 0) {
    for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
      x[i] = y[i] % ecdh_n[i];
    }
  } else {
    for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
      x[i] = y[i];
    }
  }
}

void lightecdh_bit_neg(bit x, const bit y) {
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    x[i] = y[i]^(-1);
  }
}

// Clear bit
void lightecdh_bit_clear(bit x, const u32 idx) {
  x[idx / 32U] &= ~(1U << (idx & 31U));
}

// Set bits to zero
void lightecdh_bit_zero(bit x) {
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    x[i] = 0;
  }
}

int lightecdh_bit_is_zero(const bit x) {
  int ret = 1;
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    ret &= (x[i] == 0);
  }
  return ret;
}

// Return the number of the highest one-bit + 1
int lightecdh_bit_degree(const bit x) {
  int i = BITVEC_NWORDS * 32;
  // Start at the back of the vector (MSB)
  x += BITVEC_NWORDS;

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
void lightecdh_bit_add(bit z, const bit x, const bit y) {
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    z[i] = (x[i] ^ y[i]);
  }
}

// increment element
void lightecdh_bit_inc(bit x) {
  x[0] ^= 1;
}

// field multiplication 'z := (x * y)'
void lightecdh_bit_mul(bit z, const bit x, const bit y) {
  bit tmp;
  assert(z != y);

  lightecdh_bit_copy(tmp, x);

  // LSB set? Then start with x
  if (lightecdh_bit_get(y, 0) != 0) {
    lightecdh_bit_copy(z, x);
  } else {
    lightecdh_bit_zero(z);
  }

  // Then add 2^i * x for the rest
  for (int i = 1; i < CURVE_DEGREE; ++i) {
    extern bit ecdh_p;
    // lshift 1 - doubling the value of tmp
    lightecdh_bit_lshift(tmp, tmp, 1);

    // Modulo reduction polynomial if degree(tmp) > CURVE_DEGREE
    if (lightecdh_bit_get(tmp, CURVE_DEGREE)) {
      lightecdh_bit_add(tmp, tmp, ecdh_p);
    }

    // Add 2^i * tmp if this factor in y is non-zero
    if (lightecdh_bit_get(y, i)) {
      lightecdh_bit_add(z, z, tmp);
    }
  }
}

void lightecdh_bit_swap(bit x, bit y) {
  bit tmp;
  lightecdh_bit_copy(tmp, x);
  lightecdh_bit_copy(x, y);
  lightecdh_bit_copy(y, tmp);
}

int lightecdh_bit_get(const bit x, const u32 idx) {
  return ((x[idx / 32U] >> (idx & 31U) & 1U));
}

int lightecdh_bit_equal(const bit x, const bit y) {
  int ret = 1;
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    ret &= (x[i] == y[i]);
  }
  return ret;
}

// field inversion 'z := 1/x'
void lightecdh_bit_inv(bit z, const bit x) {
  bit u, v, g, h;
  extern bit ecdh_p;

  lightecdh_bit_copy(u, x);
  lightecdh_bit_copy(v, ecdh_p);
  lightecdh_bit_zero(g);
  lightecdh_bit_one(z);
  
  while (!lightecdh_bit_is_one(u)) {
    int i = (lightecdh_bit_degree(u) - lightecdh_bit_degree(v));
    if (i < 0) {
      lightecdh_bit_swap(u, v);
      lightecdh_bit_swap(g, z);
      i = -i;
    }
    lightecdh_bit_lshift(h, v, i);
    lightecdh_bit_add(u, u, h);
    lightecdh_bit_lshift(h, g, i);
    lightecdh_bit_add(z, z, h);
  }
}

// left-shift by 'count' digits
void lightecdh_bit_lshift(bit x, const bit y, int nb) {
  int i, j;
  int nw = (nb / 32);

  // Shift whole words first if nwords > 0
  for (i = 0; i < nw; ++i) {
    // Zero-initialize from least-significant word until offset reached
    x[i] = 0;
  }
  j=0;
  // Copy to x output
  while (i < BITVEC_NWORDS) {
    x[i] = y[j];
    i += 1;
    j += 1;
  }

  // Shift the rest if count was not multiple of bitsize of DTYPE
  nb &= 31;
  if (nb != 0) {
    // Left shift rest
    for (int i = (BITVEC_NWORDS - 1); i > 0; --i) {
      x[i]  = (x[i] << nb) | (x[i - 1] >> (32 - nb));
    }
    x[0] <<= nb;
  }
}

void lightecdh_bit_one(bit x) {
  // Set first word to one
  x[0] = 1;
  // .. and the rest to zero
  for (int i = 1; i < BITVEC_NWORDS; ++i) {
    x[i] = 0;
  }
}

// constant-time check
int lightecdh_bit_is_one(const bit x) {
  int ret = 0;
  // Check if first word == 1
  if (x[0] == 1) {
    ret = 1;
  }
  // ...and if rest of words == 0
  for (int i = 1; i < BITVEC_NWORDS; ++i) {
    ret &= (x[i] == 0);
  }
  return ret;
}
