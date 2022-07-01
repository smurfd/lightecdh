#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"
#include "lightecdh_pointmath.h"

// Copy point
void lightecdh_point_copy(bit x1, bit y1, const bit x2, const bit y2, cur* cc) {
  lightecdh_bit_copy(x1, x2, cc);
  lightecdh_bit_copy(y1, y2, cc);
}

void lightecdh_point_mul(bit x, bit y, const bit exp, cur* cc) {
  bit tmpx, tmpy, dummyx, dummyy;
  int nb = lightecdh_bit_degree(exp, cc);

  lightecdh_point_zero(tmpx, tmpy, cc);
  lightecdh_point_zero(dummyx, dummyy, cc);
  for (int i = (nb - 1); i >= 0; --i) {
    lightecdh_point_double(tmpx, tmpy, cc);
    // Add point if bit(i) is set in exp
    if (lightecdh_bit_get(exp, i)) {
      lightecdh_point_add(tmpx, tmpy, x, y, cc);
    }
  }

  lightecdh_point_copy(x, y, tmpx, tmpy, cc);
}

// double the point (x,y)
void lightecdh_point_double(bit x, bit y, cur* cc) {
  // iff P = O (zero or infinity): 2 * P = P
  if (lightecdh_bit_is_zero(x, cc)) {
    lightecdh_bit_zero(y, cc);
  } else {
    bit l;
    //extern int ecdh_a;
    lightecdh_bit_inv(l, x, cc);
    lightecdh_bit_mul(l, l, y, cc);
    lightecdh_bit_add(l, l, x, cc);
    lightecdh_bit_mul(y, x, x, cc);
    lightecdh_bit_mul(x, l, l, cc);
    if ((*cc).ecdh_a == 1) {
      lightecdh_bit_inc(l);
    }
    lightecdh_bit_add(x, x, l, cc);
    lightecdh_bit_mul(l, l, x, cc);
    lightecdh_bit_add(y, y, l, cc);
  }
}

// add two points together (x1, y1) := (x1, y1) + (x2, y2)
void lightecdh_point_add(bit x1, bit y1, const bit x2, const bit y2, cur* cc) {
  //extern int ecdh_a;
  if (!lightecdh_point_is_zero(x2, y2, cc)) {
    if (lightecdh_point_is_zero(x1, y1, cc)) {
      lightecdh_point_copy(x1, y1, x2, y2, cc);
    } else {
      if (lightecdh_bit_equal(x1, x2, cc)) {
        if (lightecdh_bit_equal(y1, y2, cc)) {
          lightecdh_point_double(x1, y1, cc);
        } else {
          lightecdh_point_zero(x1, y1, cc);
        }
      } else {
        // Arithmetic with temporary variables
        bit a, b, c, d;

        lightecdh_bit_add(a, y1, y2, cc);
        lightecdh_bit_add(b, x1, x2, cc);
        lightecdh_bit_inv(c, b, cc);
        lightecdh_bit_mul(c, c, a, cc);
        lightecdh_bit_mul(d, c, c, cc);
        lightecdh_bit_add(d, d, c, cc);
        lightecdh_bit_add(d, d, b, cc);
        if ((*cc).ecdh_a == 1) {
          lightecdh_bit_inc(d);
        }
        lightecdh_bit_add(x1, x1, d, cc);
        lightecdh_bit_mul(a, x1, c, cc);
        lightecdh_bit_add(a, a, d, cc);
        lightecdh_bit_add(y1, y1, a, cc);
        lightecdh_bit_copy(x1, d, cc);
      }
    }
  }
}

void lightecdh_point_zero(bit x, bit y, cur* cc) {
  lightecdh_bit_zero(x, cc);
  lightecdh_bit_zero(y, cc);
}

int lightecdh_point_is_zero(const bit x, const bit y, cur* cc) {
  return (lightecdh_bit_is_zero(x, cc) && lightecdh_bit_is_zero(y, cc));
}

// check if y^2 + x*y = x^3 + a*x^2 + coeff_b holds
int lightecdh_point_on_curve(const bit x, const bit y, cur* cc) {
  //extern int ecdh_a;
  //extern bit ecdh_b;
  bit a, b;

  if (lightecdh_point_is_zero(x, y, cc)) {
    return 1;
  } else {
    lightecdh_bit_mul(a, x, x, cc);
    if ((*cc).ecdh_a == 0) {
      lightecdh_bit_mul(a, a, x, cc);
    } else {
      lightecdh_bit_mul(b, a, x, cc);
      lightecdh_bit_add(a, a, b, cc);
    }

    lightecdh_bit_add(a, a, (*cc).ecdh_b, cc);
    lightecdh_bit_mul(b, y, y, cc);
    lightecdh_bit_add(a, a, b, cc);
    lightecdh_bit_mul(b, x, y, cc);

    return lightecdh_bit_equal(a, b, cc);
  }
}

// Borrowed / Stolen from https://github.com/jestan/easy-ecc

// Returns 1 if p_point is the point at infinity, 0 otherwise.
int lee_p_iszero(lee_p *p) {
  return (lee_iszero(p->x) && lee_iszero(p->y));
}

// Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
// From http://eprint.iacr.org/2011/338.pdf

// Double in place
void lee_p_double(u64 *X1, u64 *Y1, u64 *Z1) {
  // t1 = X, t2 = Y, t3 = Z
  u64 t4[LEE_D], t5[LEE_D];

  if (lee_iszero(Z1)) {return;}
  lee_m_sqr(t4, Y1);              // t4 = y1^2
  lee_m_mul(t5, X1, t4);          // t5 = x1*y1^2 = A
  lee_m_sqr(t4, t4);              // t4 = y1^4
  lee_m_mul(Y1, Y1, Z1);          // t2 = y1*z1 = z3
  lee_m_sqr(Z1, Z1);              // t3 = z1^2

  lee_m_add(X1, X1, Z1, curve_p); // t1 = x1 + z1^2
  lee_m_add(Z1, Z1, Z1, curve_p); // t3 = 2*z1^2
  lee_m_sub(Z1, X1, Z1, curve_p); // t3 = x1 - z1^2
  lee_m_mul(X1, X1, Z1);          // t1 = x1^2 - z1^4

  lee_m_add(Z1, X1, X1, curve_p); // t3 = 2*(x1^2 - z1^4)
  lee_m_add(X1, X1, Z1, curve_p); // t1 = 3*(x1^2 - z1^4)
  if (lee_isset(X1, 0)) {
    u64 car = lee_add(X1, X1, curve_p);
    lee_rshift1(X1);
    X1[LEE_D-1] |= car << 63;
  } else {lee_rshift1(X1);}
  // t1 = 3/2*(x1^2 - z1^4) = B

  lee_m_sqr(Z1, X1);              // t3 = B^2
  lee_m_sub(Z1, Z1, t5, curve_p); // t3 = B^2 - A
  lee_m_sub(Z1, Z1, t5, curve_p); // t3 = B^2 - 2A = x3
  lee_m_sub(t5, t5, Z1, curve_p); // t5 = A - x3
  lee_m_mul(X1, X1, t5);          // t1 = B * (A - x3)
  lee_m_sub(t4, X1, t4, curve_p); // t4 = B * (A - x3) - y1^4 = y3

  lee_set(X1, Z1);
  lee_set(Z1, Y1);
  lee_set(Y1, t4);
}

// Modify (x1, y1) => (x1 * z^2, y1 * z^3)
void lee_p_appz(u64 *X1, u64 *Y1, u64 *Z) {
  u64 t1[LEE_D];

  lee_m_sqr(t1, Z);      // z^2
  lee_m_mul(X1, X1, t1); // x1 * z^2
  lee_m_mul(t1, t1, Z);  // z^3
  lee_m_mul(Y1, Y1, t1); // y1 * z^3
}

// P = (x1, y1) => 2P, (x2, y2) => P'
void lee_p_inidoub(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2, u64 *p) {
  u64 z[LEE_D];

  lee_set(X2, X1);
  lee_set(Y2, Y1);
  lee_clear(z);
  z[0] = 1;

  if (p) {lee_set(z, p);}

  lee_p_appz(X1, Y1, z); 
  lee_p_double(X1, Y1, z);
  lee_p_appz(X2, Y2, z);
}

// Input P = (x1, y1, Z), Q = (x2, y2, Z)
// Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
// or P => P', Q => P + Q
void lee_p_add(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  u64 t5[LEE_D];

  lee_m_sub(t5, X2, X1, curve_p); // t5 = x2 - x1
  lee_m_sqr(t5, t5);              // t5 = (x2 - x1)^2 = A
  lee_m_mul(X1, X1, t5);          // t1 = x1*A = B
  lee_m_mul(X2, X2, t5);          // t3 = x2*A = C
  lee_m_sub(Y2, Y2, Y1, curve_p); // t4 = y2 - y1
  lee_m_sqr(t5, Y2);              // t5 = (y2 - y1)^2 = D

  lee_m_sub(t5, t5, X1, curve_p); // t5 = D - B
  lee_m_sub(t5, t5, X2, curve_p); // t5 = D - B - C = x3
  lee_m_sub(X2, X2, X1, curve_p); // t3 = C - B
  lee_m_mul(Y1, Y1, X2);          // t2 = y1*(C - B)
  lee_m_sub(X2, X1, t5, curve_p); // t3 = B - x3
  lee_m_mul(Y2, Y2, X2);          // t4 = (y2 - y1)*(B - x3)
  lee_m_sub(Y2, Y2, Y1, curve_p); // t4 = y3

  lee_set(X2, t5);
}

// Input P = (x1, y1, Z), Q = (x2, y2, Z)
// Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
// or P => P - Q, Q => P + Q
void lee_p_addc(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2) {
  // t1 = X1, t2 = Y1, t3 = X2, t4 = Y2
  u64 t5[LEE_D], t6[LEE_D], t7[LEE_D];

  lee_m_sub(t5, X2, X1, curve_p); // t5 = x2 - x1
  lee_m_sqr(t5, t5);              // t5 = (x2 - x1)^2 = A
  lee_m_mul(X1, X1, t5);          // t1 = x1*A = B
  lee_m_mul(X2, X2, t5);          // t3 = x2*A = C
  lee_m_add(t5, Y2, Y1, curve_p); // t4 = y2 + y1
  lee_m_sub(Y2, Y2, Y1, curve_p); // t4 = y2 - y1

  lee_m_sub(t6, X2, X1, curve_p); // t6 = C - B
  lee_m_mul(Y1, Y1, t6);          // t2 = y1 * (C - B)
  lee_m_add(t6, X1, X2, curve_p); // t6 = B + C
  lee_m_sqr(X2, Y2);              // t3 = (y2 - y1)^2
  lee_m_sub(X2, X2, t6, curve_p); // t3 = x3

  lee_m_sub(t7, X1, X2, curve_p); // t7 = B - x3
  lee_m_mul(Y2, Y2, t7);          // t4 = (y2 - y1)*(B - x3)
  lee_m_sub(Y2, Y2, Y1, curve_p); // t4 = y3

  lee_m_sqr(t7, t5);              // t7 = (y2 + y1)^2 = F
  lee_m_sub(t7, t7, t6, curve_p); // t7 = x3'
  lee_m_sub(t6, t7, X1, curve_p); // t6 = x3' - B
  lee_m_mul(t6, t6, t5);          // t6 = (y2 + y1)*(x3' - B)
  lee_m_sub(Y1, t6, Y1, curve_p); // t2 = y3'

  lee_set(X1, t7);
}

void lee_p_mul(lee_p *r, lee_p *p, u64 *q, u64 *s) {
  // R0 and R1
  u64 Rx[2][LEE_D], Ry[2][LEE_D], z[LEE_D];
  int nb;

  lee_set(Rx[1], p->x);
  lee_set(Ry[1], p->y);
  lee_p_inidoub(Rx[1], Ry[1], Rx[0], Ry[0], s);
  for (int i = lee_bits(q) - 2; i > 0; --i) {
    nb = !lee_isset(q, i);
    lee_p_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);
    lee_p_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  }

  nb = !lee_isset(q, 0);
  lee_p_addc(Rx[1-nb], Ry[1-nb], Rx[nb], Ry[nb]);

  // Find final 1/Z value.
  lee_m_sub(z, Rx[1], Rx[0], curve_p); // X1 - X0
  lee_m_mul(z, z, Ry[1-nb]);           // Yb * (X1 - X0)
  lee_m_mul(z, z, p->x);         // xP * Yb * (X1 - X0)
  lee_m_inv(z, z, curve_p);            // 1 / (xP * Yb * (X1 - X0))
  lee_m_mul(z, z, p->y);         // yP / (xP * Yb * (X1 - X0))
  lee_m_mul(z, z, Rx[1-nb]);           // Xb * yP / (xP * Yb * (X1 - X0))
  // End 1/Z calculation

  lee_p_add(Rx[nb], Ry[nb], Rx[1-nb], Ry[1-nb]);
  lee_p_appz(Rx[0], Ry[0], z);
  lee_set(r->x, Rx[0]);
  lee_set(r->y, Ry[0]);
}

void lee_p_decom(lee_p *p, const u64 q[LEE_B+1]) {
  u64 _3[LEE_D] = {3};                                 // -a = 3
  lee_set(p->x, q+1);

  lee_m_sqr(p->y, p->x);                   // y = x^2
  lee_m_sub(p->y, p->y, _3, curve_p);      // y = x^2 - 3
  lee_m_mul(p->y, p->y, p->x);       // y = x^3 - 3x
  lee_m_add(p->y, p->y, curve_b, curve_p); // y = x^3 - 3x + b
  lee_m_sqrt(p->y);

  if ((p->y[0] & 0x01) != (q[0] & 0x01)) {
    lee_sub(p->y, curve_p, p->y);
  }
}

// Computes p_result = (p_left + p_right) % p_mod.
// Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod.
void lee_m_add(u64 *r, u64 *p, u64 *q, u64 *m) {
  u64 car = lee_add(r, p, q);
  if (car || lee_cmp(r, m) >= 0) {lee_sub(r, r, m);}
  // p_result > p_mod (p_result = p_mod + remainder),
  // so subtract p_mod to get remainder.
}

// Computes p_result = (p_left - p_right) % p_mod.
// Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod.
void lee_m_sub(u64 *r, u64 *p, u64 *q, u64 *m) {
  if (lee_sub(r, p, q)) {lee_add(r, r, m);}
  // In this case, p_result == -diff == (max int) - diff.
  // Since -x % d == d - x, we can get the correct result from
  // p_result + p_mod (with overflow).
}

void lee_o_mul(u64 *r, u64 *p) {
  u64 tmp[LEE_D], car, diff;

  // Multiply by (2^128 + 2^96 - 2^32 + 1).
  lee_set(r, p); // 1
  car = lee_lshift(tmp, p, 32);
  r[1 + LEE_D] = car + lee_add(r + 1, r + 1, tmp); // 2^96 + 1
  r[2 + LEE_D] = lee_add(r + 2, r + 2, p);         // 2^128 + 2^96 + 1
  car += lee_sub(r, r, tmp);                       // 2^128 + 2^96 - 2^32 + 1
  diff = r[LEE_D] - car;
  if (diff > r[LEE_D]) {                           // borrow if necessary.
    for (uint8_t i = 1 + LEE_D; ; ++i) {
      --r[i];
      if(r[i] != (u64) - 1) {
        break;
      }
    }
  }
  r[LEE_D] = diff;
}

// Computes p_result = p_product % curve_p
// see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
// section "Curve-Specific Optimizations"
void lee_m_mod(u64 *r, u64 *p) {
  u64 tmp[2 * LEE_D];

  while (!lee_iszero(p + LEE_D)) {  // While c1 != 0
    u64 car = 0;

    lee_clear(tmp);
    lee_clear(tmp + LEE_D);
    lee_o_mul(tmp, p + LEE_D);      // tmp = w * c1
    lee_clear(p + LEE_D);           // p = c0

    // (c1, c0) = c0 + w * c1
    for (uint8_t i = 0; i < LEE_D + 3; ++i) {
      u64 sum = p[i] + tmp[i] + car;
      if (sum != p[i]) {
        car = (sum < p[i]);
      }
      p[i] = sum;
    }
  }

  while (lee_cmp(p, curve_p) > 0) {lee_sub(p, p, curve_p);}
  lee_set(r, p);
}

// Computes p_result = (p_left * p_right) % curve_p.
void lee_m_mul(u64 *r, u64 *p, u64 *q) {
  u64 product[2 * LEE_D];
  lee_mul(product, p, q);
  lee_m_mod(r, product);
}

// Computes p_result = p_left^2 % curve_p.
void lee_m_sqr(u64 *r, u64 *p) {
  u64 product[2 * LEE_D];
  lee_sqr(product, p);
  lee_m_mod(r, product);
}

// Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
// See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
// https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
void lee_m_inv(u64 *r, u64 *p, u64 *m) {
  u64 a[LEE_D], b[LEE_D], u[LEE_D], v[LEE_D], car;
  int cmpResult;

  if(lee_iszero(p)) {
    lee_clear(r);
    return;
  }

  lee_set(a, p);
  lee_set(b, m);
  lee_clear(u);
  u[0] = 1;
  lee_clear(v);

  while ((cmpResult = lee_cmp(a, b)) != 0) {
    car = 0;
    if (EVEN(a)) {
      lee_rshift1(a);
      if (!EVEN(u)) {car = lee_add(u, u, m);}
      lee_rshift1(u);
      if (car) {u[LEE_D-1] |= 0x8000000000000000;}
    } else if (EVEN(b)) {
      lee_rshift1(b);
      if (!EVEN(v)) {car = lee_add(v, v, m);}
      lee_rshift1(v);
      if (car) {v[LEE_D-1] |= 0x8000000000000000;}
    } else if (cmpResult > 0) {
      lee_sub(a, a, b);
      lee_rshift1(a);
      if (lee_cmp(u, v) < 0) {lee_add(u, u, m);}
      lee_sub(u, u, v);
      if (!EVEN(u)) {car = lee_add(u, u, m);}
      lee_rshift1(u);
      if (car) {u[LEE_D-1] |= 0x8000000000000000;}
    } else {
      lee_sub(b, b, a);
      lee_rshift1(b);
      if (lee_cmp(v, u) < 0) {lee_add(v, v, m);}
      lee_sub(v, v, u);
      if (!EVEN(v)) {car = lee_add(v, v, m);}
      lee_rshift1(v);
      if (car) {v[LEE_D-1] |= 0x8000000000000000;}
    }
  }

  lee_set(r, u);
}

// Compute a = sqrt(a) (mod curve_p).
void lee_m_sqrt(u64 a[LEE_D]) {
  u64 p1[LEE_D] = {1}, result[LEE_D] = {1};

  // Since curve_p == 3 (mod 4) for all supported curves, we can
  // compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p).
  lee_add(p1, curve_p, p1); // p1 = curve_p + 1
  for (uint i = lee_bits(p1) - 1; i > 1; --i) {
    lee_m_sqr(result, result);
    if (lee_isset(p1, i)) {lee_m_mul(result, result, a);}
  }
  lee_set(a, result);
}

// Computes p_result = (p_left * p_right) % p_mod.
void lee_m_mmul(u64 *r, u64 *p, u64 *q, u64 *m) {
  u64 product[2 * LEE_D], modMultiple[2 * LEE_D];
  uint digitShift, bitShift, productBits, modBits = lee_bits(m);

  lee_mul(product, p, q);
  productBits = lee_bits(product + LEE_D);
  if (productBits) {productBits += LEE_D * 64;}
  else {productBits = lee_bits(product);}

  if (productBits < modBits) { // product < p_mod.
    lee_set(r, product);
    return;
  }

  // Shift p_mod by (leftBits - modBits). This multiplies p_mod by the largest
  // power of two possible while still resulting in a number less than p_left.
  lee_clear(modMultiple);
  lee_clear(modMultiple + LEE_D);
  digitShift = (productBits - modBits) / 64;
  bitShift = (productBits - modBits) % 64;
  if (bitShift) {
    modMultiple[digitShift + LEE_D] = lee_lshift(modMultiple + digitShift, m, bitShift);
  } else {
    lee_set(modMultiple + digitShift, m);
  }

  // Subtract all multiples of p_mod to get the remainder.
  lee_clear(r);
  r[0] = 1; // Use p_result as a temp var to store 1 (for subtraction)
  while (productBits > LEE_D * 64 || lee_cmp(modMultiple, m) >= 0) {
    int cmp = lee_cmp(modMultiple + LEE_D, product + LEE_D);
    if (cmp < 0 || (cmp == 0 && lee_cmp(modMultiple, product) <= 0)) {
      if (lee_sub(product, product, modMultiple)) { // borrow
        lee_sub(product + LEE_D, product + LEE_D, r);
      }
      lee_sub(product + LEE_D, product + LEE_D, modMultiple + LEE_D);
    }
    u64 car = (modMultiple[LEE_D] & 0x01) << 63;
    lee_rshift1(modMultiple + LEE_D);
    lee_rshift1(modMultiple);
    modMultiple[LEE_D-1] |= car;
    --productBits;
  }
  lee_set(r, product);
}

