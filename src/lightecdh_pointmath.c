#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"
#include "lightecdh_pointmath.h"

// Copy point
void lightecdh_point_copy(bit x1, bit y1, const bit x2, const bit y2, cur* cc) {
  lightecdh_bit_copy(x1, x2);
  lightecdh_bit_copy(y1, y2);
}

void lightecdh_point_mul(bit x, bit y, const bit exp, cur* cc) {
  bit tmpx, tmpy, dummyx, dummyy;
  int nb = lightecdh_bit_degree(exp);

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
  if (lightecdh_bit_is_zero(x)) {
    lightecdh_bit_zero(y);
  } else {
    bit l;
    //extern int ecdh_a;
    lightecdh_bit_inv(l, x);
    lightecdh_bit_mul(l, l, y);
    lightecdh_bit_add(l, l, x);
    lightecdh_bit_mul(y, x, x);
    lightecdh_bit_mul(x, l, l);
    if ((*cc).ecdh_a == 1) {
      lightecdh_bit_inc(l);
    }
    lightecdh_bit_add(x, x, l);
    lightecdh_bit_mul(l, l, x);
    lightecdh_bit_add(y, y, l);
  }
}

// add two points together (x1, y1) := (x1, y1) + (x2, y2)
void lightecdh_point_add(bit x1, bit y1, const bit x2, const bit y2, cur* cc) {
  //extern int ecdh_a;
  if (!lightecdh_point_is_zero(x2, y2, cc)) {
    if (lightecdh_point_is_zero(x1, y1, cc)) {
      lightecdh_point_copy(x1, y1, x2, y2, cc);
    } else {
      if (lightecdh_bit_equal(x1, x2)) {
        if (lightecdh_bit_equal(y1, y2)) {
          lightecdh_point_double(x1, y1, cc);
        } else {
          lightecdh_point_zero(x1, y1, cc);
        }
      } else {
        // Arithmetic with temporary variables
        bit a, b, c, d;

        lightecdh_bit_add(a, y1, y2);
        lightecdh_bit_add(b, x1, x2);
        lightecdh_bit_inv(c, b);
        lightecdh_bit_mul(c, c, a);
        lightecdh_bit_mul(d, c, c);
        lightecdh_bit_add(d, d, c);
        lightecdh_bit_add(d, d, b);
        if ((*cc).ecdh_a == 1) {
          lightecdh_bit_inc(d);
        }
        lightecdh_bit_add(x1, x1, d);
        lightecdh_bit_mul(a, x1, c);
        lightecdh_bit_add(a, a, d);
        lightecdh_bit_add(y1, y1, a);
        lightecdh_bit_copy(x1, d);
      }
    }
  }
}

void lightecdh_point_zero(bit x, bit y, cur* cc) {
  lightecdh_bit_zero(x);
  lightecdh_bit_zero(y);
}

int lightecdh_point_is_zero(const bit x, const bit y, cur* cc) {
  return (lightecdh_bit_is_zero(x) && lightecdh_bit_is_zero(y));
}

// check if y^2 + x*y = x^3 + a*x^2 + coeff_b holds
int lightecdh_point_on_curve(const bit x, const bit y, cur* cc) {
  //extern int ecdh_a;
  //extern bit ecdh_b;
  bit a, b;

  if (lightecdh_point_is_zero(x, y, cc)) {
    return 1;
  } else {
    lightecdh_bit_mul(a, x, x);
    if ((*cc).ecdh_a == 0) {
      lightecdh_bit_mul(a, a, x);
    } else {
      lightecdh_bit_mul(b, a, x);
      lightecdh_bit_add(a, a, b);
    }

    lightecdh_bit_add(a, a, (*cc).ecdh_b);
    lightecdh_bit_mul(b, y, y);
    lightecdh_bit_add(a, a, b);
    lightecdh_bit_mul(b, x, y);

    return lightecdh_bit_equal(a, b);
  }
}

