#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"

#ifndef LIGHTECDH_POINTMATH_H 
#define LIGHTECDH_POINTMATH_H 1

void lightecdh_point_copy(bit x1, bit y1, const bit x2, const bit y2);
void lightecdh_point_mul(bit x, bit y, const bit exp);
void lightecdh_point_double(bit x, bit y);
void lightecdh_point_add(bit x1, bit y1, const bit x2, const bit y2);
void lightecdh_point_zero(bit x, bit y);
int lightecdh_point_is_zero(const bit x, const bit y);
int lightecdh_point_on_curve(const bit x, const bit y);
#endif
