#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"

#ifndef LIGHTECDH_POINTMATH_H 
#define LIGHTECDH_POINTMATH_H 1

typedef struct curves cur;

void lightecdh_point_copy(bit x1, bit y1, const bit x2, const bit y2, cur* cc);
void lightecdh_point_mul(bit x, bit y, const bit exp, cur* cc);
void lightecdh_point_double(bit x, bit y, cur* cc);
void lightecdh_point_add(bit x1, bit y1, const bit x2, const bit y2, cur* cc);
void lightecdh_point_zero(bit x, bit y, cur* cc);
int lightecdh_point_is_zero(const bit x, const bit y, cur* cc);
int lightecdh_point_on_curve(const bit x, const bit y, cur* cc);
#endif
