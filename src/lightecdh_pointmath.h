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

int lee_p_iszero(lee_p *p);
void lee_p_appz(u64 *X1, u64 *Y1, u64 *Z);
void lee_p_double(u64 *X1, u64 *Y1, u64 *Z1);
void lee_p_decom(lee_p *p, const u64 q[LEE_B + 1]);
void lee_p_add(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2);
void lee_p_addc(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2);
void lee_p_mul(lee_p *r, lee_p *p, u64 *q, u64 *s);
void lee_p_inidoub(u64 *X1, u64 *Y1, u64 *X2, u64 *Y2, u64 *p);

void lee_m_add(u64 *r, u64 *p, u64 *q, u64 *m);
void lee_m_sub(u64 *r, u64 *p, u64 *q, u64 *m);
void lee_o_mul(u64 *r, u64 *p);
void lee_m_mod(u64 *r, u64 *p);
void lee_m_mul(u64 *r, u64 *p, u64 *q);
void lee_m_sqr(u64 *r, u64 *p);
void lee_m_inv(u64 *r, u64 *p, u64 *m);
void lee_m_sqrt(u64 a[LEE_D]);
void lee_m_mmul(u64 *r, u64 *p, u64 *q, u64 *m);
#endif
