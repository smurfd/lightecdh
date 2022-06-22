#ifndef LIGHTECDH_CURVES_H 
#define LIGHTECDH_CURVES_H 1
#include "lightecdh.h"

#define NIST_B163  1
#define NIST_K163  2
#define NIST_B233  3
#define NIST_K233  4
#define NIST_B283  5
#define NIST_K283  6
#define NIST_B409  7
#define NIST_K409  8
#define NIST_B571  9
#define NIST_K571 10

typedef struct curves {
  bit ecdh_p;
  bit ecdh_b;
  bit ecdh_x;
  bit ecdh_y;
  bit ecdh_n;
  int ecdh_a;
  int ecdh_h;

  int CURV; // Curve type
  int PRIV; // Private key sisze
  int PUBL; // Publik key size
  int NBYT; // Nbytes
  int NBIT; // Nbits
  int NWOR; // Nwords
  int DEGR; // Degree
  int MARG; // Margin
} cur;
/*
#define CURVE_DEGREE       163
#define ECC_PRV_KEY_SIZE    24

#define ECC_PUB_KEY_SIZE   (2 * ECC_PRV_KEY_SIZE)

#define BITVEC_MARGIN     3
#define BITVEC_NBITS      (CURVE_DEGREE + BITVEC_MARGIN)
#define BITVEC_NWORDS     ((BITVEC_NBITS + 31) / 32)
#define BITVEC_NBYTES     (sizeof(uint32_t) * BITVEC_NWORDS)
*/

cur* lightecdh_curves_get(int c);
void lightecdh_curves_end(cur* cc);
#endif
