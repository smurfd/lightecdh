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

cur* lightecdh_curves_get(int c);
void lightecdh_curves_end(cur* cc);

int lee_make_keys(u64 publ[LEE_B+1], u64 priv[LEE_B]);
int lee_shar_secr(const u64 publ[LEE_B+1], const u64 priv[LEE_B], u64 secr[LEE_B]);
int lee_sign(const u64 priv[LEE_B], const u64 hash[LEE_B], u64 sign[LEE_B*2]);
int lee_vrfy(const u64 publ[LEE_B+1], const u64 hash[LEE_B], const u64 sign[LEE_B*2]);
#endif
