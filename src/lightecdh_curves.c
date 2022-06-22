#include "lightecdh.h"
#include "lightecdh_curves.h"
#include <string.h>

// NIST K-163
bit ecdh_p = { 0x000000c9UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000008UL };
bit ecdh_b = { 0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL };
bit ecdh_x = { 0x5c94eee8UL, 0xde4e6d5eUL, 0xaa07d793UL, 0x7bbc11acUL, 0xfe13c053UL, 0x00000002UL };
bit ecdh_y = { 0xccdaa3d9UL, 0x0536d538UL, 0x321f2e80UL, 0x5d38ff58UL, 0x89070fb0UL, 0x00000002UL };
bit ecdh_n = { 0x99f8a5efUL, 0xa2e0cc0dUL, 0x00020108UL, 0x00000000UL, 0x00000000UL, 0x00000004UL };
int ecdh_a = 1;
int ecdh_h = 2;

cur* lightecdh_curves_init(cur* cc, bit ecdh_p, bit ecdh_b, bit ecdh_x, bit ecdh_y, bit ecdh_n, int ecdh_a, int ecdh_h, int ecdh_cd, int ecdh_pk) {
  memcpy((*cc).ecdh_p, ecdh_p, sizeof(bit));
  memcpy((*cc).ecdh_b, ecdh_b, sizeof(bit));
  memcpy((*cc).ecdh_x, ecdh_x, sizeof(bit));
  memcpy((*cc).ecdh_y, ecdh_y, sizeof(bit));
  memcpy((*cc).ecdh_n, ecdh_n, sizeof(bit));
  (*cc).ecdh_a = ecdh_a;
  (*cc).ecdh_h = ecdh_h;
  (*cc).DEGR = ecdh_cd;
  (*cc).PRIV = ecdh_pk;
  return cc;
}

void lightecdh_curves_end(cur* cc) {
  free(cc);
}

cur* lightecdh_curves_get(int c) {
  cur* cc = malloc (sizeof(struct curves));

  if (c == NIST_K163) {
    bit ecdh_p = { 0x000000c9UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000008UL };
    bit ecdh_b = { 0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL };
    bit ecdh_x = { 0x5c94eee8UL, 0xde4e6d5eUL, 0xaa07d793UL, 0x7bbc11acUL, 0xfe13c053UL, 0x00000002UL };
    bit ecdh_y = { 0xccdaa3d9UL, 0x0536d538UL, 0x321f2e80UL, 0x5d38ff58UL, 0x89070fb0UL, 0x00000002UL };
    bit ecdh_n = { 0x99f8a5efUL, 0xa2e0cc0dUL, 0x00020108UL, 0x00000000UL, 0x00000000UL, 0x00000004UL };
    int ecdh_a = 1;
    int ecdh_h = 2;
    int ecdh_DEGR = 163;
    int ecdh_PRIV = 24;
    cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
  } else if (c == NIST_K571) {
    bit ecdh_p = { 0x00000425, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
    bit ecdh_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
    bit ecdh_x = { 0xa01c8972, 0xe2945283, 0x4dca88c7, 0x988b4717, 0x494776fb, 0xbbd1ba39, 0xb4ceb08c, 0x47da304d, 0x93b205e6, 0x43709584, 0x01841ca4, 0x60248048, 0x0012d5d4, 0xac9ca297, 0xf8103fe4, 0x82189631, 0x59923fbc, 0x026eb7a8 };
    bit ecdh_y = { 0x3ef1c7a3, 0x01cd4c14, 0x591984f6, 0x320430c8, 0x7ba7af1b, 0xb620b01a, 0xf772aedc, 0x4fbebbb9, 0xac44aea7, 0x9d4979c0, 0x006d8a2c, 0xffc61efc, 0x9f307a54, 0x4dd58cec, 0x3bca9531, 0x4f4aeade, 0x7f4fbf37, 0x0349dc80 };
    bit ecdh_n = { 0x637c1001, 0x5cfe778f, 0x1e91deb4, 0xe5d63938, 0xb630d84b, 0x917f4138, 0xb391a8db, 0xf19a63e4, 0x131850e1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000 };
    int ecdh_a = 0;
    int ecdh_h = 4;
    int ecdh_DEGR = 571;
    int ecdh_PRIV = 72;
    cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
  } else {
    // Set NIST_K163 as default if no value is set
    bit ecdh_p = { 0x000000c9UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000008UL };
    bit ecdh_b = { 0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL };
    bit ecdh_x = { 0x5c94eee8UL, 0xde4e6d5eUL, 0xaa07d793UL, 0x7bbc11acUL, 0xfe13c053UL, 0x00000002UL };
    bit ecdh_y = { 0xccdaa3d9UL, 0x0536d538UL, 0x321f2e80UL, 0x5d38ff58UL, 0x89070fb0UL, 0x00000002UL };
    bit ecdh_n = { 0x99f8a5efUL, 0xa2e0cc0dUL, 0x00020108UL, 0x00000000UL, 0x00000000UL, 0x00000004UL };
    int ecdh_a = 1;
    int ecdh_h = 2;
    int ecdh_DEGR = 163;
    int ecdh_PRIV = 24;
    cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
  }

  (*cc).CURV = c;
  (*cc).PUBL = (*cc).PRIV * 2;
  (*cc).MARG = 3;
  (*cc).NBIT = ((*cc).DEGR + (*cc).MARG);
  (*cc).NWOR = (((*cc).NBIT + 31) / 32);
  (*cc).NBYT = (sizeof(u32) + (*cc).NWOR);
  return cc;
}

/*
  int CURV; // Curve type
  int PRIV; // Private key sisze
  int PUBL; // Publik key size
  int NBYT; // Nbytes
  int NBIT; // Nbits
  int NWOR; // Nwords
  int DEGR; // Degree
  int MARG; // Margin
} cur;
*/
/*
#define CURVE_DEGREE       163
#define ECC_PRV_KEY_SIZE    24

#define ECC_PUB_KEY_SIZE   (2 * ECC_PRV_KEY_SIZE)

#define BITVEC_MARGIN     3
#define BITVEC_NBITS      (CURVE_DEGREE + BITVEC_MARGIN)
#define BITVEC_NWORDS     ((BITVEC_NBITS + 31) / 32)
#define BITVEC_NBYTES     (sizeof(uint32_t) * BITVEC_NWORDS)
*/
