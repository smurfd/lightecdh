#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"
#include "lightecdh_pointmath.h"

// Generate keypair
void lightecdh_keygen(u08* pubkey, u08* privkey) {
  extern bit ecdh_x;
  extern bit ecdh_y;
  extern bit ecdh_n;

  lightecdh_point_copy((u32*)(pubkey), (u32*)(pubkey+BITVEC_NBYTES), ecdh_x, ecdh_y);

  int nb = lightecdh_bit_degree(ecdh_n);
  for (int i = (nb - 1); i < (BITVEC_NWORDS * 32); ++i) {
    lightecdh_bit_clear((u32*)privkey, i);
  }
  lightecdh_point_mul((u32*)(pubkey), (u32*)(pubkey+BITVEC_NBYTES), (u32*)privkey);
}

int lightecdh_shared_secret(const u08* privkey, const u08* pubkey, u08* res) {
  // Do some basic validation of other party's public key
  if (!lightecdh_point_is_zero ((u32*)pubkey, (u32*)(pubkey + BITVEC_NBYTES)) && 
    lightecdh_point_on_curve((u32*)pubkey, (u32*)(pubkey + BITVEC_NBYTES))) {
    // Copy other side's public key to output
    for (unsigned int i = 0; i < (BITVEC_NBYTES * 2); ++i) {
      res[i] = pubkey[i];
    }

    // Multiply other side's public key with own private key
    lightecdh_point_mul((u32*)res,(u32*)(res + BITVEC_NBYTES), (const u32*)privkey);
    return 1;
  } else {
    return 0;
  }
}

void lightecdh_decompress_sig(u32* x, u32* y, u32* z) {
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    x[i] = z[i];
    y[i] = z[i+ECC_PRV_KEY_SIZE];
  }
}

void lightecdh_compress_sig(u32* x, u32* y, u32* z) {
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    x[i] = y[i];
    x[i+ECC_PRV_KEY_SIZE] = z[i];
  }
}

void lightecdh_sign(const u08* privkey, u08* hash, u08* rnd, u08* sig) {
  bit r, s, z, rx, ry, kn, rp, h, hn, k;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;
  int nb;

  printf("lengths : %lu %d %d %d: %d\n", BITVEC_NBYTES, BITVEC_NWORDS, BITVEC_NBITS, ECC_PRV_KEY_SIZE, lightecdh_bit_degree(ecdh_n));

  lightecdh_bit_zero(r);
  lightecdh_bit_zero(s);
  lightecdh_bit_copy(z, (u32*)hash);

  nb = lightecdh_bit_degree(ecdh_n);
  for (u32 i = (nb - 1); i < BITVEC_NBYTES; ++i) {
    lightecdh_bit_clear(z, i);
  }

  // Calculate the random point R = k * G and take its x-coordinate: r = R.x
  lightecdh_bit_copy(k, (u32*)rnd);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  lightecdh_bit_mul(r, k, rx);
  lightecdh_bit_mul(s, k, ry);
  lightecdh_bit_mod_n(r, r);

  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(modn)
  lightecdh_bit_neg(kn, k);
  lightecdh_bit_mul(rp, r, (u32*)privkey);
  lightecdh_bit_add(h, (u32*)hash, rp);  // h needs mod n before?
  lightecdh_bit_mod_n(hn, h);
  lightecdh_bit_mul(s, hn, kn);
  lightecdh_compress_sig((u32*)sig, r, s);

//The modular inverse  is an integer, such that  k ∗k−1≡1(modn)
//​Return the signature {r, s}.
  for (int i=0; i<BITVEC_NWORDS; ++i) {
    printf(" +++ %.8x %.8x\n", (u32)r[i], (u32)s[i]);
  }

}

void lightecdh_verify(const u08* publkey, u08* hash, u08* rnd, u08* sig) {
  bit z, s1, hs, rs, pubs, rx, ry, px, py;
  extern bit ecdh_x;
  extern bit ecdh_y;
  u08 r[ECC_PRV_KEY_SIZE];
  u08 s[ECC_PRV_KEY_SIZE];
  lightecdh_bit_copy(z, (u32*)rnd); // just to avoid warnings for not used variables

// Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  //lightecdh_bit_copy(z, (u32*)hash);

// Calculate the modular inverse of the signature proof: s1 = s^{-1} modn
  lightecdh_decompress_sig((u32*)r, (u32*)s, (u32*)sig);
  lightecdh_bit_neg(s1, (u32*)s);
  lightecdh_bit_mod_n(s1, s1);

// Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
  lightecdh_bit_mul(hs, s1, (u32*)hash);
  lightecdh_bit_mul(rs, s1, (u32*)r);
  lightecdh_bit_mul(pubs, rs, (u32*)publkey);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);

  lightecdh_bit_mul(rx, rx, rs);
  lightecdh_bit_mul(ry, ry, rs);
  lightecdh_bit_mul(px, rx, pubs);
  lightecdh_bit_mul(py, ry, pubs);

// Take from R' its x-coordinate: r' = R'.x

// Calculate the signature validation result by comparing whether r' == r
  for (int i=0; i<BITVEC_NWORDS; ++i) {
    printf(" --- %.8x %.8x\n", (u32)px[i], (u32)rx[i]);
  }
}
