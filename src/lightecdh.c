#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"
#include "lightecdh_pointmath.h"

// Generate keypair
void lightecdh_keygen(u32* pubkey, u32* privkey) {
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

int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res) {
  // Do some basic validation of other party's public key
  if (!lightecdh_point_is_zero ((u32*)pubkey, (u32*)(pubkey + BITVEC_NBYTES)) && 
    lightecdh_point_on_curve((u32*)pubkey, (u32*)(pubkey + BITVEC_NBYTES))) {
    // Copy other side's public key to output
    for (unsigned int i = 0; i < (ECC_PUB_KEY_SIZE); ++i) {
      res[i] = pubkey[i];
    }

    // Multiply other side's public key with own private key
    lightecdh_point_mul((u32*)res,(u32*)(res + BITVEC_NBYTES), (const u32*)privkey);
    return 1;
  } else {
    return 0;
  }
}

void lightecdh_decompress_sig(u32* x, u32* y, const u32* z) {
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    x[i] = z[i];
    y[i] = z[i + ECC_PRV_KEY_SIZE];
  }
}

void lightecdh_compress_sig(u32* x, const u32* y, const u32* z) {
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    x[i] = y[i];
    x[i + ECC_PRV_KEY_SIZE] = z[i];
  }
}

void lightecdh_sign(const u32* privkey, u32* hash, u32* rnd, u32* sign) {
  bit z, kn, rp, h, hn, k;
  sig r, s, rm, rx, ry;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;
  int nb;

  printf("lengths : %lu %d %d %d: %d\n", BITVEC_NBYTES, BITVEC_NWORDS, BITVEC_NBITS, ECC_PRV_KEY_SIZE, lightecdh_bit_degree(ecdh_n));

  //lightecdh_bit_zero(r);
  //lightecdh_bit_zero(s);
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
    rm[i] = 0;
  }
  lightecdh_bit_copy(z, (u32*)hash);
  print_bit(z, "z", ECC_PRV_KEY_SIZE);

  nb = lightecdh_bit_degree(ecdh_n);
  for (u32 i = (nb - 1); i < BITVEC_NBYTES; ++i) {
    lightecdh_bit_clear(z, i);
  }
  print_bit(z, "z", ECC_PRV_KEY_SIZE);

  // Calculate the random point R = k * G and take its x-coordinate: r = R.x
  lightecdh_bit_copy(k, (u32*)rnd);
  print_bit(z, "z", ECC_PRV_KEY_SIZE);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  print_bit(rx, "x", ECC_PRV_KEY_SIZE);
  print_bit(ry, "y", ECC_PRV_KEY_SIZE);
  lightecdh_bit_mul(r, k, rx);
  lightecdh_bit_mul(s, k, ry);
  print_bit(s, "s", ECC_PRV_KEY_SIZE);
  print_bit(r, "r", ECC_PRV_KEY_SIZE);

  lightecdh_bit_mod_n(rm, r);
  print_bit(rm, "rm", ECC_PRV_KEY_SIZE);

  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(mod n)
  lightecdh_bit_neg(kn, k);
  print_bit(kn, "kn", ECC_PRV_KEY_SIZE);

  lightecdh_bit_mul(rp, r, (u32*)privkey);
  print_bit(rp, "rp", ECC_PRV_KEY_SIZE);
  lightecdh_bit_add(h, (u32*)hash, rp);  // h needs mod n before?
  lightecdh_bit_mod_n(hn, h);
  print_bit(h, "h", ECC_PRV_KEY_SIZE);
  print_bit(hn, "hn", ECC_PRV_KEY_SIZE);
  lightecdh_bit_mul(s, hn, kn);
  print_bit(s, "s", ECC_PRV_KEY_SIZE);
  lightecdh_compress_sig((u32*)sign, r, s);
  print_bit(r, "r", ECC_PRV_KEY_SIZE);
  print_bit(s, "s", ECC_PRV_KEY_SIZE);
  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" +++ %.8x %.8x\n", (u32)r[i], (u32)s[i]);
  }
}

void lightecdh_verify(const u32* publkey, u32* hash, u32* sign) {
  bit hs, rs, rx, ry;
  sig r, s, s1, px, py, pubs;
  extern bit ecdh_x;
  extern bit ecdh_y;

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
  }

// Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  //lightecdh_bit_copy(z, (u32*)hash);

// Calculate the modular inverse of the signature proof: s1 = s^{-1} modn
  lightecdh_decompress_sig((u32*)r, (u32*)s, (u32*)sign);
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
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" --- %.8x %.8x %.8x %.8x\n", (u32)px[i], (u32)rx[i], (u32)r[i], (u32)s[i]);
  }
}
