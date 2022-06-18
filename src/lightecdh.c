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
    lightecdh_bit_clear(privkey, i);
  }
  lightecdh_point_mul(pubkey, pubkey+BITVEC_NBYTES, privkey);
}

int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res) {
  // Do some basic validation of other party's public key
  if (!lightecdh_point_is_zero (pubkey, pubkey + BITVEC_NBYTES) &&
    lightecdh_point_on_curve(pubkey, pubkey + BITVEC_NBYTES)) {
    // Copy other side's public key to output
    for (unsigned int i = 0; i < ECC_PUB_KEY_SIZE; ++i) {
      res[i] = pubkey[i];
    }

    // Multiply other side's public key with own private key
    lightecdh_point_mul(res, res + BITVEC_NBYTES, privkey);
    return 1;
  } else {
    return 0;
  }
}

void lightecdh_decompress_sig(u32* x, u32* y, const u32* z) {
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    x[i] = z[i];
    y[i] = z[i + BITVEC_NWORDS];
  }
}

void lightecdh_compress_sig(u32* x, const u32* y, const u32* z) {
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    x[i] = y[i];
    x[i + BITVEC_NWORDS] = z[i];
  }
}

void lightecdh_sign(const u32* privkey, u32* hash, u32* rnd, u32* sign) {
  bit z, kn, rp, h, hn, k;
  sig r, s, rm, rx, ry;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;
  int nb;

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
    rm[i] = 0;
  }
  lightecdh_bit_copy(z, (u32*)hash);

  nb = lightecdh_bit_degree(ecdh_n);
  for (u32 i = (nb - 1); i < BITVEC_NBYTES; ++i) {
    lightecdh_bit_clear(z, i);
  }

  // Calculate the random point R = k * G and take its x-coordinate: r = R.x
  lightecdh_bit_copy(k, (u32*)rnd);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);

  lightecdh_bit_mul(r, rx, k);
  lightecdh_bit_mul(s, ry, k);

  lightecdh_bit_mod_n(rm, r);

  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(mod n)
  lightecdh_bit_neg(kn, k);

  lightecdh_bit_mul(rp, r, privkey);
  lightecdh_bit_add(h, hash, rp);  // h needs mod n before?
  lightecdh_bit_mod_n(hn, h);
  lightecdh_bit_mul(s, hn, kn);
  lightecdh_compress_sig(sign, r, s);
  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" +++ %.8x %.8x\n", r[i], s[i]);
  }
}

void lightecdh_verify(const u32* publkey, u32* hash, u32* sign) {
  bit hs, rs;
  sig r, s, s1, px, py, pubs, rm, z, rx, ry;
  extern bit ecdh_x;
  extern bit ecdh_y;

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
    px[i] = 0;
    py[i] = 0;
    pubs[i] = 0;
    rx[i] = 0;
    ry[i] = 0;

  }

  // Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  lightecdh_bit_copy(z, hash);

  // Calculate the modular inverse of the signature proof: s1 = s^{-1} mod n
  lightecdh_decompress_sig(r, s, sign);

  lightecdh_bit_neg(s1, s);
  lightecdh_bit_mod_n(s1, s1);

  // Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
  lightecdh_bit_mul(hs, s1, z);

  lightecdh_bit_mul(rs, s1, r);
  lightecdh_bit_mul(pubs, rs, publkey);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" *** %.8x %.8x %.8x\n", rx[i], ry[i], pubs[i]);
  }

  lightecdh_bit_mul(rx, rx, hs);
  lightecdh_bit_mul(ry, ry, hs);
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" ***** %.8x %.8x %.8x\n", rx[i], ry[i], pubs[i]);
  }
  lightecdh_bit_add(px, rx, pubs);
  lightecdh_bit_add(py, ry, pubs);

  lightecdh_bit_mod_n(rm, px);
  // Take from R' its x-coordinate: r' = R'.x

  // Calculate the signature validation result by comparing whether r' == r
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" --- %.8x %.8x %.8x %.8x %.8x\n", px[i], rx[i], r[i], s[i], rm[i]);
  }
  printf("lengths : %lu %d %d %d\n", BITVEC_NBYTES, BITVEC_NBITS, BITVEC_NWORDS, ECC_PRV_KEY_SIZE);

  printf("degree: %d %d %d %d %d\n", lightecdh_bit_degree(px),lightecdh_bit_degree(rx), lightecdh_bit_degree(r), lightecdh_bit_degree(s), lightecdh_bit_degree(rm));
  printf("equal? %d\n", lightecdh_bit_equal(r, rx));
}
