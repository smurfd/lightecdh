#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "lightecdh.h"
#include "lightecdh_bitmath.h"
#include "lightecdh_curves.h"
#include "lightecdh_pointmath.h"

// Generate keypair
void lightecdh_keygen(u32* pubkey, u32* privkey, cur* cc) {
  extern bit ecdh_x;
  extern bit ecdh_y;
  extern bit ecdh_n;

  lightecdh_point_copy((u32*)(pubkey), (u32*)(pubkey+BITVEC_NBYTES), ecdh_x, ecdh_y);

  int nb = lightecdh_bit_degree(ecdh_n);
  for (int i = (nb - 1); i < ((((*cc).DEGR + 3 + 31) / 32) * 32); ++i) {
    lightecdh_bit_clear(privkey, i);
  }
  lightecdh_point_mul(pubkey, pubkey+BITVEC_NBYTES, privkey);
}

int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res, cur* cc) {
  // Do some basic validation of other party's public key
  if (!lightecdh_point_is_zero (pubkey, pubkey + BITVEC_NBYTES) &&
    lightecdh_point_on_curve(pubkey, pubkey + BITVEC_NBYTES)) {
    // Copy other side's public key to output
    for (u32 i = 0; i < (u32)(*cc).PRIV * 2; ++i) {
      res[i] = pubkey[i];
    }

    // Multiply other side's public key with own private key
    lightecdh_point_mul(res, res + BITVEC_NBYTES, privkey);
    return 1;
  } else {
    return 0;
  }
}

void lightecdh_decompress_sig(u32* x, u32* y, const u32* z, cur* cc) {
  for (int i = 0; i < (*cc).PRIV; ++i) {
    x[i] = z[i];
    y[i] = z[i + (*cc).PRIV];
  }
}

void lightecdh_compress_sig(u32* x, const u32* y, const u32* z, cur* cc) {
  for (int i = 0; i < (*cc).PRIV; ++i) {
    x[i] = y[i];
    x[i + (*cc).PRIV] = z[i];
  }
}

void lightecdh_sign(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc) {
  bit z, kn, rp, h, hn, k;
  sig r, s, rm, rx, ry;
  extern bit ecdh_n;
  extern bit ecdh_p;
  extern bit ecdh_x;
  extern bit ecdh_y;
  int nb;

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
    rm[i] = 0;
  }
  lightecdh_bit_copy(z, hash);

  nb = lightecdh_bit_degree(ecdh_n);
  for (u32 i = (nb - 1); i < BITVEC_NBYTES; ++i) {
    lightecdh_bit_clear(z, i);
  }

  // Calculate the random point R = k * G and take its x-coordinate: r = R.x
  lightecdh_bit_copy(k, rnd);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);

  lightecdh_bit_mul(r, rx, k);
  lightecdh_bit_mul(s, ry, k);

  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(mod n)
  lightecdh_bit_neg1(kn, k);

  lightecdh_bit_mul(rp, r, privkey);
  lightecdh_bit_add(h, z, rp);  // h needs mod n before?
  lightecdh_bit_mul(hn, h, kn);

  lightecdh_bit_mod1(s, hn, ecdh_n);

  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  lightecdh_compress_sig(sign, r, s, cc);
}

void lightecdh_verify(const u32* publkey, u32* hash, u32* sign, cur* cc) {
  sig r, s, s1, px, py, pubs, z, rx, ry, hs, rs;
  extern bit ecdh_n;
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
  lightecdh_decompress_sig(r, s, sign, cc);
  lightecdh_bit_neg1(s1, s);
  lightecdh_bit_mod1(s1, s1, ecdh_n);

  // Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  lightecdh_bit_mul(hs, s1, z);
  lightecdh_bit_mul(rs, rx, hs);

  lightecdh_bit_mul(hs, s1, r);
  lightecdh_bit_mul(pubs, hs, publkey);
  lightecdh_bit_add(px, rs, pubs);

  // Take from R' its x-coordinate: r' = R'.x
  // Calculate the signature validation result by comparing whether r' == r
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" --- %.8x %.8x\n", px[i], r[i]); // r[i], s[i], rm[i]);
  }
  printf("equal? %d\n", lightecdh_bit_equal(r, px));
}

void lightecdh_sign_wikipedia(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc) {
  // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  bit  kn, x, y;
  sig r, s, rm, rx, x1, y1, k, zr, z;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;

  // Calculate e = HASH (m) (Here HASH is a cryptographic hash function, such as SHA-2, with the output converted to an integer.)
  // Let z be the Ln leftmost bits of e , where Ln is the bit length of the group order n, (Note that z can be greater than n n but not longer.[2])
  lightecdh_bit_copy(z, hash);

  // Select a cryptographically secure random integer k from [1 , n − 1]
  lightecdh_bit_copy(k, rnd);

  // Calculate the curve point ( x1 , y1 ) = k × G
  lightecdh_point_copy(x, y, ecdh_x, ecdh_y);
  lightecdh_bit_mul(x1, k, x);
  lightecdh_bit_mul(y1, k, y);

  // Calculate r = x1 mod n. If r = 0, go back to step 3.
  lightecdh_bit_mod1(r, x1, ecdh_n);

  // Calculate s = k^(−1) (z + r dA) mod n. If s = 0, go back to step 3.
  lightecdh_bit_neg1(kn, k);
  lightecdh_bit_mul(rx, r, privkey);
  lightecdh_bit_add(zr, rx, z);
  lightecdh_bit_mul(rm, zr, kn);
  lightecdh_bit_mod1(s, rm, ecdh_n);  // maby mod n on whole statement instead of here

  // The signature is the pair ( r , s ). (And ( r , − s mod n )  is also a valid signature.)
  lightecdh_compress_sig(sign, r, s, cc);
}

void lightecdh_verify_wikipedia(const u32* publkey, u32* hash, u32* sign, cur* cc) {
  bit x, y;
  sig z, r, s, s1, zs, zr, u1, u2, x1, x2, xn, rx;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;

  // Verify that r and s are integers in [ 1 , n − 1 ]. If not, the signature is invalid.
  lightecdh_decompress_sig(r, s, sign, cc);

  // Calculate e = HASH ( m ) where HASH is the same function used in the signature generation.
  // Let z be the Ln leftmost bits of e.
  lightecdh_bit_copy(z, hash);

  // Calculate u1 = zs^(−1) mod n  and u2 = rs^(−1) mod n
  lightecdh_bit_neg1(s1, s);
  lightecdh_bit_mul(zs, z, s1);
  lightecdh_bit_mod1(u1, zs, ecdh_n);

  lightecdh_bit_mul(zr, r, s1);
  lightecdh_bit_mod1(u2, zr, ecdh_n);

  // Calculate the curve point ( x1 , y1 ) = u1 × G + u2 × QA. If ( x1 , y1 ) = O then the signature is invalid.
  lightecdh_point_copy(x, y, ecdh_x, ecdh_y);
  lightecdh_bit_mul(x1, u1, x);
  lightecdh_bit_mul(x2, u2, publkey);
  lightecdh_bit_add(rx, x1, x2);
  lightecdh_bit_mod1(xn, rx, ecdh_n);

  // The signature is valid if r ≡ x1 ( mod n ), invalid otherwise.
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    printf(" --- %.8x %.8x %.8x\n", r[i], xn[i], rx[i]);
  }
}

void lightecdh_sign_pdf(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc) {
  // https://pdfserv.maximintegrated.com/en/an/TUT5767.pdf
  sig r, s, rm, rx, ry, z, kn, rp, h, hn, k;
  extern bit ecdh_n;
  extern bit ecdh_p;
  extern bit ecdh_x;
  extern bit ecdh_y;

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
    rm[i] = 0;
    rx[i] = 0;
    ry[i] = 0;
    z[i] = 0;
    kn[i] = 0;
    rp[i] = 0;
    h[i] = 0;
    hn[i] = 0;
    k[i] = 0;
  }
  lightecdh_bit_copy(z, hash);

  // sign
  // (x1, y1) = k × G(x, y) mod p
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  lightecdh_bit_copy(k, rnd);
  lightecdh_point_mul(rx, rx, k);
  lightecdh_bit_mod1(rm, rx, ecdh_p);

  // r = x1 mod n
  lightecdh_bit_mod1(r, rm, ecdh_n);

  // s = (k (h(m) + d * r) mod n
  lightecdh_bit_mul(rx, r, privkey);
  lightecdh_bit_add(ry, z, rx);
  lightecdh_bit_mul(rx, k, ry);
  lightecdh_bit_mod1(s, ry, ecdh_n);

  lightecdh_compress_sig(sign, r, s, cc);
  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" +++ %.8x %.8x\n", r[i], s[i]);
  }
}

void lightecdh_verify_pdf(const u32* publkey, u32* hash, u32* sign, cur* cc) {
  sig r, s, s1, px, py, pubs, rm, z, rx, ry, u1, u2, x2, w;
  extern bit ecdh_b;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;

  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    r[i] = 0;
    s[i] = 0;
    z[i] = 0;
    w[i] = 0;
    s1[i] = 0;
    px[i] = 0;
    py[i] = 0;
    pubs[i] = 0;
    rm[i] = 0;
    rx[i] = 0;
    ry[i] = 0;
    u1[i] = 0;
    u2[i] = 0;
    x2[i] = 0;
  }

  // verify
  // Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  lightecdh_bit_copy(z, hash);

  // Calculate the modular inverse of the signature proof: s1 = s^{-1} mod n
  lightecdh_decompress_sig(r, s, sign, cc);

  // w = s^(-1) mod n
  lightecdh_bit_neg1(s1, s);
  lightecdh_bit_mod1(w, s1, ecdh_n);

  // u1 = (h(m) * w) mod n
  lightecdh_bit_mul(rx, z, w);
  lightecdh_bit_mod1(u1, rx, ecdh_n);

  // u2 = (r * w) mod n
  lightecdh_bit_mul(ry, r, w);
  lightecdh_bit_mod1(u2, ry, ecdh_n);

  // (x2, y2) = (u1 × G(x, y) + u2 × Q(x, y)) mod n
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  lightecdh_bit_mul(px, u1, rx);
  lightecdh_bit_mul(py, u2, publkey);
  lightecdh_bit_add(rm, ry, px);
  lightecdh_bit_mod1(x2, rm, ecdh_n);

  // if x2 == r signature is valid
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" --- %.8x %.8x %.8x %.8x %.8x\n", x2[i], r[i], rx[i], px[i], rm[i]);
  }
}
