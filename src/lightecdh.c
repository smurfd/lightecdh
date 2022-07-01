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
  for (u32 i = 0; i < (u32)(*cc).PUBL; ++i) {
    pubkey[i] = 0;
  }
  lightecdh_point_copy((u32*)(pubkey), (u32*)(pubkey + (*cc).NBYT), (*cc).ecdh_x, (*cc).ecdh_y, cc);

  int nb = lightecdh_bit_degree((*cc).ecdh_n, cc);
  for (int i = (nb - 1); i < ((((*cc).DEGR + 3 + 31) / 32) * 32); ++i) {
    lightecdh_bit_clear(privkey, i);
  }
  lightecdh_point_mul(pubkey, pubkey + (*cc).NBYT, privkey, cc);
}

int lightecdh_shared_secret(const u32* privkey, const u32* pubkey, u32* res, cur* cc) {
  // Do some basic validation of other party's public key
  if (!lightecdh_point_is_zero (pubkey, pubkey + (*cc).NBYT, cc) &&
    lightecdh_point_on_curve(pubkey, pubkey + (*cc).NBYT, cc)) {
    // Copy other side's public key to output
    for (u32 i = 0; i < (u32)(*cc).PUBL; ++i) {
      res[i] = pubkey[i];
    }

    // Multiply other side's public key with own private key
    lightecdh_point_mul(res, res + (*cc).NBYT, privkey, cc);
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
  sig r, s, rx, ry;
  int nb;

  lightecdh_bit_copy(z, hash, cc);

  nb = lightecdh_bit_degree((*cc).ecdh_n, cc);
  for (u32 i = (nb - 1); i < (u32)(*cc).NBYT; ++i) {
    lightecdh_bit_clear(z, i);
  }

  // Calculate the random point R = k * G and take its x-coordinate: r = R.x
  lightecdh_bit_copy(k, rnd, cc);
  lightecdh_point_copy(rx, ry, (*cc).ecdh_x, (*cc).ecdh_y, cc);

  lightecdh_bit_mul(r, rx, k, cc);
  lightecdh_bit_mul(s, ry, k, cc);

  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(mod n)
  lightecdh_bit_neg1(kn, k, cc);

  lightecdh_bit_mul(rp, r, privkey, cc);
  lightecdh_bit_add(h, z, rp, cc);  // h needs mod n before?
  lightecdh_bit_mul(hn, h, kn, cc);

  lightecdh_bit_mod1(s, hn, (*cc).ecdh_n, cc);

  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  lightecdh_compress_sig(sign, r, s, cc);
}

void lightecdh_verify(const u32* publkey, u32* hash, u32* sign, cur* cc) {
  sig r, s, s1, px, pubs, z, rx, ry, hs, rs;

  // Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  lightecdh_bit_copy(z, hash, cc);

  // Calculate the modular inverse of the signature proof: s1 = s^{-1} mod n
  lightecdh_decompress_sig(r, s, sign, cc);
  lightecdh_bit_neg1(s1, s, cc);
  lightecdh_bit_mod1(s1, s1, (*cc).ecdh_n, cc);

  // Recover the random point used during the signing: R' = (h * s1) * G + (r * s1) * pubKey
  lightecdh_point_copy(rx, ry, (*cc).ecdh_x, (*cc).ecdh_y, cc);
  lightecdh_bit_mul(hs, s1, z, cc);
  lightecdh_bit_mul(rs, rx, hs, cc);

  lightecdh_bit_mul(hs, s1, r, cc);
  lightecdh_bit_mul(pubs, hs, publkey, cc);
  lightecdh_bit_add(px, rs, pubs, cc);

  // Take from R' its x-coordinate: r' = R'.x
  // Calculate the signature validation result by comparing whether r' == r
  for (int i = 0; i < (*cc).PRIV; ++i) {
    printf(" --- %.8x %.8x\n", px[i], r[i]); // r[i], s[i], rm[i]);
  }
  printf("equal? %d\n", lightecdh_bit_equal(r, px, cc));
}

void lightecdh_sign_wikipedia(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc) {
  // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  sig r, s, rm, rx, x1, y1, k, zr, z, kn, x, y;

  // Calculate e = HASH (m) (Here HASH is a cryptographic hash function, such as SHA-2, with the output converted to an integer.)
  // Let z be the Ln leftmost bits of e , where Ln is the bit length of the group order n, (Note that z can be greater than n n but not longer.[2])
  lightecdh_bit_copy(z, hash, cc);

  // Select a cryptographically secure random integer k from [1 , n − 1]
  lightecdh_bit_copy(k, rnd, cc);

  // Calculate the curve point ( x1 , y1 ) = k × G
  lightecdh_point_copy(x, y, (*cc).ecdh_x, (*cc).ecdh_y, cc);
  lightecdh_bit_mul(x1, k, x, cc);
  lightecdh_bit_mul(y1, k, y, cc);

  // Calculate r = x1 mod n. If r = 0, go back to step 3.
  lightecdh_bit_mod1(r, x1, (*cc).ecdh_n, cc);

  // Calculate s = k^(−1) (z + r dA) mod n. If s = 0, go back to step 3.
  lightecdh_bit_neg1(kn, k, cc);
  lightecdh_bit_mul(rx, r, privkey, cc);
  lightecdh_bit_add(zr, rx, z, cc);
  lightecdh_bit_mul(rm, zr, kn, cc);
  lightecdh_bit_mod1(s, rm, (*cc).ecdh_n, cc);  // maby mod n on whole statement instead of here

  // The signature is the pair ( r , s ). (And ( r , − s mod n )  is also a valid signature.)
  lightecdh_compress_sig(sign, r, s, cc);
}

void lightecdh_verify_wikipedia(const u32* publkey, u32* hash, u32* sign, cur* cc) {
  sig z, r, s, s1, zs, zr, u1, u2, x1, x2, xn, rx, x, y;

  // Verify that r and s are integers in [ 1 , n − 1 ]. If not, the signature is invalid.
  lightecdh_decompress_sig(r, s, sign, cc);

  // Calculate e = HASH ( m ) where HASH is the same function used in the signature generation.
  // Let z be the Ln leftmost bits of e.
  lightecdh_bit_copy(z, hash, cc);

  // Calculate u1 = zs^(−1) mod n  and u2 = rs^(−1) mod n
  lightecdh_bit_neg1(s1, s, cc);
  lightecdh_bit_mul(zs, z, s1, cc);
  lightecdh_bit_mod1(u1, zs, (*cc).ecdh_n, cc);

  lightecdh_bit_mul(zr, r, s1, cc);
  lightecdh_bit_mod1(u2, zr, (*cc).ecdh_n, cc);

  // Calculate the curve point ( x1 , y1 ) = u1 × G + u2 × QA. If ( x1 , y1 ) = O then the signature is invalid.
  lightecdh_point_copy(x, y, (*cc).ecdh_x, (*cc).ecdh_y, cc);
  lightecdh_bit_mul(x1, u1, x, cc);
  lightecdh_bit_mul(x2, u2, publkey, cc);
  lightecdh_bit_add(rx, x1, x2, cc);
  lightecdh_bit_mod1(xn, rx, (*cc).ecdh_n, cc);

  // The signature is valid if r ≡ x1 ( mod n ), invalid otherwise.
  for (int i = 0; i < (*cc).NWOR; ++i) {
    printf(" --- %.8x %.8x %.8x\n", r[i], xn[i], rx[i]);
  }
}

void lightecdh_sign_pdf(const u32* privkey, u32* hash, u32* rnd, u32* sign, cur* cc) {
  // https://pdfserv.maximintegrated.com/en/an/TUT5767.pdf
  sig r, s, rm, rx, ry, z, k;

  // sign
  lightecdh_bit_copy(z, hash, cc);

  // (x1, y1) = k × G(x, y) mod p
  lightecdh_point_copy(rx, ry, (*cc).ecdh_x, (*cc).ecdh_y, cc);
  lightecdh_bit_copy(k, rnd, cc);
  lightecdh_point_mul(rx, rx, k, cc);
  lightecdh_bit_mod1(rm, rx, (*cc).ecdh_p, cc);

  // r = x1 mod n
  lightecdh_bit_mod1(r, rm, (*cc).ecdh_n, cc);

  // s = (k (h(m) + d * r) mod n
  lightecdh_bit_mul(rx, r, privkey, cc);
  lightecdh_bit_add(ry, z, rx, cc);
  lightecdh_bit_mul(rx, k, ry, cc);
  lightecdh_bit_mod1(s, ry, (*cc).ecdh_n, cc);

  lightecdh_compress_sig(sign, r, s, cc);
  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  for (int i = 0; i < (*cc).PRIV; ++i) {
    printf(" +++ %.8x %.8x\n", r[i], s[i]);
  }
}

void lightecdh_verify_pdf(const u32* publkey, u32* hash, u32* sign, cur* cc) {
  sig r, s, s1, px, py, rm, z, rx, ry, u1, u2, x2, w;

  // verify
  // Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  lightecdh_bit_copy(z, hash, cc);

  // Calculate the modular inverse of the signature proof: s1 = s^{-1} mod n
  lightecdh_decompress_sig(r, s, sign, cc);

  // w = s^(-1) mod n
  lightecdh_bit_neg1(s1, s, cc);
  lightecdh_bit_mod1(w, s1, (*cc).ecdh_n, cc);

  // u1 = (h(m) * w) mod n
  lightecdh_bit_mul(rx, z, w, cc);
  lightecdh_bit_mod1(u1, rx, (*cc).ecdh_n, cc);

  // u2 = (r * w) mod n
  lightecdh_bit_mul(ry, r, w, cc);
  lightecdh_bit_mod1(u2, ry, (*cc).ecdh_n, cc);

  // (x2, y2) = (u1 × G(x, y) + u2 × Q(x, y)) mod n
  lightecdh_point_copy(rx, ry, (*cc).ecdh_x, (*cc).ecdh_y, cc);
  lightecdh_bit_mul(px, u1, rx, cc);
  lightecdh_bit_mul(py, u2, publkey, cc);
  lightecdh_bit_add(rm, ry, px, cc);
  lightecdh_bit_mod1(x2, rm, (*cc).ecdh_n, cc);

  // if x2 == r signature is valid
  for (int i = 0; i < (*cc).PRIV; ++i) {
    printf(" --- %.8x %.8x %.8x %.8x %.8x\n", x2[i], r[i], rx[i], px[i], rm[i]);
  }
}

// Below is Borrowed / Stolen from https://github.com/jestan/easy-ecc

// Clear p
void lee_clear(u64 *p) {
  for (uint8_t i = 0; i < LEE_D; ++i) {p[i] = 0;}
}

// Returns 1 if p == 0, 0 otherwise.
int lee_iszero(u64 *p) {
  for (uint8_t i = 0; i < LEE_D; ++i) {
    if (p[i]) {return 0;}
  }
  return 1;
}

// Returns nonzero if bit q of p is set.
u64 lee_isset(u64 *p, uint q) {
  return (p[q / 64] & ((u64)1 << (q % 64)));
}

// Counts the number of 64-bit "digits" in p.
uint lee_digits(u64 *p) {
  int i;
  // Search from the end until we find a non-zero digit.
  // We do it in reverse because we expect that most digits will be nonzero.
  for (i = LEE_D - 1; i >= 0 && p[i] == 0; --i) {}
  return (i + 1);
}

// Counts the number of bits required for p.
uint lee_bits(u64 *p) {
  uint i, numDigits = lee_digits(p);
  u64 digit;

  if (numDigits == 0) {return 0;}

  digit = p[numDigits - 1];
  for (i = 0; digit; ++i) {digit >>= 1;}

  return ((numDigits - 1) * 64 + i);
}

// Sets r = p.
void lee_set(u64 *r, const u64 *p) {
  for (uint8_t i = 0; i < LEE_D; ++i) {r[i] = p[i];}
}

// Returns sign of p - q.
int lee_cmp(u64 *p, u64 *q) {
  for (int i = LEE_D-1; i >= 0; --i) {
    if (p[i] > q[i]) {
      return 1;
    } else if (p[i] < q[i]) {
      return -1;
    }
  }
  return 0;
}
