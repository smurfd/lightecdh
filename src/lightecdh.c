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
  extern bit ecdh_p;
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

  lightecdh_bit_mod(rm, r, ecdh_p);

  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(mod n)
  lightecdh_bit_neg1(kn, k);

  lightecdh_bit_mul(rp, r, privkey);
  lightecdh_bit_add(h, hash, rp);  // h needs mod n before?
  lightecdh_bit_mod(hn, h, ecdh_n);
  lightecdh_bit_mul(s, hn, kn);
  lightecdh_compress_sig(sign, rm, s);
  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" +++ %.8x %.8x\n", r[i], s[i]);
  }
}

void lightecdh_verify(const u32* publkey, u32* hash, u32* sign) {
  bit hs, rs;
  sig r, s, s1, px, py, pubs, rm, z, rx, ry;
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
  lightecdh_decompress_sig(r, s, sign);

  lightecdh_bit_neg1(s1, s);
  lightecdh_bit_mod(s1, s1, ecdh_n);

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

  lightecdh_bit_mod(rm, px, ecdh_n);
  // Take from R' its x-coordinate: r' = R'.x

  // Calculate the signature validation result by comparing whether r' == r
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" --- %.8x %.8x %.8x %.8x %.8x\n", px[i], rx[i], r[i], s[i], rm[i]);
  }
  printf("lengths : %lu %d %d %d\n", BITVEC_NBYTES, BITVEC_NBITS, BITVEC_NWORDS, ECC_PRV_KEY_SIZE);

  printf("degree: %d %d %d %d %d\n", lightecdh_bit_degree(px),lightecdh_bit_degree(rx), lightecdh_bit_degree(r), lightecdh_bit_degree(s), lightecdh_bit_degree(rm));
  printf("equal? %d\n", lightecdh_bit_equal(r, rx));
}

void lightecdh_sign_wikipedia(const u32* privkey, u32* hash, u32* rnd, u32* sign) {
  // https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
  bit  kn, rp, h, hn, e, x, y;
  sig r, s, rm, rx, ry, x1, y1, k, zr, z;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;
  int nb;
  // Calculate e = HASH (m) (Here HASH is a cryptographic hash function, such as SHA-2, with the output converted to an integer.)
  // Let z be the Ln leftmost bits of e , where Ln is the bit length of the group order n, (Note that z can be greater than n n but not longer.[2])
  lightecdh_bit_copy(z, hash);

  // Select a cryptographically secure random integer k from [1 , n − 1]
  lightecdh_bit_copy(k, hash);

  // Calculate the curve point ( x1 , y1 ) = k × G
  lightecdh_point_copy(x, y, ecdh_x, ecdh_y);
  lightecdh_bit_mul(x1, x, k);
  lightecdh_bit_mul(y1, y, k);

  // Calculate r = x1 mod n. If r = 0, go back to step 3.
  lightecdh_bit_mod(r, x1, ecdh_n);

  // Calculate s = k^(−1) (z + r dA) mod n. If s = 0, go back to step 3.
  lightecdh_bit_inv(kn, k);
  lightecdh_bit_mul(rx, r, privkey);
  lightecdh_bit_add(zr, rx, z);
  lightecdh_bit_mod(z, zr, ecdh_n);  // maby mod n on whole statement instead of here
  lightecdh_bit_mul(s, z, kn);
  // ie : uncomment mod n and mul above and :
  // lightecdh_bit_mul(z, zr, kn);
  // lightecdh_bit_mod_n(s, z);

  // The signature is the pair ( r , s ). (And ( r , − s mod n )  is also a valid signature.)
  lightecdh_compress_sig(sign, r, s);
}

void lightecdh_verify_wikipedia(const u32* publkey, u32* hash, u32* sign) {
  bit hs, rs,  x, y;
  sig z, r, s, s1, s2, px, py, pubs, zs, zr, u1, u2, x1, x2, u1x, u2x, xn, rx, ry;
  extern bit ecdh_n;
  extern bit ecdh_x;
  extern bit ecdh_y;

  // Verify that r and s are integers in [ 1 , n − 1 ]. If not, the signature is invalid.
  lightecdh_decompress_sig(r, s, sign);
  // Calculate e = HASH ( m ) where HASH is the same function used in the signature generation.
  // Let z be the Ln leftmost bits of e.
  lightecdh_bit_copy(z, hash);

  // Calculate u1 = zs^(−1) mod n  and u2 = rs^(−1) mod n
  lightecdh_bit_neg1(s1, s);
  lightecdh_bit_mul(zs, z, s);
  lightecdh_bit_inv(s1, zs);
  lightecdh_bit_mod(u1, s1, ecdh_n);

  lightecdh_bit_mul(zr, r, s);
  lightecdh_bit_inv(s1, zr);
  lightecdh_bit_mod(u2, s1, ecdh_n);
  //lightecdh_bit_mod_n(s1, s1); //
  //lightecdh_bit_mul(u1, s1, z); //
  //lightecdh_bit_mul(u2, s1, r); //


  // Calculate the curve point ( x1 , y1 ) = u1 × G + u2 × QA. If ( x1 , y1 ) = O then the signature is invalid.
  lightecdh_point_copy(x, y, ecdh_x, ecdh_y);
  lightecdh_bit_mul(u1, x, y);
  lightecdh_bit_copy(rx, publkey);
  lightecdh_bit_copy(ry, publkey + ECC_PRV_KEY_SIZE);
  lightecdh_bit_mul(u2, rx, ry);

  lightecdh_point_add(x1, x2, u1, u2);
  lightecdh_bit_mod(xn, x1, ecdh_n);
//  lightecdh_point_mul(x, y, u1);
//  lightecdh_point_mul(u2, u1, publkey);
//  //lightecdh_bit_mul(u1x, x, u1);
//  //lightecdh_bit_mul(u2x, u2, publkey);
//  lightecdh_bit_add(x1, x, u1);
//  lightecdh_bit_mod_n(xn, x1);

/*
  lightecdh_bit_mul(u1x, x, u1);
  lightecdh_bit_mul(u2x, u2, publkey);
  lightecdh_bit_add(x1, u1x, u2x);
  lightecdh_bit_mod_n(xn, x1);
*/

  // The signature is valid if r ≡ x1 ( mod n ), invalid otherwise.
  for (int i = 0; i < BITVEC_NWORDS; ++i) {
    printf(" --- %.8x %.8x %.8x\n", r[i], xn[i], x1[i]);
  }
}

void lightecdh_sign_pdf(const u32* privkey, u32* hash, u32* rnd, u32* sign) {
  // https://pdfserv.maximintegrated.com/en/an/TUT5767.pdf
  sig r, s, rm, rx, ry, z, kn, rp, h, hn, k;
  extern bit ecdh_n;
  extern bit ecdh_p;
  extern bit ecdh_x;
  extern bit ecdh_y;
  int nb;

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
  //(x1, y1) = k × G(x, y) mod p
  //r = x1 mod n
  //s = (k (h(m) + d * r) mod n

  nb = lightecdh_bit_degree(ecdh_n);
  for (u32 i = (nb - 1); i < BITVEC_NBYTES; ++i) {
    lightecdh_bit_clear(z, i);
  }

  // Calculate the random point R = k * G and take its x-coordinate: r = R.x
  lightecdh_bit_copy(k, rnd);
  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  lightecdh_point_mul(rx, ry, k);
//  lightecdh_bit_mul(r, rx, k);
//  lightecdh_bit_mul(s, ry, k);

  lightecdh_bit_mod(rm, rx, ecdh_p);
  lightecdh_bit_mod(r, rm, ecdh_n);

  lightecdh_bit_mul(rx, r, privkey);
  lightecdh_bit_add(ry, z, rx);
  lightecdh_bit_mod(rm, ry, ecdh_n);
  lightecdh_bit_mul(s, k, rm);
  //lightecdh_bit_mul(rm, ry, k);
  //lightecdh_bit_mod_n(s, rm);
  // Calculate the signature proof: s = k−1∗(h+r∗privKey)(mod n)
  //lightecdh_bit_neg(kn, k);

  //lightecdh_bit_mul(rp, r, privkey);
  //lightecdh_bit_add(h, hash, rp);  // h needs mod n before?
  //lightecdh_bit_mod_n(hn, h);
  //lightecdh_bit_mul(s, hn, kn);

  lightecdh_compress_sig(sign, r, s);
  //The modular inverse  is an integer, such that  k ∗ k^(−1)≡1(mod n)
  //​Return the signature {r, s}.
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" +++ %.8x %.8x\n", r[i], s[i]);
  }
}

void lightecdh_verify_pdf(const u32* publkey, u32* hash, u32* sign) {
  //bit hs, rs;
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
  //w = s-1 mod n
  //u1 = (h(m) * w) mod n
  //u2 = (r * w) mod n
  //(x2, y2) = (u1 × G(x, y) + u2 × Q(x, y)) mod n
  //x2 == r
  // Calculate the message hash, with the same cryptographic hash function used during the signing: h = hash(msg)
  lightecdh_bit_copy(z, hash);

  // Calculate the modular inverse of the signature proof: s1 = s^{-1} mod n
  lightecdh_decompress_sig(r, s, sign);

  lightecdh_bit_neg1(s1, s);
  lightecdh_bit_mod(w, s1, ecdh_n);

  lightecdh_bit_mul(rx, z, w);
  lightecdh_bit_mod(u1, rx, ecdh_n);

  lightecdh_bit_mul(ry, r, w);
  lightecdh_bit_mod(u2, ry, ecdh_n);

  lightecdh_point_copy(rx, ry, ecdh_x, ecdh_y);
  lightecdh_bit_mul(px, u1, rx);
  lightecdh_bit_mul(py, u2, publkey);
  //lightecdh_point_mul(rx, ry, u1);
  //lightecdh_point_mul(px, py, u2);
  //lightecdh_point_copy(px, py, rx, publkey);
  lightecdh_bit_add(rm, ry, px);
  lightecdh_bit_mod(x2, rm, ecdh_n);
/*
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
*/
  for (int i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    printf(" --- %.8x %.8x %.8x %.8x %.8x\n", x2[i], r[i], rx[i], px[i], rm[i]);
  }
  printf("lengths : %lu %d %d %d\n", BITVEC_NBYTES, BITVEC_NBITS, BITVEC_NWORDS, ECC_PRV_KEY_SIZE);

  printf("degree: %d %d %d %d %d\n", lightecdh_bit_degree(x2),lightecdh_bit_degree(rx), lightecdh_bit_degree(r), lightecdh_bit_degree(s), lightecdh_bit_degree(rm));
  printf("equal? %d\n", lightecdh_bit_equal(r, x2));
  printf("-------------------------\n");
  lightecdh_bit_add(x2, ecdh_x, ecdh_b);
  print_bit(x2, "x2", BITVEC_NWORDS);

  lightecdh_bit_mul(x2, ecdh_x, ecdh_b);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_mod(x2, ecdh_b, ecdh_n);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_mod(x2, ecdh_x, ecdh_b);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_neg(x2, ecdh_b);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_neg(x2, ecdh_x);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_inv(x2, ecdh_b);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_inv(x2, ecdh_x);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_neg1(x2, ecdh_b);
  print_bit(ecdh_b, "ecdh_b", ECC_PRV_KEY_SIZE);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);

  lightecdh_bit_neg1(x2, ecdh_x);
  print_bit(ecdh_x, "ecdh_x", ECC_PRV_KEY_SIZE);
  print_bit(x2, "x2", ECC_PRV_KEY_SIZE);
}

/*
prog :
x + b : 0x5c94eee9 0xde4e6d5e 0xaa07d793 0x7bbc11ac 0xfe13c053 0x00000002
x * b : x2 = [ 0x5c94eee8 0xde4e6d5e 0xaa07d793 0x7bbc11ac 0xfe13c053 0x00000002 ]

---
python :
x + b : 0x5c94eee9 de4e6d5e aa07d793 7bbc11a cfe13c053 00000002
x * b : 0x5c94eee8 de4e6d5eaa07d7937bbc11acfe13c053000000020000000000000000000000000000000000000000
b ^(-1) : -0x5c94eee8de4e6d5eaa07d7937bbc11acfe13c05300000003
x % b : 0x10000000000000000000000000000000000000000
b % x : 0xde4e6d5eaa07d7937bbc11acfe13c05300000002
*/