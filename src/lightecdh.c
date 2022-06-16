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
