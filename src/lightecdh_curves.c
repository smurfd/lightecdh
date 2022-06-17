#include "lightecdh.h"

// NIST K-163
bit ecdh_p = { 0x000000c9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008 }; 
bit ecdh_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 }; 
bit ecdh_x = { 0x5c94eee8, 0xde4e6d5e, 0xaa07d793, 0x7bbc11ac, 0xfe13c053, 0x00000002 }; 
bit ecdh_y = { 0xccdaa3d9, 0x0536d538, 0x321f2e80, 0x5d38ff58, 0x89070fb0, 0x00000002 }; 
bit ecdh_n = { 0x99f8a5ef, 0xa2e0cc0d, 0x00020108, 0x00000000, 0x00000000, 0x00000004 }; 
int ecdh_a = 1;
int ecdh_h = 2;

void lightecdh_curves_set() {
  // maby used to set differnt curves to use in the future?
}