#include "lightecdh.h"

// NIST K-163
bit ecdh_p = { 0x000000c9UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000008UL };
bit ecdh_b = { 0x00000001UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL, 0x00000000UL };
bit ecdh_x = { 0x5c94eee8UL, 0xde4e6d5eUL, 0xaa07d793UL, 0x7bbc11acUL, 0xfe13c053UL, 0x00000002UL };
bit ecdh_y = { 0xccdaa3d9UL, 0x0536d538UL, 0x321f2e80UL, 0x5d38ff58UL, 0x89070fb0UL, 0x00000002UL };
bit ecdh_n = { 0x99f8a5efUL, 0xa2e0cc0dUL, 0x00020108UL, 0x00000000UL, 0x00000000UL, 0x00000004UL };
int ecdh_a = 1;
int ecdh_h = 2;

void lightecdh_curves_set() {
  // maby used to set differnt curves to use in the future?
}
