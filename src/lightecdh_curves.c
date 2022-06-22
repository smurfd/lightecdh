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
  switch (c) {
    case NIST_K163: {
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
      break;
    }
    case NIST_B163: {
      bit ecdh_p = { 0x000000c9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008 };
      bit ecdh_b = { 0x4a3205fd, 0x512f7874, 0x1481eb10, 0xb8c953ca, 0x0a601907, 0x00000002 };
      bit ecdh_x = { 0xe8343e36, 0xd4994637, 0xa0991168, 0x86a2d57e, 0xf0eba162, 0x00000003 };
      bit ecdh_y = { 0x797324f1, 0xb11c5c0c, 0xa2cdd545, 0x71a0094f, 0xd51fbc6c, 0x00000000 };
      bit ecdh_n = { 0xa4234c33, 0x77e70c12, 0x000292fe, 0x00000000, 0x00000000, 0x00000004 };
      int ecdh_a = 1;
      int ecdh_h = 2;
      int ecdh_DEGR = 163;
      int ecdh_PRIV = 24;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_K233: {
      bit ecdh_p = { 0x00000001, 0x00000000, 0x00000400, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200 };
      bit ecdh_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
      bit ecdh_x = { 0xefad6126, 0x0a4c9d6e, 0x19c26bf5, 0x149563a4, 0x29f22ff4, 0x7e731af1, 0x32ba853a, 0x00000172 };
      bit ecdh_y = { 0x56fae6a3, 0x56e0c110, 0xf18aeb9b, 0x27a8cd9b, 0x555a67c4, 0x19b7f70f, 0x537dece8, 0x000001db };
      bit ecdh_n = { 0xf173abdf, 0x6efb1ad5, 0xb915bcd4, 0x00069d5b, 0x00000000, 0x00000000, 0x00000000, 0x00000080 };
      int ecdh_a = 0;
      int ecdh_h = 4;
      int ecdh_DEGR = 233;
      int ecdh_PRIV = 32;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_B233: {
      bit ecdh_p = { 0x00000001, 0x00000000, 0x00000400, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000200 };
      bit ecdh_b = { 0x7d8f90ad, 0x81fe115f, 0x20e9ce42, 0x213b333b, 0x0923bb58, 0x332c7f8c, 0x647ede6c, 0x00000066 };
      bit ecdh_x = { 0x71fd558b, 0xf8f8eb73, 0x391f8b36, 0x5fef65bc, 0x39f1bb75, 0x8313bb21, 0xc9dfcbac, 0x000000fa };
      bit ecdh_y = { 0x01f81052, 0x36716f7e, 0xf867a7ca, 0xbf8a0bef, 0xe58528be, 0x03350678, 0x6a08a419, 0x00000100 };
      bit ecdh_n = { 0x03cfe0d7, 0x22031d26, 0xe72f8a69, 0x0013e974, 0x00000000, 0x00000000, 0x00000000, 0x00000100 };
      int ecdh_a = 1;
      int ecdh_h = 2;
      int ecdh_DEGR = 233;
      int ecdh_PRIV = 32;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_K283: {
      bit ecdh_p = { 0x000010a1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
      bit ecdh_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
      bit ecdh_x = { 0x58492836, 0xb0c2ac24, 0x16876913, 0x23c1567a, 0x53cd265f, 0x62f188e5, 0x3f1a3b81, 0x78ca4488, 0x0503213f };
      bit ecdh_y = { 0x77dd2259, 0x4e341161, 0xe4596236, 0xe8184698, 0xe87e45c0, 0x07e5426f, 0x8d90f95d, 0x0f1c9e31, 0x01ccda38 };
      bit ecdh_n = { 0x1e163c61, 0x94451e06, 0x265dff7f, 0x2ed07577, 0xffffe9ae, 0xffffffff, 0xffffffff, 0xffffffff, 0x01ffffff };
      int ecdh_a = 0;
      int ecdh_h = 4;
      int ecdh_DEGR = 283;
      int ecdh_PRIV = 36;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_B283: {
      bit ecdh_p = { 0x000010a1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
      bit ecdh_b = { 0x3b79a2f5, 0xf6263e31, 0xa581485a, 0x45309fa2, 0xca97fd76, 0x19a0303f, 0xa5a4af8a, 0xc8b8596d, 0x027b680a };
      bit ecdh_x = { 0x86b12053, 0xf8cdbecd, 0x80e2e198, 0x557eac9c, 0x2eed25b8, 0x70b0dfec, 0xe1934f8c, 0x8db7dd90, 0x05f93925 };
      bit ecdh_y = { 0xbe8112f4, 0x13f0df45, 0x826779c8, 0x350eddb0, 0x516ff702, 0xb20d02b4, 0xb98fe6d4, 0xfe24141c, 0x03676854 };
      bit ecdh_n = { 0xefadb307, 0x5b042a7c, 0x938a9016, 0x399660fc, 0xffffef90, 0xffffffff, 0xffffffff, 0xffffffff, 0x03ffffff };
      int ecdh_a = 1;
      int ecdh_h = 2;
      int ecdh_DEGR = 283;
      int ecdh_PRIV = 36;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_K409: {
      bit ecdh_p = { 0x00000001, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000 };
      bit ecdh_b = { 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
      bit ecdh_x = { 0xe9023746, 0xb35540cf, 0xee222eb1, 0xb5aaaa62, 0xc460189e, 0xf9f67cc2, 0x27accfb8, 0xe307c84c, 0x0efd0987, 0x0f718421, 0xad3ab189, 0x658f49c1, 0x0060f05f };
      bit ecdh_y = { 0xd8e0286b, 0x5863ec48, 0xaa9ca27a, 0xe9c55215, 0xda5f6c42, 0xe9ea10e3, 0xe6325165, 0x918ea427, 0x3460782f, 0xbf04299c, 0xacba1dac, 0x0b7c4e42, 0x01e36905 };
      bit ecdh_n = { 0xe01e5fcf, 0x4b5c83b8, 0xe3e7ca5b, 0x557d5ed3, 0x20400ec4, 0x83b2d4ea, 0xfffffe5f, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x007fffff };
      int ecdh_a = 0;
      int ecdh_h = 4;
      int ecdh_DEGR = 409;
      int ecdh_PRIV = 52;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_B409: {
      bit ecdh_p = { 0x00000001, 0x00000000, 0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000 };
      bit ecdh_b = { 0x7b13545f, 0x4f50ae31, 0xd57a55aa, 0x72822f6c, 0xa9a197b2, 0xd6ac27c8, 0x4761fa99, 0xf1f3dd67, 0x7fd6422e, 0x3b7b476b, 0x5c4b9a75, 0xc8ee9feb, 0x0021a5c2 };
      bit ecdh_x = { 0xbb7996a7, 0x60794e54, 0x5603aeab, 0x8a118051, 0xdc255a86, 0x34e59703, 0xb01ffe5b, 0xf1771d4d, 0x441cde4a, 0x64756260, 0x496b0c60, 0xd088ddb3, 0x015d4860 };
      bit ecdh_y = { 0x0273c706, 0x81c364ba, 0xd2181b36, 0xdf4b4f40, 0x38514f1f, 0x5488d08f, 0x0158aa4f, 0xa7bd198d, 0x7636b9c5, 0x24ed106a, 0x2bbfa783, 0xab6be5f3, 0x0061b1cf };
      bit ecdh_n = { 0xd9a21173, 0x8164cd37, 0x9e052f83, 0x5fa47c3c, 0xf33307be, 0xaad6a612, 0x000001e2, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x01000000 };
      int ecdh_a = 1;
      int ecdh_h = 2;
      int ecdh_DEGR = 409;
      int ecdh_PRIV = 52;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    case NIST_K571: {
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
      break;
    }
    case NIST_B571: {
      bit ecdh_p = { 0x00000425, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000 };
      bit ecdh_b = { 0x2955727a, 0x7ffeff7f, 0x39baca0c, 0x520e4de7, 0x78ff12aa, 0x4afd185a, 0x56a66e29, 0x2be7ad67, 0x8efa5933, 0x84ffabbd, 0x4a9a18ad, 0xcd6ba8ce, 0xcb8ceff1, 0x5c6a97ff, 0xb7f3d62f, 0xde297117, 0x2221f295, 0x02f40e7e };
      bit ecdh_x = { 0x8eec2d19, 0xe1e7769c, 0xc850d927, 0x4abfa3b4, 0x8614f139, 0x99ae6003, 0x5b67fb14, 0xcdd711a3, 0xf4c0d293, 0xbde53950, 0xdb7b2abd, 0xa5f40fc8, 0x955fa80a, 0x0a93d1d2, 0x0d3cd775, 0x6c16c0d4, 0x34b85629, 0x0303001d };
      bit ecdh_y = { 0x1b8ac15b, 0x1a4827af, 0x6e23dd3c, 0x16e2f151, 0x0485c19b, 0xb3531d2f, 0x461bb2a8, 0x6291af8f, 0xbab08a57, 0x84423e43, 0x3921e8a6, 0x1980f853, 0x009cbbca, 0x8c6c27a6, 0xb73d69d7, 0x6dccfffe, 0x42da639b, 0x037bf273 };
      bit ecdh_n = { 0x2fe84e47, 0x8382e9bb, 0x5174d66e, 0x161de93d, 0xc7dd9ca1, 0x6823851e, 0x08059b18, 0xff559873, 0xe661ce18, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x03ffffff };
      int ecdh_a = 1;
      int ecdh_h = 2;
      int ecdh_DEGR = 571;
      int ecdh_PRIV = 72;
      cc = lightecdh_curves_init(cc, ecdh_p, ecdh_b, ecdh_x, ecdh_y, ecdh_n, ecdh_a, ecdh_h, ecdh_DEGR, ecdh_PRIV);
      break;
    }
    default: {
      // incorrect curve
      break;
    }
  }

  (*cc).CURV = c;
  (*cc).PUBL = (*cc).PRIV * 2;
  (*cc).MARG = 3;
  (*cc).NBIT = ((*cc).DEGR + (*cc).MARG);
  (*cc).NWOR = (((*cc).NBIT + 31) / 32);
  (*cc).NBYT = (sizeof(u32) + (*cc).NWOR);
  return cc;
}
