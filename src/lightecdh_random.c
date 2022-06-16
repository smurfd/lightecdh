#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "lightecdh.h"
#include "lightecdh_random.h"
// Pseudo-random number generator inspired / stolen from: http://burtleburtle.net/bob/rand/smallprng.html
// pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage

u32 prng_rotate(u32 x, u32 k) {
  return (x << k) | (x >> (32 - k)); 
}

u32 prng_next(void) {
  u32 e = prng_ctx.a - prng_rotate(prng_ctx.b, 27); 
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17); 
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; 
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

void prng_init(u32 seed) {
  prng_ctx.a = 0xea7f00d1;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (u32 i = 0; i < 31; ++i) {
    (void) prng_next();
  }
}
