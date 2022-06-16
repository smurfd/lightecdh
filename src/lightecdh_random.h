#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include "lightecdh.h"

// Pseudo-random number generator inspired / stolen from: http://burtleburtle.net/bob/rand/smallprng.html
// pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage

#ifndef LIGHTECDH_RANDOM_H 
#define LIGHTECDH_RANDOM_H 1

typedef struct {
  u32 a;
  u32 b;
  u32 c;
  u32 d;
} prng_t;

static prng_t prng_ctx;

u32 prng_rotate(u32 x, u32 k);
u32 prng_next(void);
void prng_init(u32 seed);

#endif
