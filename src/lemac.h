#pragma once

#include <immintrin.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  __m128i S[9];
} state;

typedef struct {
  state init;
  __m128i keys[2][11];
  __m128i subkeys[18];
} context;

void lemac_init(context* ctx, const uint8_t k[]);
void lemac_MAC(context* ctx, const uint8_t* nonce, const uint8_t* m,
               size_t mlen, uint8_t* tag);

#ifdef __cplusplus
} // extern "C"
#endif
