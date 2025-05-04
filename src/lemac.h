#pragma once

#include <array>
#include <cstdint>
#include <span>

#include <immintrin.h>
#include <stdint.h>

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

class LeMac {
public:
  static constexpr std::size_t key_size = 16;
  explicit LeMac(std::span<const std::uint8_t, key_size> key = std::span{
                     zero_key});
  explicit LeMac(std::span<const std::uint8_t> key);

  void update(std::span<const std::uint8_t> data);

  std::array<std::uint8_t, 16>
  finalize(std::span<const std::uint8_t> nonce = std::span{zero_key});
  void finalize_to(std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t, 16> target);

  static constexpr std::array<const std::uint8_t, key_size> zero_key{};

private:
  void init(std::span<const std::uint8_t, key_size> key);
  static constexpr std::size_t block_size = 64;
  void process_full_block(std::span<const std::uint8_t, block_size> data);

  struct Rstate {
    __m128i RR;
    __m128i R0;
    __m128i R1;
    __m128i R2;
  };

  context m_context;
  state m_state;
  Rstate m_rstate;
  std::array<std::uint8_t, block_size> m_buf{};
  std::size_t m_bufsize{};
};
