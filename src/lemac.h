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
  struct compile_time_options {
    /// clang - best with true for inputs larger than a few kB (10% faster), but
    /// best with false for small inputs (10% faster)
    /// gcc - faster with false
    constexpr static inline bool oneshot_uses_tail = false;
    /// gcc and clang - both are faster with false
    constexpr static inline bool finalize_uses_tail = false;
    /// does not seem to be important
    constexpr static inline bool unroll_zero_blocks = false;
    /// does not seem to be important
    constexpr static inline bool inline_processing = false;
  };

  static constexpr std::size_t key_size = 16;
  explicit LeMac(std::span<const std::uint8_t, key_size> key = std::span{
                     zero_key});
  explicit LeMac(std::span<const std::uint8_t> key);

  void update(std::span<const std::uint8_t> data);

  std::array<std::uint8_t, 16> oneshot(
      std::span<const std::uint8_t> data,
      std::span<const std::uint8_t> nonce = std::span{zero_key}) const noexcept;

  std::array<std::uint8_t, 16>
  finalize(std::span<const std::uint8_t> nonce = std::span{zero_key});

  void finalize_to(std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t, 16> target) noexcept;

  void reset();

  static constexpr std::array<const std::uint8_t, key_size> zero_key{};

  struct Sstate {
    __m128i S[9];
  };

  struct Rstate {
    void reset();
    __m128i RR;
    __m128i R0;
    __m128i R1;
    __m128i R2;
  };

  // this is the state that changes during absorption of data
  struct ComboState {
    Sstate s;
    Rstate r;
  };

  // this is inited on lemac construction and not changed after
  struct LeMacContext {
    Sstate init;
    __m128i keys[2][11];
    __m128i subkeys[18];
  };

private:
  void init(std::span<const std::uint8_t, key_size> key);
  static constexpr std::size_t block_size = 64;

  void tail(const LeMacContext& context, Sstate& state,
            std::span<const std::uint8_t> nonce,
            std::span<std::uint8_t, 16> target) const noexcept;
  LeMacContext m_context;
  ComboState m_state;
  std::array<std::uint8_t, block_size> m_buf{};
  std::size_t m_bufsize{};
};
