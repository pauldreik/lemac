/*
 * This is a C++ implementation of LeMac, based on the 2024 public domain
 * implementation (CC0-1.0 license) by Augustin Bariant and Gaëtan Leurent.
 *
 * By Paul Dreik, https://www.pauldreik.se/
 *
 * https://github.com/pauldreik/lemac
 * SPDX-License-Identifier: BSL-1.0
 */

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include <immintrin.h>
#include <wmmintrin.h>

#include "lemac.h"

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wignored-attributes"
#endif

namespace {
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

__m128i AES128_modified(std::span<const __m128i, 11> Ki, __m128i x) {
  x ^= Ki[0];
  x = _mm_aesenc_si128(x, Ki[1]);
  x = _mm_aesenc_si128(x, Ki[2]);
  x = _mm_aesenc_si128(x, Ki[3]);
  x = _mm_aesenc_si128(x, Ki[4]);
  x = _mm_aesenc_si128(x, Ki[5]);
  x = _mm_aesenc_si128(x, Ki[6]);
  x = _mm_aesenc_si128(x, Ki[7]);
  x = _mm_aesenc_si128(x, Ki[8]);
  x = _mm_aesenc_si128(x, Ki[9]);
  x = _mm_aesenc_si128(x, _mm_set_epi64x(0, 0));
  return x;
}

__m128i AES128(std::span<const __m128i, 11> Ki, __m128i x) {
  assert(Ki.size() == 11);
  x ^= Ki[0];
  x = _mm_aesenc_si128(x, Ki[1]);
  x = _mm_aesenc_si128(x, Ki[2]);
  x = _mm_aesenc_si128(x, Ki[3]);
  x = _mm_aesenc_si128(x, Ki[4]);
  x = _mm_aesenc_si128(x, Ki[5]);
  x = _mm_aesenc_si128(x, Ki[6]);
  x = _mm_aesenc_si128(x, Ki[7]);
  x = _mm_aesenc_si128(x, Ki[8]);
  x = _mm_aesenc_si128(x, Ki[9]);
  x = _mm_aesenclast_si128(x, Ki[10]);
  return x;
}

// AES key schedule from
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf
void AES128_keyschedule(const __m128i K, std::span<__m128i, 11> roundkeys) {

  auto AES128_assist = [](__m128i a, __m128i b) -> __m128i {
    b = _mm_shuffle_epi32(b, 0xff);
    __m128i c = _mm_slli_si128(a, 0x4);
    a ^= c;
    c = _mm_slli_si128(c, 0x4);
    a ^= c;
    c = _mm_slli_si128(c, 0x4);
    a ^= c ^ b;
    return a;
  };

  __m128i a = K;
  roundkeys[0] = a;

  __m128i b = _mm_aeskeygenassist_si128(a, 0x1);
  a = AES128_assist(a, b);
  roundkeys[1] = a;

  b = _mm_aeskeygenassist_si128(a, 0x2);
  a = AES128_assist(a, b);
  roundkeys[2] = a;

  b = _mm_aeskeygenassist_si128(a, 0x4);
  a = AES128_assist(a, b);
  roundkeys[3] = a;

  b = _mm_aeskeygenassist_si128(a, 0x8);
  a = AES128_assist(a, b);
  roundkeys[4] = a;

  b = _mm_aeskeygenassist_si128(a, 0x10);
  a = AES128_assist(a, b);
  roundkeys[5] = a;

  b = _mm_aeskeygenassist_si128(a, 0x20);
  a = AES128_assist(a, b);
  roundkeys[6] = a;

  b = _mm_aeskeygenassist_si128(a, 0x40);
  a = AES128_assist(a, b);
  roundkeys[7] = a;

  b = _mm_aeskeygenassist_si128(a, 0x80);
  a = AES128_assist(a, b);
  roundkeys[8] = a;

  b = _mm_aeskeygenassist_si128(a, 0x1b);
  a = AES128_assist(a, b);
  roundkeys[9] = a;

  b = _mm_aeskeygenassist_si128(a, 0x36);
  a = AES128_assist(a, b);
  roundkeys[10] = a;
}

void init(lemac::LeMac::LeMacContext& ctx,
          std::span<const uint8_t, lemac::key_size> key) {
  __m128i Ki[11];
  AES128_keyschedule(_mm_loadu_si128((const __m128i*)key.data()), Ki);

  // Kinit 0 --> 8
  for (unsigned i = 0; i < std::size(ctx.init.S); ++i) {
    ctx.init.S[i] = AES128(Ki, _mm_set_epi64x(0, i));
  }

  // Kinit 9 --> 26
  for (unsigned i = 0; i < std::size(ctx.subkeys); ++i) {
    ctx.subkeys[i] = AES128(Ki, _mm_set_epi64x(0, i + std::size(ctx.init.S)));
  }

  // k2 27
  AES128_keyschedule(AES128(Ki, _mm_set_epi64x(0, std::size(ctx.init.S) +
                                                      std::size(ctx.subkeys))),
                     ctx.keys[0]);

  // k3 28
  AES128_keyschedule(
      AES128(Ki, _mm_set_epi64x(0, std::size(ctx.init.S) +
                                       std::size(ctx.subkeys) + 1)),
      ctx.keys[1]);
}
constexpr auto vector_register_alignment = std::alignment_of_v<__m128i>;

// assumes no alignment
inline void process_block(lemac::LeMac::Sstate& S, lemac::LeMac::Rstate& R,
                          const std::uint8_t* ptr) noexcept {
  const auto M0 = _mm_loadu_si128((const __m128i*)(ptr + 0));
  const auto M1 = _mm_loadu_si128((const __m128i*)(ptr + 16));
  const auto M2 = _mm_loadu_si128((const __m128i*)(ptr + 32));
  const auto M3 = _mm_loadu_si128((const __m128i*)(ptr + 48));
  __m128i T = S.S[8];
  S.S[8] = _mm_aesenc_si128(S.S[7], M3);
  S.S[7] = _mm_aesenc_si128(S.S[6], M1);
  S.S[6] = _mm_aesenc_si128(S.S[5], M1);
  S.S[5] = _mm_aesenc_si128(S.S[4], M0);

  S.S[4] = _mm_aesenc_si128(S.S[3], M0);
  S.S[3] = _mm_aesenc_si128(S.S[2], R.R1 ^ R.R2);
  S.S[2] = _mm_aesenc_si128(S.S[1], M3);
  S.S[1] = _mm_aesenc_si128(S.S[0], M3);
  S.S[0] = S.S[0] ^ T ^ M2;
  R.R2 = R.R1;
  R.R1 = R.R0;
  R.R0 = R.RR ^ M1;
  R.RR = M2;
}

inline void process_aligned_block(lemac::LeMac::Sstate& S,
                                  lemac::LeMac::Rstate& R,
                                  const __m128i* ptr) noexcept {
  __m128i T = S.S[8];
  S.S[8] = _mm_aesenc_si128(S.S[7], *(ptr + 3));
  S.S[7] = _mm_aesenc_si128(S.S[6], *(ptr + 1));
  S.S[6] = _mm_aesenc_si128(S.S[5], *(ptr + 1));
  S.S[5] = _mm_aesenc_si128(S.S[4], *(ptr + 0));

  S.S[4] = _mm_aesenc_si128(S.S[3], *(ptr + 0));
  S.S[3] = _mm_aesenc_si128(S.S[2], R.R1 ^ R.R2);
  S.S[2] = _mm_aesenc_si128(S.S[1], *(ptr + 3));
  S.S[1] = _mm_aesenc_si128(S.S[0], *(ptr + 3));
  S.S[0] = S.S[0] ^ T ^ *(ptr + 2);
  R.R2 = R.R1;
  R.R1 = R.R0;
  R.R0 = R.RR ^ *(ptr + 1);
  R.RR = *(ptr + 2);
}

inline void process_zero_block(lemac::LeMac::Sstate& S,
                               lemac::LeMac::Rstate& R) noexcept {
  const __m128i M = _mm_set_epi64x(0, 0);
  __m128i T = S.S[8];
  S.S[8] = _mm_aesenc_si128(S.S[7], M);
  S.S[7] = _mm_aesenc_si128(S.S[6], M);
  S.S[6] = _mm_aesenc_si128(S.S[5], M);
  S.S[5] = _mm_aesenc_si128(S.S[4], M);

  S.S[4] = _mm_aesenc_si128(S.S[3], M);
  S.S[3] = _mm_aesenc_si128(S.S[2], R.R1 ^ R.R2);
  S.S[2] = _mm_aesenc_si128(S.S[1], M);
  S.S[1] = _mm_aesenc_si128(S.S[0], M);
  S.S[0] = S.S[0] ^ T /*^ M2*/;
  R.R2 = R.R1;
  R.R1 = R.R0;
  R.R0 = R.RR /*^ M1*/;
  R.RR = M;
}
} // namespace

namespace lemac {

LeMac::LeMac(std::span<const uint8_t, key_size> key) noexcept { init(key); }

LeMac::LeMac(std::span<const std::uint8_t> key) {
  if (key.size() != key_size) {
    throw std::runtime_error("wrong size of key");
  }
  init(key.first<key_size>());
}

void LeMac::reset() noexcept {
  m_state.s = m_context.init;
  m_state.r.reset();
  m_bufsize = 0;
}

void LeMac::init(std::span<const uint8_t, key_size> key) noexcept {
  ::init(m_context, key);
  reset();
}

void LeMac::update(std::span<const uint8_t> data) noexcept {

  bool process_entire_m_buf = false;
  std::size_t remaining_to_full_block;
  if (m_bufsize != 0) {
    // fill the remainder of m_buf from data and process a whole block if
    // possible
    assert(m_bufsize < block_size);
    remaining_to_full_block = block_size - m_bufsize;
    if (data.size() < remaining_to_full_block) {
      // not enough data for a full block, append to the buffer and hope for
      // better luck next time
      std::memcpy(&m_buf[m_bufsize], data.data(), data.size());
      m_bufsize += data.size();
      return;
    }
    process_entire_m_buf = true;
  }

  // operate on a copy of the state and write it back later, this is 2.5x
  // faster than operating on m_state directly
  auto state = m_state;

  if (process_entire_m_buf) {
    // process the entire block
    std::memcpy(&m_buf[m_bufsize], data.data(), remaining_to_full_block);
    const bool buf_is_aligned =
        (reinterpret_cast<std::uintptr_t>(m_buf.data()) %
         vector_register_alignment) == 0;
    if (buf_is_aligned) {
      process_aligned_block(state.s, state.r, (const __m128i*)m_buf.data());
    } else {
      process_block(state.s, state.r, m_buf.data());
    }
    m_bufsize = 0;
    data = data.subspan(remaining_to_full_block);
  }

  // process whole blocks
  const auto whole_blocks = data.size() / block_size;
  const auto block_end = data.data() + whole_blocks * block_size;

  auto ptr = data.data();
  const bool aligned =
      (reinterpret_cast<std::uintptr_t>(ptr) % vector_register_alignment) == 0;
  if (aligned) {
    for (; ptr != block_end; ptr += block_size) {
      process_aligned_block(state.s, state.r, (const __m128i*)ptr);
    }
  } else {
    for (; ptr != block_end; ptr += block_size) {
      process_block(state.s, state.r, ptr);
    }
  }
  m_state = state;

  // write the tail into m_buf
  m_bufsize = data.size() - whole_blocks * block_size;
  if (m_bufsize) {
    std::memcpy(m_buf.data(), ptr, m_bufsize);
  }
}

std::array<std::uint8_t, 16>
LeMac::finalize(std::span<const std::uint8_t> nonce) {
  std::array<std::uint8_t, 16> ret;
  finalize_to(nonce, ret);
  return ret;
}

void LeMac::finalize_to(std::span<const std::uint8_t> nonce,
                        std::span<std::uint8_t, 16> target) noexcept {

  // let m_buf be padded
  assert(m_bufsize < m_buf.size());
  m_buf[m_bufsize] = 1;
  for (std::size_t i = m_bufsize + 1; i < m_buf.size(); ++i) {
    m_buf[i] = 0;
  }
  const bool buf_is_aligned = (reinterpret_cast<std::uintptr_t>(m_buf.data()) %
                               vector_register_alignment) == 0;
  if (buf_is_aligned) {
    process_aligned_block(m_state.s, m_state.r, (const __m128i*)m_buf.data());
  } else {
    process_block(m_state.s, m_state.r, m_buf.data());
  }

  // Four final rounds to absorb message state
  if constexpr (compile_time_options::unroll_zero_blocks) {
    process_zero_block(m_state.s, m_state.r);
    process_zero_block(m_state.s, m_state.r);
    process_zero_block(m_state.s, m_state.r);
    process_zero_block(m_state.s, m_state.r);
  } else {
    for (int i = 0; i < 4; ++i) {
      process_zero_block(m_state.s, m_state.r);
    }
  }

  if constexpr (compile_time_options::finalize_uses_tail) {
    tail(m_context, m_state.s, nonce, target);
  } else {
    assert(nonce.size() == 16);

    const auto N = _mm_loadu_si128((const __m128i*)nonce.data());

    auto& S = m_state.s;
    __m128i T = N ^ AES128(m_context.keys[0], N);
    T ^= AES128_modified(m_context.get_subkey<0>(), S.S[0]);
    T ^= AES128_modified(m_context.get_subkey<1>(), S.S[1]);
    T ^= AES128_modified(m_context.get_subkey<2>(), S.S[2]);
    T ^= AES128_modified(m_context.get_subkey<3>(), S.S[3]);
    T ^= AES128_modified(m_context.get_subkey<4>(), S.S[4]);
    T ^= AES128_modified(m_context.get_subkey<5>(), S.S[5]);
    T ^= AES128_modified(m_context.get_subkey<6>(), S.S[6]);
    T ^= AES128_modified(m_context.get_subkey<7>(), S.S[7]);
    T ^= AES128_modified(m_context.get_subkey<8>(), S.S[8]);

    const auto tag = AES128(m_context.keys[1], T);
    _mm_storeu_si128((__m128i*)target.data(), tag);
  }
}

void LeMac::Rstate::reset() { std::memset(this, 0, sizeof(*this)); }

std::array<uint8_t, 16>
LeMac::oneshot(std::span<const uint8_t> data,
               std::span<const uint8_t> nonce) const noexcept {

  Sstate S = m_context.init;
  Rstate R{};

  // process whole blocks
  const auto whole_blocks = data.size() / block_size;

  if (whole_blocks) {
    const bool data_is_aligned =
        (reinterpret_cast<std::uintptr_t>(data.data()) %
         vector_register_alignment) == 0;
    if (data_is_aligned) {
      auto ptr = (const __m128i*)data.data();
      const auto step = (block_size / sizeof(*ptr));
      const auto block_end = ptr + whole_blocks * step;
      for (; ptr != block_end; ptr += step) {
        if constexpr (compile_time_options::inline_processing) {
          __m128i T = S.S[8];
          S.S[8] = _mm_aesenc_si128(S.S[7], *(ptr + 3));
          S.S[7] = _mm_aesenc_si128(S.S[6], *(ptr + 1));
          S.S[6] = _mm_aesenc_si128(S.S[5], *(ptr + 1));
          S.S[5] = _mm_aesenc_si128(S.S[4], *(ptr + 0));

          S.S[4] = _mm_aesenc_si128(S.S[3], *(ptr + 0));
          S.S[3] = _mm_aesenc_si128(S.S[2], R.R1 ^ R.R2);
          S.S[2] = _mm_aesenc_si128(S.S[1], *(ptr + 3));
          S.S[1] = _mm_aesenc_si128(S.S[0], *(ptr + 3));
          S.S[0] = S.S[0] ^ T ^ *(ptr + 2);
          R.R2 = R.R1;
          R.R1 = R.R0;
          R.R0 = R.RR ^ *(ptr + 1);
          R.RR = *(ptr + 2);
        } else {
          process_aligned_block(S, R, ptr);
        }
      }
    } else {
      const auto block_end = data.data() + whole_blocks * block_size;
      auto ptr = data.data();
      for (; ptr != block_end; ptr += block_size) {
        if constexpr (compile_time_options::inline_processing) {
          const auto M0 = _mm_loadu_si128((const __m128i*)(ptr + 0));
          const auto M1 = _mm_loadu_si128((const __m128i*)(ptr + 16));
          const auto M2 = _mm_loadu_si128((const __m128i*)(ptr + 32));
          const auto M3 = _mm_loadu_si128((const __m128i*)(ptr + 48));
          __m128i T = S.S[8];
          S.S[8] = _mm_aesenc_si128(S.S[7], M3);
          S.S[7] = _mm_aesenc_si128(S.S[6], M1);
          S.S[6] = _mm_aesenc_si128(S.S[5], M1);
          S.S[5] = _mm_aesenc_si128(S.S[4], M0);

          S.S[4] = _mm_aesenc_si128(S.S[3], M0);
          S.S[3] = _mm_aesenc_si128(S.S[2], R.R1 ^ R.R2);
          S.S[2] = _mm_aesenc_si128(S.S[1], M3);
          S.S[1] = _mm_aesenc_si128(S.S[0], M3);
          S.S[0] = S.S[0] ^ T ^ M2;
          R.R2 = R.R1;
          R.R1 = R.R0;
          R.R0 = R.RR ^ M1;
          R.RR = M2;
        } else {
          process_block(S, R, ptr);
        }
      }
    }
  }

  // write the tail into m_buf
  std::array<std::uint8_t, block_size> buf{};
  const std::size_t bufsize = data.size() - whole_blocks * block_size;
  if (bufsize) {
    std::memcpy(buf.data(), data.data() + whole_blocks * block_size, bufsize);
  }

  // let m_buf be padded
  assert(bufsize < buf.size());
  buf[bufsize] = 1;

  process_block(S, R, buf.data());

  // Four final rounds to absorb message state
  if constexpr (compile_time_options::unroll_zero_blocks) {
    process_zero_block(S, R);
    process_zero_block(S, R);
    process_zero_block(S, R);
    process_zero_block(S, R);
  } else {
    for (int i = 0; i < 4; ++i) {
      process_zero_block(S, R);
    }
  }
  assert(nonce.size() == 16);

  const auto N = _mm_loadu_si128((const __m128i*)nonce.data());

  if constexpr (!compile_time_options::oneshot_uses_tail) {
    __m128i T = N ^ AES128(m_context.keys[0], N);
    T ^= AES128_modified(m_context.get_subkey<0>(), S.S[0]);
    T ^= AES128_modified(m_context.get_subkey<1>(), S.S[1]);
    T ^= AES128_modified(m_context.get_subkey<2>(), S.S[2]);
    T ^= AES128_modified(m_context.get_subkey<3>(), S.S[3]);
    T ^= AES128_modified(m_context.get_subkey<4>(), S.S[4]);
    T ^= AES128_modified(m_context.get_subkey<5>(), S.S[5]);
    T ^= AES128_modified(m_context.get_subkey<6>(), S.S[6]);
    T ^= AES128_modified(m_context.get_subkey<7>(), S.S[7]);
    T ^= AES128_modified(m_context.get_subkey<8>(), S.S[8]);

    const auto tag = AES128(m_context.keys[1], T);
    std::array<std::uint8_t, 16> ret;
    _mm_storeu_si128((__m128i*)ret.data(), tag);
    return ret;
  } else {
    std::array<std::uint8_t, 16> ret;
    tail(m_context, S, nonce, ret);
    return ret;
  }
}

void LeMac::tail(const LeMacContext& context, Sstate& S,
                 std::span<const std::uint8_t> nonce,
                 std::span<std::uint8_t, 16> target) const noexcept {
  assert(nonce.size() == 16);

  const auto N = _mm_loadu_si128((const __m128i*)nonce.data());

  __m128i T = N ^ AES128(m_context.keys[0], N);
  T ^= AES128_modified(m_context.get_subkey<0>(), S.S[0]);
  T ^= AES128_modified(m_context.get_subkey<1>(), S.S[1]);
  T ^= AES128_modified(m_context.get_subkey<2>(), S.S[2]);
  T ^= AES128_modified(m_context.get_subkey<3>(), S.S[3]);
  T ^= AES128_modified(m_context.get_subkey<4>(), S.S[4]);
  T ^= AES128_modified(m_context.get_subkey<5>(), S.S[5]);
  T ^= AES128_modified(m_context.get_subkey<6>(), S.S[6]);
  T ^= AES128_modified(m_context.get_subkey<7>(), S.S[7]);
  T ^= AES128_modified(m_context.get_subkey<8>(), S.S[8]);

  const auto tag = AES128(std::span(context.keys[1]), T);
  _mm_storeu_si128((__m128i*)target.data(), tag);
}
} // namespace lemac
