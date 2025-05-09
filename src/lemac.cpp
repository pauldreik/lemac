/* LeMac AES-NI implementation

Written in 2024 by
  Augustin Bariant <augustin.bariant@ssi.gouv.fr>
  Gaëtan Leurent <gaetan.leurent@inria.fr>

To the extent possible under law, the author(s) have dedicated all
copyright and related and neighboring rights to this software to the
public domain worldwide. This software is distributed without any
warranty.

You should have received a copy of the CC0 Public Domain Dedication
along with this software. If not, see
<http://creativecommons.org/publicdomain/zero/1.0/>.
*/

/* NOTES
 - This file implements the correct version of LeMac, fixing a mistake
   in the message schedule in the original specification
 - Assumes that the message size is a multiple of 8bits
 - Assumes that endianness matches the hardware
 */

#include <cassert>
#include <cstring>
#include <immintrin.h>
#include <stdexcept>
#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>

#include "lemac.h"

#define STATE_0 _mm_set_epi64x(0, 0)

#define tabsize(T) (sizeof(T) / sizeof((T)[0]))

// AES key schedule from
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

__m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x4);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

void AES_KS(__m128i K, __m128i* Key_Schedule) {
  __m128i temp1, temp2;
  temp1 = K;
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = AES_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
}

__m128i AES(const __m128i* Ki, __m128i x) {
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

__m128i AES_modified(const __m128i* Ki, __m128i x) {
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

void lemac_init(context* ctx, const uint8_t k[]) {
  const auto K = _mm_loadu_si128((const __m128i*)k);
  __m128i Ki[11];
  AES_KS(K, Ki);

  // Kinit 0 --> 8
  for (unsigned i = 0; i < tabsize(ctx->init.S); i++)
    ctx->init.S[i] = AES(Ki, _mm_set_epi64x(0, i));

  // Kinit 9 --> 26
  for (unsigned i = 0; i < tabsize(ctx->subkeys); i++)
    ctx->subkeys[i] = AES(Ki, _mm_set_epi64x(0, i + tabsize(ctx->init.S)));

  // k2 27
  AES_KS(
      AES(Ki, _mm_set_epi64x(0, tabsize(ctx->init.S) + tabsize(ctx->subkeys))),
      ctx->keys[0]);

  // k3 28
  AES_KS(AES(Ki, _mm_set_epi64x(0, tabsize(ctx->init.S) +
                                       tabsize(ctx->subkeys) + 1)),
         ctx->keys[1]);
}

#define ROUND(S, M0, M1, M2, M3, RR, R0, R1, R2)                               \
  do {                                                                         \
    __m128i T = S.S[8];                                                        \
    S.S[8] = _mm_aesenc_si128(S.S[7], M3);                                     \
    S.S[7] = _mm_aesenc_si128(S.S[6], M1);                                     \
    S.S[6] = _mm_aesenc_si128(S.S[5], M1);                                     \
    S.S[5] = _mm_aesenc_si128(S.S[4], M0);                                     \
    S.S[4] = _mm_aesenc_si128(S.S[3], M0);                                     \
    S.S[3] = _mm_aesenc_si128(S.S[2], R1 ^ R2);                                \
    S.S[2] = _mm_aesenc_si128(S.S[1], M3);                                     \
    S.S[1] = _mm_aesenc_si128(S.S[0], M3);                                     \
    S.S[0] = S.S[0] ^ T ^ M2;                                                  \
    R2 = R1;                                                                   \
    R1 = R0;                                                                   \
    R0 = RR ^ M1;                                                              \
    RR = M2;                                                                   \
  } while (0);

state lemac_AU(context* ctx, const uint8_t* m, size_t mlen) {
  assert(m);
  /* state S = ctx->init; */
  // Padding
  size_t m_padded_len = mlen - (mlen % 64) + 64;
  uint8_t m_padding[64];
  memcpy(m_padding, m + (mlen / 64) * 64, mlen % 64);
  m_padding[mlen % 64] = 1;
  __m128i* M_padding = (__m128i*)m_padding;
  for (size_t i = 1 + (mlen % 64); i < 64; ++i) {
    m_padding[i] = 0;
  }

  const __m128i* M = (__m128i*)m;
  __m128i* Mfin = (__m128i*)(m + m_padded_len - 64);

  state S = ctx->init;

  __m128i RR = STATE_0;
  __m128i R0 = STATE_0;
  __m128i R1 = STATE_0;
  __m128i R2 = STATE_0;
  // Main rounds
  for (; M < Mfin; M += 4) {
    ROUND(S, M[0], M[1], M[2], M[3], RR, R0, R1, R2);
  }

  // Last round (padding)
  ROUND(S, M_padding[0], M_padding[1], M_padding[2], M_padding[3], RR, R0, R1,
        R2);

  // Four final rounds to absorb message state
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);
  ROUND(S, STATE_0, STATE_0, STATE_0, STATE_0, RR, R0, R1, R2);

  return S;
}

void lemac_MAC(context* ctx, const uint8_t* nonce, const uint8_t* m,
               size_t mlen, uint8_t* tag) {
  state S = lemac_AU(ctx, m, mlen);
  const __m128i* N = (const __m128i*)nonce;

  __m128i T = *N ^ AES(ctx->keys[0], *N);
  T ^= AES_modified(ctx->subkeys, S.S[0]);
  T ^= AES_modified(ctx->subkeys + 1, S.S[1]);
  T ^= AES_modified(ctx->subkeys + 2, S.S[2]);
  T ^= AES_modified(ctx->subkeys + 3, S.S[3]);
  T ^= AES_modified(ctx->subkeys + 4, S.S[4]);
  T ^= AES_modified(ctx->subkeys + 5, S.S[5]);
  T ^= AES_modified(ctx->subkeys + 6, S.S[6]);
  T ^= AES_modified(ctx->subkeys + 7, S.S[7]);
  T ^= AES_modified(ctx->subkeys + 8, S.S[8]);

  *(__m128i*)tag = AES(ctx->keys[1], T);
}

LeMac::LeMac(std::span<const uint8_t, key_size> key) { init(key); }

LeMac::LeMac(std::span<const std::uint8_t> key) {
  if (key.size() != key_size) {
    throw std::runtime_error("wrong size of key");
  }
  init(key.first<key_size>());
}

void LeMac::reset() {
  m_state.s = m_context.init;
  m_state.r.reset();
  m_bufsize = 0;
}

void LeMac::init(std::span<const uint8_t, key_size> key) {
  context tmp;
  lemac_init(&tmp, key.data());
  std::memcpy(m_context.init.S, tmp.init.S, sizeof(Sstate));
  std::memcpy(m_context.keys, tmp.keys, sizeof(m_context.keys));
  std::memcpy(m_context.subkeys, tmp.subkeys, sizeof(m_context.subkeys));
  reset();
}

namespace {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
constexpr auto vector_register_alignment = std::alignment_of_v<__m128i>;
#pragma GCC diagnostic pop

// assumes no alignment
inline void process_block(LeMac::Sstate& S, LeMac::Rstate& R,
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
inline void process_aligned_block(LeMac::Sstate& S, LeMac::Rstate& R,
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

inline void process_zero_block(LeMac::Sstate& S, LeMac::Rstate& R) noexcept {
  const __m128i M = STATE_0;
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

void LeMac::update(std::span<const uint8_t> data) {

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
    __m128i T = N ^ AES(m_context.keys[0], N);
    T ^= AES_modified(m_context.subkeys, S.S[0]);
    T ^= AES_modified(m_context.subkeys + 1, S.S[1]);
    T ^= AES_modified(m_context.subkeys + 2, S.S[2]);
    T ^= AES_modified(m_context.subkeys + 3, S.S[3]);
    T ^= AES_modified(m_context.subkeys + 4, S.S[4]);
    T ^= AES_modified(m_context.subkeys + 5, S.S[5]);
    T ^= AES_modified(m_context.subkeys + 6, S.S[6]);
    T ^= AES_modified(m_context.subkeys + 7, S.S[7]);
    T ^= AES_modified(m_context.subkeys + 8, S.S[8]);

    const auto tag = AES(m_context.keys[1], T);
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
    __m128i T = N ^ AES(m_context.keys[0], N);
    T ^= AES_modified(m_context.subkeys, S.S[0]);
    T ^= AES_modified(m_context.subkeys + 1, S.S[1]);
    T ^= AES_modified(m_context.subkeys + 2, S.S[2]);
    T ^= AES_modified(m_context.subkeys + 3, S.S[3]);
    T ^= AES_modified(m_context.subkeys + 4, S.S[4]);
    T ^= AES_modified(m_context.subkeys + 5, S.S[5]);
    T ^= AES_modified(m_context.subkeys + 6, S.S[6]);
    T ^= AES_modified(m_context.subkeys + 7, S.S[7]);
    T ^= AES_modified(m_context.subkeys + 8, S.S[8]);

    const auto tag = AES(m_context.keys[1], T);
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

  __m128i T = N ^ AES(context.keys[0], N);
  T ^= AES_modified(context.subkeys, S.S[0]);
  T ^= AES_modified(context.subkeys + 1, S.S[1]);
  T ^= AES_modified(context.subkeys + 2, S.S[2]);
  T ^= AES_modified(context.subkeys + 3, S.S[3]);
  T ^= AES_modified(context.subkeys + 4, S.S[4]);
  T ^= AES_modified(context.subkeys + 5, S.S[5]);
  T ^= AES_modified(context.subkeys + 6, S.S[6]);
  T ^= AES_modified(context.subkeys + 7, S.S[7]);
  T ^= AES_modified(context.subkeys + 8, S.S[8]);

  const auto tag = AES(context.keys[1], T);
  _mm_storeu_si128((__m128i*)target.data(), tag);
}
