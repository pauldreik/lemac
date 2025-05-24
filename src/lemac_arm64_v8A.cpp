#include "lemac_arm64_v8A.h"
#include "lemac.h"
#include <cassert>
#include <fmt/core.h>
#include <iostream>

// this was useful for understanding how to work with neon:
// http://const.me/articles/simd/NEON.pdf

namespace lemac::inline v1 {

namespace {
/// zeros which can be used as a key or a nonce
static constexpr std::array<const std::uint8_t, key_size> zeros{};

// based on
// https://en.wikipedia.org/wiki/Rijndael_S-box#Example_implementation_in_C_language
constexpr std::array<std::uint8_t, 256> calculate_sbox() {
  std::array<std::uint8_t, 256> sbox;
  std::uint8_t p = 1;
  std::uint8_t q = 1;

  /* loop invariant: p * q == 1 in the Galois field */
  do {
    /* multiply p by 3 */
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

    /* divide q by 3 (equals multiplication by 0xf6) */
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= q & 0x80 ? 0x09 : 0;

    /* compute the affine transformation */
    auto ROTL8 = [](auto x, auto shift) {
      return (x << shift) | (x >> (8 - shift));
    };
    const std::uint8_t xformed =
        q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

    sbox[p] = xformed ^ 0x63;
  } while (p != 1);

  /* 0 is a special case since it has no inverse */
  sbox[0] = 0x63;
  return sbox;
}

static constexpr std::array<std::uint8_t, 256> sbox = calculate_sbox();

std::uint32_t ROTWORD(std::uint32_t x) { return std::rotl(x, 8); }
std::uint32_t SUBWORD(std::uint32_t x) {
  return ((sbox[x >> 0 & 0xFF]) << 0) | ((sbox[x >> 8 & 0xFF]) << 8) |
         ((sbox[x >> 16 & 0xFF]) << 16) | ((sbox[x >> 24 & 0xFF]) << 24);
}
void AES128_keyschedule(const uint8x16_t K,
                        std::span<uint8x16_t, 11> roundkeys) {

  static_assert(std::endian::native == std::endian::little,
                "code assumes little endian");

  // following the notation on
  // https://en.wikipedia.org/wiki/AES_key_schedule#The_key_schedule
  // and the FIPS-197 document at
  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf

  // number of 32 bit words (4 for AES-128)
  constexpr auto Nk = 4;

  // number of round keys needed (11 for AES-128)
  constexpr auto R = 11;
  static_assert(roundkeys.size() == R);

  // convert K to four little endian uint32
  const auto K_le = vreinterpretq_u32_u8(vrev32q_u8(K));

  static constexpr std::array<std::uint8_t, 11> Rcon{
      0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

  std::array<std::uint32_t, 4 * R> W;

  for (int i = 0; i < 4 * R; ++i) {
    std::uint32_t& Wi = W[i];
    if (i == 0) {
      Wi = vgetq_lane_u32(K_le, 0);
    } else if (i == 1) {
      Wi = vgetq_lane_u32(K_le, 1);
    } else if (i == 2) {
      Wi = vgetq_lane_u32(K_le, 2);
    } else if (i == 3) {
      Wi = vgetq_lane_u32(K_le, 3);
    } else {
      auto temp = W[i - 1];
      if (i % Nk == 0) {
        const auto after_rotword = ROTWORD(temp);
        const auto after_subword = SUBWORD(after_rotword);
        const auto after_rcon = after_subword ^ (Rcon[i / Nk] << 24);
        temp = after_rcon;
      } else if (Nk > 6 && (i % Nk == 4)) {
        temp = SUBWORD(temp);
      }
      Wi = W[i - Nk] ^ temp;
    }
  }
  // copy round keys to output, in big endian
  for (int i = 0; i < 4 * R; i += 4) {
    roundkeys[i / 4] =
        vrev32q_u8(vld1q_u8(reinterpret_cast<const std::uint8_t*>(&W[i])));
  }
}

void print(auto label, uint8x16_t x) {
  std::array<std::uint8_t, 16> tmp;
  vst1q_u8(tmp.data(), x);
  fmt::println("{}", label);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      fmt::print("{:02x} |", +tmp[i + j * 4]);
    }
    fmt::println("{}", "");
  }
  std::cout.flush();
}

uint8x16_t AES128(std::span<const uint8x16_t, 11> roundkeys, uint8x16_t x) {
  // see Algorithm 1 in FIPS-197
  // print("input data", x);
  for (int round = 1; round < 10; ++round) {
    // vaeseq_u8 is subbytes(shiftrows(a^b))
    x = vaeseq_u8(x, roundkeys[round - 1]);
    // print("after addround, shiftrow, subbytes:", x);
    //  mixcolumns
    x = vaesmcq_u8(x);
    // print("after mixcolumns", x);
  }
  // subbytes(shiftrows(addround))
  x = vaeseq_u8(x, roundkeys[9]);
  // addround
  x = veorq_u8(x, roundkeys[10]);
  // print("when finished", x);
  return x;
}

uint8x16_t AES128_modified(std::span<const uint8x16_t, 11> roundkeys,
                           uint8x16_t x) {
  // see Algorithm 1 in FIPS-197
  // print("input data", x);
  for (int round = 1; round < 10; ++round) {
    // vaeseq_u8 is subbytes(shiftrows(a^b))
    x = vaeseq_u8(x, roundkeys[round - 1]);
    // print("after addround, shiftrow, subbytes:", x);
    //  mixcolumns
    x = vaesmcq_u8(x);
    // print("after mixcolumns", x);
  }
  // subbytes(shiftrows(addround))
  x = vaeseq_u8(x, roundkeys[9]);
  // mixcolumn instead of addround
  x = vaesmcq_u8(x);
  return x;
}

void init(std::span<const uint8_t, key_size> key, detail::LeMacContext& ctx) {
  uint8x16_t Ki[11];
  AES128_keyschedule(vld1q_u8(key.data()), Ki);
  // constexpr std::array<std::uint8_t, 16> input = {
  //     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
  //     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  // auto encrypted = AES128(Ki, vld1q_u8(input.data()));

  // Kinit 0 --> 8
  for (std::uint64_t i = 0; i < std::size(ctx.init.S); ++i) {
    ctx.init.S[i] = AES128(
        Ki, vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(i), vcreate_u64(0))));
  }

  // Kinit 9 --> 26
  for (std::uint64_t i = 0; i < std::size(ctx.subkeys); ++i) {
    ctx.subkeys[i] = AES128(
        Ki, vreinterpretq_u8_u64(vcombine_u64(
                vcreate_u64(i + std::size(ctx.init.S)), vcreate_u64(0))));
  }

  // k2 27
  AES128_keyschedule(AES128(Ki, vreinterpretq_u8_u64(vcombine_u64(
                                    vcreate_u64(std::size(ctx.init.S) +
                                                std::size(ctx.subkeys)),
                                    vcreate_u64(0)))),
                     ctx.keys[0]);

  // k3 28
  AES128_keyschedule(AES128(Ki, vreinterpretq_u8_u64(vcombine_u64(
                                    vcreate_u64(std::size(ctx.init.S) +
                                                std::size(ctx.subkeys) + 1),
                                    vcreate_u64(0)))),
                     ctx.keys[1]);
}

// does what _mm_aesenc_si128 does
uint8x16_t aesenc(uint8x16_t v, uint8x16_t round_key) {
  //_mm_aesenc_si128 does:
  // round_key^mixcolumns(subbytes(shiftrows(v)))
  // vaeseq_u8 is subbytes(shiftrows(a^b))
  const uint8x16_t zero =
      vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(0), vcreate_u64(0)));
  v = vaeseq_u8(v, zero);
  v = vaesmcq_u8(v);
  v = veorq_u8(v, round_key);
  return v;
}

void process_block(detail::Sstate& S, detail::Rstate& R,
                   const std::uint8_t* ptr) noexcept {
  const auto M0 = vld1q_u8(ptr + 0);
  const auto M1 = vld1q_u8(ptr + 16);
  const auto M2 = vld1q_u8(ptr + 32);
  const auto M3 = vld1q_u8(ptr + 48);

  uint8x16_t T = S.S[8];
  S.S[8] = aesenc(S.S[7], M3);
  S.S[7] = aesenc(S.S[6], M1);
  S.S[6] = aesenc(S.S[5], M1);
  S.S[5] = aesenc(S.S[4], M0);

  S.S[4] = aesenc(S.S[3], M0);
  S.S[3] = aesenc(S.S[2], R.R1 ^ R.R2);
  S.S[2] = aesenc(S.S[1], M3);
  S.S[1] = aesenc(S.S[0], M3);
  S.S[0] = S.S[0] ^ T ^ M2;
  R.R2 = R.R1;
  R.R1 = R.R0;
  R.R0 = R.RR ^ M1;
  R.RR = M2;
}

void process_zero_block(detail::Sstate& S, detail::Rstate& R) noexcept {
  const uint8x16_t zero =
      vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(0), vcreate_u64(0)));
  const auto M0 = zero;
  const auto M1 = zero;
  const auto M2 = zero;
  const auto M3 = zero;

  uint8x16_t T = S.S[8];
  S.S[8] = aesenc(S.S[7], M3);
  S.S[7] = aesenc(S.S[6], M1);
  S.S[6] = aesenc(S.S[5], M1);
  S.S[5] = aesenc(S.S[4], M0);

  S.S[4] = aesenc(S.S[3], M0);
  S.S[3] = aesenc(S.S[2], R.R1 ^ R.R2);
  S.S[2] = aesenc(S.S[1], M3);
  S.S[1] = aesenc(S.S[0], M3);
  S.S[0] = S.S[0] ^ T /*^ M2*/;
  R.R2 = R.R1;
  R.R1 = R.R0;
  R.R0 = R.RR /*^ M1*/;
  R.RR = M2;
}
} // namespace

LemacArm64v8A::LemacArm64v8A() noexcept : LemacArm64v8A(zeros) {}

LemacArm64v8A::LemacArm64v8A(std::span<const uint8_t, key_size> key) noexcept {
  init(key, m_context);
}

std::unique_ptr<detail::ImplInterface> LemacArm64v8A::clone() const noexcept {
  return std::make_unique<LemacArm64v8A>(*this);
}

void LemacArm64v8A::update(std::span<const uint8_t> data) noexcept {

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

  // operate on a copy of the state and write it back later
  auto state = m_state;

  if (process_entire_m_buf) {
    // process the entire block
    std::memcpy(&m_buf[m_bufsize], data.data(), remaining_to_full_block);

    process_block(state.s, state.r, m_buf.data());
    m_bufsize = 0;
    data = data.subspan(remaining_to_full_block);
  }

  // process whole blocks
  const auto whole_blocks = data.size() / block_size;
  const auto block_end = data.data() + whole_blocks * block_size;

  auto ptr = data.data();

  for (; ptr != block_end; ptr += block_size) {
    process_block(state.s, state.r, ptr);
  }
  m_state = state;

  // write the tail into m_buf
  m_bufsize = data.size() - whole_blocks * block_size;
  if (m_bufsize) {
    std::memcpy(m_buf.data(), ptr, m_bufsize);
  }
}

void LemacArm64v8A::finalize_to(std::span<const uint8_t> nonce,
                                std::span<uint8_t, 16> target) noexcept {
  // let m_buf be padded
  assert(m_bufsize < m_buf.size());
  m_buf[m_bufsize] = 1;
  for (std::size_t i = m_bufsize + 1; i < m_buf.size(); ++i) {
    m_buf[i] = 0;
  }

  process_block(m_state.s, m_state.r, m_buf.data());

  // Four final rounds to absorb message state
  for (int i = 0; i < 4; ++i) {
    process_zero_block(m_state.s, m_state.r);
  }

  assert(nonce.size() == 16);

  const auto N = vld1q_u8(nonce.data());

  auto& S = m_state.s;
  uint8x16_t T = N ^ AES128(m_context.keys[0], N);
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
  vst1q_u8(target.data(), tag);
}

std::array<uint8_t, 16>
LemacArm64v8A::oneshot(std::span<const uint8_t> data,
                       std::span<const uint8_t> nonce) const noexcept {
  auto copy = *this;
  copy.reset();
  copy.update(data);
  std::array<uint8_t, 16> ret;
  copy.finalize_to(nonce, ret);
  return ret;
}

void LemacArm64v8A::reset() noexcept {
  m_state.s = m_context.init;
  m_state.r.reset();
  m_bufsize = 0;
}
#ifdef LEMAC_INTERNAL_STATE_VISIBILITY
namespace {
std::string to_string(const uint8x16_t x) {
  std::array<unsigned char, 16> binary;
  vst1q_u8(binary.data(), x);
  std::string ret(32, '\0');
  char buf[3];
  for (std::size_t i = 0; auto c : binary) {
    std::sprintf(buf, "%02x", c);
    ret[i + 0] = buf[0];
    ret[i + 1] = buf[1];
    i += 2;
  }
  return ret;
}

std::string to_state(const detail::Sstate& sstate) {
  std::string ret("S[9]:\n");
  for (const auto& e : sstate.S) {
    ret += to_string(e);
    ret.push_back('\n');
  }
  return ret;
}

std::string to_state(const detail::LeMacContext& context) {
  std::string ret("context:\n");
  ret += to_state(context.init);
  ret += "keys[0]:\n";
  for (const auto& k : context.keys[0]) {
    ret += to_string(k);
    ret.push_back('\n');
  }
  ret += "keys[1]:\n";
  for (const auto& k : context.keys[0]) {
    ret += to_string(k);
    ret.push_back('\n');
  }
  ret += "subkeys:\n";
  for (const auto& k : context.subkeys) {
    ret += to_string(k);
    ret.push_back('\n');
  }
  
  return ret;
}
} // namespace
std::string LemacArm64v8A::get_internal_state() const noexcept {
  std::string ret;
  ret = to_state(m_context);
  return ret;
}
#endif

std::unique_ptr<detail::ImplInterface> make_arm64_v8A() {
  return std::make_unique<LemacArm64v8A>();
}

std::unique_ptr<detail::ImplInterface>
make_arm64_v8A(std::span<const uint8_t, key_size> key) {
  return std::make_unique<LemacArm64v8A>(key);
}

void detail::Rstate::reset() { std::memset(this, 0, sizeof(*this)); }

} // namespace lemac::inline v1
