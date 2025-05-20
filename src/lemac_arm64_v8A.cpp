#include "lemac_arm64_v8A.h"
#include "lemac.h"
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
  constexpr auto N = 4;
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
  fmt::print("{}\n", label);
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      fmt::print("{:02x} |", +tmp[i + j * 4]);
    }
    fmt::print("{}\n", "");
  }
  std::cout.flush();
}

uint8x16_t AES128(std::span<uint8x16_t, 11> roundkeys, uint8x16_t x) {
  // see Algorithm 1 in FIPS-197
  print("input data", x);
  for (int round = 1; round < 10; ++round) {
    // vaeseq_u8 is subbytes(shiftrows(a^b))
    x = vaeseq_u8(x, roundkeys[round - 1]);
    print("after addround, shiftrow, subbytes:", x);
    // mixcolumns
    x = vaesmcq_u8(x);
    print("after mixcolumns", x);
  }
  // subbytes(shiftrows(addround))
  x = vaeseq_u8(x, roundkeys[9]);
  // addround
  x = veorq_u8(x, roundkeys[10]);
  print("when finished", x);
  return x;
}

void init(std::span<const uint8_t, key_size> key, detail::LeMacContext& ctx) {
  uint8x16_t Ki[11];
  AES128_keyschedule(vld1q_u8(key.data()), Ki);
  // constexpr std::array<std::uint8_t, 16> input = {
  //     0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
  //     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  // auto encrypted = AES128(Ki, vld1q_u8(input.data()));
}

} // namespace

LemacArm64v8A::LemacArm64v8A() noexcept : LemacArm64v8A(zeros) {}

LemacArm64v8A::LemacArm64v8A(std::span<const uint8_t, key_size> key) noexcept {
  init(key, m_context);
}

std::unique_ptr<detail::ImplInterface> LemacArm64v8A::clone() const noexcept {
  return std::make_unique<LemacArm64v8A>(*this);
}

void LemacArm64v8A::update(std::span<const uint8_t> data) noexcept { return; }

void LemacArm64v8A::finalize_to(std::span<const uint8_t> nonce,
                                std::span<uint8_t, 16> target) noexcept {}

std::array<uint8_t, 16>
LemacArm64v8A::oneshot(std::span<const uint8_t> data,
                       std::span<const uint8_t> nonce) const noexcept {
  return {};
}

void LemacArm64v8A::reset() noexcept {}

std::unique_ptr<detail::ImplInterface> make_arm64_v8A() {
  return std::make_unique<LemacArm64v8A>();
}

std::unique_ptr<detail::ImplInterface>
make_arm64_v8A(std::span<const uint8_t, key_size> key) {
  return std::make_unique<LemacArm64v8A>(key);
}

} // namespace lemac::inline v1
