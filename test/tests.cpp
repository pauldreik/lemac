
#include <cassert>
#include <iostream>
#include <numeric>
#include <span>

#include <cstdint>
#include <stdint.h>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <lemac.h>

/*
 * from running ./test_vectors.py, taken from
https://github.com/AugustinBariant/Implementations_LeMac_PetitMac/blob/main/test_vectors.py
Key     : 00000000000000000000000000000000
Nonce   : 00000000000000000000000000000000
Message :
LeMac-0 : d93e95c08ef1f63264d925c3210112b7
LeMac   : 52282e853c9cfeb5537d33fb916a341f
PetitMac: 6c8f75e007cdbbc6f3fda1dc67be2b44

Key     : 00000000000000000000000000000000
Nonce   : 00000000000000000000000000000000
Message : 00000000000000000000000000000000
LeMac-0 : 8131c19f27648120bf3ccc3286b2a6e5
LeMac   : 26fa471b77facc73ec2f9b50bb1af864
PetitMac: c276ff7007cd9b54746d77bc501ca8f5

Key     : 000102030405060708090a0b0c0d0e0f
Nonce   : 000102030405060708090a0b0c0d0e0f
Message :
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
LeMac-0 : 21d650c1e6ef1bdce57a79e54ef4bbde
LeMac   : d58dfdbe8b0224e1d5106ac4d775beef
PetitMac: 2a7a9626edf82f6cbde155075e426f87
*/

namespace {
std::string tohex(std::span<const std::uint8_t> binary) {
  std::string ret;
  char buf[3];
  for (auto c : binary) {
    std::sprintf(buf, "%02x", (unsigned char)c);
    ret.append(buf);
  }
  return ret;
}
} // namespace

TEST_CASE("recreate test vector with zero nonce, key and empty input") {
  constexpr auto MSIZE = 0;

  uint8_t M[1] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};
  uint8_t T[16] = {};

  context ctx;
  lemac_init(&ctx, K);

  // Blank computation
  lemac_MAC(&ctx, N, M, MSIZE, T);
  std::cout << "Key=" << tohex(std::span(K, sizeof(K))) << '\n';
  std::cout << "Nonce=" << tohex(std::span(N, sizeof(N))) << '\n';
  std::cout << "Message=" << MSIZE << " zeros\n";
  const auto lemac = tohex(std::span(T, sizeof(T)));
  std::cout << "LeMac=" << lemac << '\n';
  const std::string expected = "52282e853c9cfeb5537d33fb916a341f";
  REQUIRE(expected == lemac);
}

TEST_CASE("alternate api - empty input") {
  LeMac lm;
  constexpr auto MSIZE = 0;

  uint8_t M[1] = {};
  lm.update(std::span(M, MSIZE));
  const std::string expected = "52282e853c9cfeb5537d33fb916a341f";
  const auto actual = tohex(lm.finalize());
  REQUIRE(expected == actual);
}

TEST_CASE("recreate test vector with zero nonce, key and 16 zeros as input") {
  constexpr auto MSIZE = 16;

  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};
  uint8_t T[16] = {};

  context ctx;
  lemac_init(&ctx, K);

  // Blank computation
  lemac_MAC(&ctx, N, M, MSIZE, T);
  std::cout << "Key=" << tohex(std::span(K, sizeof(K))) << '\n';
  std::cout << "Nonce=" << tohex(std::span(N, sizeof(N))) << '\n';
  std::cout << "Message=" << MSIZE << " zeros\n";
  const auto lemac = tohex(std::span(T, sizeof(T)));
  std::cout << "LeMac=" << lemac << '\n';
  const std::string expected = "26fa471b77facc73ec2f9b50bb1af864";
  REQUIRE(expected == lemac);
}

TEST_CASE("alternate api - 16 zeros input") {
  LeMac lm;
  constexpr auto MSIZE = 16;

  uint8_t M[MSIZE] = {};
  lm.update(std::span(M, MSIZE));
  const std::string expected = "26fa471b77facc73ec2f9b50bb1af864";
  const auto actual = tohex(lm.finalize());
  REQUIRE(expected == actual);
}

TEST_CASE("oneshot - 16 zeros input") {
  LeMac lm;
  constexpr auto MSIZE = 16;

  uint8_t M[MSIZE] = {};

  const std::string expected = "26fa471b77facc73ec2f9b50bb1af864";
  const auto actual = tohex(lm.oneshot(std::span(M, MSIZE)));
  REQUIRE(expected == actual);
}

TEST_CASE("oneshot - 1 zero input") {
  LeMac lm;
  constexpr auto MSIZE = 1;

  uint8_t M[MSIZE] = {};
  lm.update(std::span(M, MSIZE));
  const auto update_and_finalize = tohex(lm.finalize());
  const auto oneshot = tohex(LeMac{}.oneshot(std::span(M, MSIZE)));
  REQUIRE(update_and_finalize == oneshot);
}

TEST_CASE("the hasher can be reset") {
  const std::vector<std::uint8_t> data{0x20, 0x42};
  LeMac lemac;
  lemac.update(data);
  const auto first_round = lemac.finalize();
  lemac.reset();
  lemac.update(data);
  const auto second_round = lemac.finalize();
  REQUIRE(first_round == second_round);
}

TEST_CASE("recreate test vector with iota nonce, key and input") {
  constexpr auto MSIZE = 65;

  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};
  uint8_t T[16] = {};

  std::iota(std::begin(M), std::end(M), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  context ctx;
  lemac_init(&ctx, K);

  // Blank computation
  lemac_MAC(&ctx, N, M, MSIZE, T);
  std::cout << "Key=" << tohex(std::span(K, sizeof(K))) << '\n';
  std::cout << "Nonce=" << tohex(std::span(N, sizeof(N))) << '\n';
  std::cout << "Message=std::iota(" << MSIZE << ")\n";
  const auto lemac = tohex(std::span(T, sizeof(T)));
  std::cout << "LeMac=" << lemac << '\n';
  const std::string expected = "d58dfdbe8b0224e1d5106ac4d775beef";
  REQUIRE(expected == lemac);
}

TEST_CASE("alternate api - iota nonces,key,input") {
  constexpr auto MSIZE = 65;

  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};

  std::iota(std::begin(M), std::end(M), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  LeMac lm(std::span(K, 16));
  lm.update(std::span(M, MSIZE));
  const std::string expected = "d58dfdbe8b0224e1d5106ac4d775beef";
  const auto actual = tohex(lm.finalize(std::span(N, 16)));
  REQUIRE(expected == actual);

  REQUIRE(tohex(LeMac{std::span(K, 16)}.oneshot(std::span(M, MSIZE),
                                                std::span(N, 16))) == expected);
}

TEST_CASE("empty input") {
  std::vector<std::uint8_t> nodata;
  // test multiple ways
  const auto a = LeMac{}.oneshot(nodata);
  LeMac lemac;
  lemac.update(nodata);
  const auto b = lemac.finalize();
  lemac.reset();
  lemac.update(nodata);
  const auto c = lemac.finalize();
  const auto d = LeMac{}.finalize();

  REQUIRE(a == b);
  REQUIRE(a == c);
  REQUIRE(a == d);
}

TEST_CASE("partial updates") {
  constexpr auto MSIZE = 65;

  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};

  std::iota(std::begin(M), std::end(M), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  LeMac lm(std::span(K, 16));

  auto inputdata = std::span(M, MSIZE);
  const auto bytes_at_a_time = GENERATE(1uz, 2uz, 64uz, 65uz, 128uz);
  while (!inputdata.empty()) {
    const auto consumed = std::min(bytes_at_a_time, inputdata.size());
    lm.update(inputdata.first(consumed));
    inputdata = inputdata.subspan(consumed);
  }

  const std::string expected = "d58dfdbe8b0224e1d5106ac4d775beef";
  const auto actual = tohex(lm.finalize(std::span(N, 16)));
  REQUIRE(expected == actual);
}

namespace {
class unaligned_buf {
public:
  unaligned_buf(std::size_t misalignment, std::size_t size)
      : m_misalignment(misalignment), m_storage(misalignment + size) {}
  auto get() { return std::span(m_storage).subspan(m_misalignment); }

private:
  std::size_t m_misalignment;
  std::vector<std::uint8_t> m_storage;
};
} // namespace

TEST_CASE("unaligned access") {
  constexpr auto MSIZE = 65;

  const auto alignment = GENERATE(0uz, 1uz, 2uz, 15uz);

  auto M = unaligned_buf(alignment, MSIZE);
  auto inputdata = M.get();

  auto N_ = unaligned_buf(alignment, 16);
  auto N = N_.get();
  auto K_ = unaligned_buf(alignment, 16);
  auto K = K_.get();

  std::iota(std::begin(inputdata), std::end(inputdata), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  LeMac lm(K);

  const auto bytes_at_a_time = GENERATE(1uz, 2uz, 64uz, 65uz, 128uz);
  while (!inputdata.empty()) {
    const auto consumed = std::min(bytes_at_a_time, inputdata.size());
    lm.update(inputdata.first(consumed));
    inputdata = inputdata.subspan(consumed);
  }

  const std::string expected = "d58dfdbe8b0224e1d5106ac4d775beef";
  const auto actual = tohex(lm.finalize(N));
  REQUIRE(expected == actual);

  REQUIRE(tohex(LeMac{K}.oneshot(M.get(), N)) == expected);
}

namespace {
template <std::size_t MSIZE> void benchmark() {
  // 5 µs * ~4 GHz / 256 kB = 0.078 cycles/byte on zen 4(claimed in paper on
  // zen3: 0.072)
  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};
  uint8_t T[16] = {};

  std::iota(std::begin(M), std::end(M), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  {
    LeMac lemac(std::span(K, 16));
    BENCHMARK("C++ implementation without init") {
      lemac.reset();
      lemac.update(std::span(M));
      const auto tmp = lemac.finalize(std::span(N));
      M[0] = tmp[0];
      return tmp[0];
    };
  }

  {
    LeMac lemac(std::span(K, 16));
    BENCHMARK("C++ oneshot") {
      // lemac.reset();
      const auto tmp = lemac.oneshot(std::span(M), std::span(N));
      M[0] = tmp[0];
      return tmp[0];
    };
  }

  {
    context ctx;
    lemac_init(&ctx, K);
    BENCHMARK("original implementation without init") {
      lemac_MAC(&ctx, N, M, MSIZE, T);
      M[0] = T[0];
      return T[0];
    };
  }
}
} // namespace
TEST_CASE("benchmark 1 byte", "[.][benchmark]") { benchmark<1>(); }
TEST_CASE("benchmark 1 kByte", "[.][benchmark]") { benchmark<1 * 1024>(); }
TEST_CASE("benchmark 4 kByte", "[.][benchmark]") { benchmark<4 * 1024>(); }
TEST_CASE("benchmark 16 kByte", "[.][benchmark]") { benchmark<16 * 1024>(); }
TEST_CASE("benchmark 64 kByte", "[.][benchmark]") { benchmark<64 * 1024>(); }
TEST_CASE("benchmark 256 kByte", "[.][benchmark]") { benchmark<256 * 1024>(); }
