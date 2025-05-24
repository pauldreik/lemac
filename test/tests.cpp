#include <cassert>
#include <cstdint>
#include <numeric>
#include <span>

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

TEST_CASE("FIPS 107-upd1 AES-128 appendix A.1 test vectors") {

  constexpr std::array<std::uint8_t, 16> Key = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  lemac::LeMac lm(Key);
#ifdef LEMAC_INTERNAL_STATE_VISIBILITY
  auto s = lm.get_internal_state();
  const auto expected = "context:\n"
                        "S[9]:\n"
                        "7df76b0c1ab899b33e42f047b91b546f\n"
                        "7e59379b5233969d25a5ad2ce335cb3e\n"
                        "1fb0c23bd209ac911ee3ab8a2d85ebcd\n"
                        "c24bfea9b560ce46c787e9ed29e7160f\n"
                        "cda43d7c6c56b627a96930a1f0b9916b\n"
                        "c936b3351ac001f736169eb1a0b202c0\n"
                        "2ef95bd96883ef6682c2de66c7763a24\n"
                        "4c5a8bbf09e3c38c43573d56c33f83a9\n"
                        "676a46366cdb5d282e2b55dfa073baa8\n"
                        "keys[0]:\n"
                        "65cce56bc727a71ac624826d3ebb98b5\n"
                        "8e8a30d949ad97c38f8915aeb1328d1b\n"
                        "afd79f11e67a08d269f31d7cd8c19067\n"
                        "d3b71a7035cd12a25c3e0fde84ff9fb9\n"
                        "cd6c4c2ff8a15e8da49f51532060ceea\n"
                        "0de7cb98f546951551d9c44671b90aac\n"
                        "7b805a3b8ec6cf2edf1f0b68aea601c4\n"
                        "1ffc46df913a89f14e258299e083835d\n"
                        "73100a3ee22a83cfac0f01564c8c820b\n"
                        "0c032117ee29a2d84226a38e0eaa2185\n"
                        "96feb6bc78d714643af1b7ea345b966f\n"
                        "keys[1]:\n"
                        "4b665e0bba677ecc604e85fc453ecaf2\n"
                        "f812d7654275a9a9223b2c556705e6a7\n"
                        "919c8be0d3e92249f1d20e1c96d7e8bb\n"
                        "9b07617048ee4339b93c4d252feba59e\n"
                        "7a016a6532ef295c8bd36479a438c1e7\n"
                        "6d79fe2c5f96d770d445b309707d72ee\n"
                        "b239d67dedaf010d39eab2044997c0ea\n"
                        "7a835146972c504baec6e24fe75122a5\n"
                        "2b1057d2bc3c079912fae5d6f5abc773\n"
                        "52d6d834eeeadfadfc103a7b09bbfd08\n"
                        "8e82e835606837989c780de395c3f0eb\n"
                        "subkeys:\n"
                        "d3f3216ed0cac29f0f23066109064795\n"
                        "d5cec70189949e081a44a8fca8c97799\n"
                        "4ce59246ba7525da79d38acb43787971\n"
                        "70c21702154259fc6ab68098c7dfe542\n"
                        "dde376ac05df9f0ba53bda80c22e2075\n"
                        "e5b1376fb2dbfafe8d903dd14a430b02\n"
                        "6be9cc106bca99b87736a0cfda45c426\n"
                        "898ee5c014f1f6abd4d6f7f688715998\n"
                        "762e195078da2db22502e8cd86f47eca\n"
                        "5c3774450533a712790e81365bf154ba\n"
                        "8813691f4d0cc00dc993ee71c612aa78\n"
                        "f70def612ff1ee6fa8b08faa7b81e7fe\n"
                        "4d3e057c1259435c7bc44e6920df2acf\n"
                        "faa252e2a67ac6b6fbff1bdf4f45c37c\n"
                        "a3a70e5ce9ef14c65300d284eaa12ebd\n"
                        "2ad3f6815883ec2ecff12ef12fd301d1\n"
                        "be6f11b4c9b34e5c69cc32d9c211de2d\n"
                        "6171cdf9eb7cb6c7b97f05ede6626e54\n"
                        "";
  REQUIRE(s == expected);
#endif
}

TEST_CASE("empty input gives correct output") {
  lemac::LeMac lm;
  constexpr auto MSIZE = 0;

  uint8_t M[1] = {};
  lm.update(std::span(M, MSIZE));
  const std::string expected = "52282e853c9cfeb5537d33fb916a341f";
  const auto actual = tohex(lm.finalize());
  REQUIRE(expected == actual);
}

TEST_CASE("wrong size key causes an exception") {

  std::array<std::uint8_t, 15> wrong_size_key{};

  REQUIRE_THROWS(lemac::LeMac(wrong_size_key));
}

TEST_CASE("update+finalize: 16 zeros input") {
  lemac::LeMac lm;
  constexpr auto MSIZE = 16;

  uint8_t M[MSIZE] = {};
  lm.update(std::span(M, MSIZE));
  const std::string expected = "26fa471b77facc73ec2f9b50bb1af864";
  const auto actual = tohex(lm.finalize());
  REQUIRE(expected == actual);
}

TEST_CASE("oneshot - 16 zeros input") {
  lemac::LeMac lm;
  constexpr auto MSIZE = 16;

  uint8_t M[MSIZE] = {};

  const std::string expected = "26fa471b77facc73ec2f9b50bb1af864";
  const auto actual = tohex(lm.oneshot(std::span(M, MSIZE)));
  REQUIRE(expected == actual);
}

TEST_CASE("oneshot - 1 zero input") {
  lemac::LeMac lm;
  constexpr auto MSIZE = 1;

  uint8_t M[MSIZE] = {};
  lm.update(std::span(M, MSIZE));
  const auto update_and_finalize = tohex(lm.finalize());
  const auto oneshot = tohex(lemac::LeMac{}.oneshot(std::span(M, MSIZE)));
  REQUIRE(update_and_finalize == oneshot);
}

TEST_CASE("the hasher can be reset") {
  const std::vector<std::uint8_t> data{0x20, 0x42};
  lemac::LeMac lemac;
  lemac.update(data);
  const auto first_round = lemac.finalize();
  lemac.reset();
  lemac.update(data);
  const auto second_round = lemac.finalize();
  REQUIRE(first_round == second_round);
}

TEST_CASE("65 byte input - iota nonces,key,input") {
  constexpr auto MSIZE = 65;

  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};

  std::iota(std::begin(M), std::end(M), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  lemac::LeMac lm(std::span(K, 16));
  lm.update(std::span(M, MSIZE));
  const std::string expected = "d58dfdbe8b0224e1d5106ac4d775beef";
  const auto actual = tohex(lm.finalize(std::span(N, 16)));
  REQUIRE(expected == actual);

  REQUIRE(tohex(lemac::LeMac{std::span(K, 16)}.oneshot(
              std::span(M, MSIZE), std::span(N, 16))) == expected);
}

TEST_CASE("empty input") {
  std::vector<std::uint8_t> nodata;
  // test multiple ways
  const auto a = lemac::LeMac{}.oneshot(nodata);
  lemac::LeMac lemac;
  lemac.update(nodata);
  const auto b = lemac.finalize();
  lemac.reset();
  lemac.update(nodata);
  const auto c = lemac.finalize();
  const auto d = lemac::LeMac{}.finalize();

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

  lemac::LeMac lm(std::span(K, 16));

  auto inputdata = std::span(M, MSIZE);
  const std::size_t bytes_at_a_time = GENERATE(1u, 2u, 64u, 65u, 128u);
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

  const std::size_t alignment = GENERATE(0u, 1u, 2u, 15u);

  auto M = unaligned_buf(alignment, MSIZE);
  auto inputdata = M.get();

  auto N_ = unaligned_buf(alignment, 16);
  auto N = N_.get();
  auto K_ = unaligned_buf(alignment, 16);
  auto K = K_.get();

  std::iota(std::begin(inputdata), std::end(inputdata), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  lemac::LeMac lm(K);

  const std::size_t bytes_at_a_time = GENERATE(1u, 2u, 64u, 65u, 128u);
  while (!inputdata.empty()) {
    const auto consumed = std::min(bytes_at_a_time, inputdata.size());
    lm.update(inputdata.first(consumed));
    inputdata = inputdata.subspan(consumed);
  }

  const std::string expected = "d58dfdbe8b0224e1d5106ac4d775beef";
  const auto actual = tohex(lm.finalize(N));
  REQUIRE(expected == actual);

  REQUIRE(tohex(lemac::LeMac{K}.oneshot(M.get(), N)) == expected);
}

TEST_CASE("hash can be copied and moved") {
  const std::array<std::uint8_t, 16> key{1, 2, 3};
  const std::array<std::uint8_t, 16> nonce_a{4, 5, 6};
  const std::array<std::uint8_t, 16> nonce_b{7, 8, 9};
  const std::array<std::uint8_t, 123> data_a{'a'};
  const std::array<std::uint8_t, 123> data_b{'b'};

  lemac::LeMac original(key);
  const auto aa = original.oneshot(data_a, nonce_a);
  const auto ab = original.oneshot(data_a, nonce_b);
  const auto ba = original.oneshot(data_b, nonce_a);
  const auto bb = original.oneshot(data_b, nonce_b);
  REQUIRE(aa != ab);
  REQUIRE(aa != ba);
  REQUIRE(aa != bb);
  {
    // make a copy and update them with different data
    auto copy = original;
    original.update(data_a);
    copy.update(data_b);
    const auto actual = original.finalize(nonce_a);
    REQUIRE(actual == aa);
    REQUIRE(ba == copy.finalize(nonce_a));
  }
  {
    // move the original and make sure the moved to object behaves identical
    lemac::LeMac moved_to;
    moved_to = std::move(original);
    REQUIRE(bb == moved_to.oneshot(data_b, nonce_b));
  }
}

namespace {
template <std::size_t MSIZE> void benchmark() {
  uint8_t M[MSIZE] = {};
  uint8_t N[16] = {};
  uint8_t K[16] = {};

  std::iota(std::begin(M), std::end(M), 0);
  std::iota(std::begin(N), std::end(N), 0);
  std::iota(std::begin(K), std::end(K), 0);

  {
    lemac::LeMac lemac(std::span(K, 16));
    BENCHMARK("C++ implementation without init") {
      lemac.reset();
      lemac.update(std::span(M));
      const auto tmp = lemac.finalize(std::span(N));
      M[0] = tmp[0];
      return tmp[0];
    };
  }

  {
    lemac::LeMac lemac(std::span(K, 16));
    BENCHMARK("C++ oneshot") {
      lemac.reset();
      const auto tmp = lemac.oneshot(std::span(M), std::span(N));
      M[0] = tmp[0];
      return tmp[0];
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

TEST_CASE("benchmark init", "[.][benchmark]") {
  BENCHMARK("only init") {
    lemac::LeMac l;
    return reinterpret_cast<const char*>(&l)[0];
  };
}
