#include <cassert>
#include <iostream>

#include <cstdint>
#include <stdint.h>

#include <lemac.h>

#include <span>

std::string tohex(std::span<const std::uint8_t> binary) {
  std::string ret;
  char buf[3];
  for (auto c : binary) {
    std::sprintf(buf, "%02x", (unsigned char)c);
    ret.append(buf);
  }
  return ret;
}

int main() {

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
  const auto lemac = tohex(std::span(T, sizeof(T)));
  std::cout << "LeMac=" << lemac << '\n';
  const std::string expected = "26fa471b77facc73ec2f9b50bb1af864";
  assert(expected == lemac);
}
