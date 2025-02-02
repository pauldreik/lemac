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
