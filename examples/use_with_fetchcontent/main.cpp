#include <cstdio>
#include <string>

#include "lemac.h"

int main() {
  std::string message("hello");
  lemac::LeMac lm;
  const auto hash = lm.oneshot(
      std::span((const std::uint8_t*)message.data(), message.size()));

  std::printf("the hash of %s is ", message.c_str());
  for (int c : hash) {
    std::printf("%02x", c);
  }
  std::putchar('\n');
}
