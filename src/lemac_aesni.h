#pragma once

#include "impl_interface.h"
#include "lemac.h"
#include <memory>

namespace lemac::inline v1 {

enum class AESNI_variant {
  /// no support
  none,
  /// basic support (128 bit), requires AES flag
  aes128,
  /// vaes support for 512 bit, requires VAES and AVX512F flags
  vaes512,
  /// vaes support for 512, 256 and 128 bit. requires VAES, AVX512F and
  /// AVX512VL flags.
  vaes512full
};

template <AESNI_variant variant>
std::unique_ptr<detail::ImplInterface> make_aesni();

template <AESNI_variant variant>
std::unique_ptr<detail::ImplInterface>
    make_aesni(std::span<const std::uint8_t, key_size>);
} // namespace lemac::inline v1
