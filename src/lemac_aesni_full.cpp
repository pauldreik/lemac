/*
 * By Paul Dreik, https://www.pauldreik.se/
 *
 * https://github.com/pauldreik/lemac
 * SPDX-License-Identifier: BSL-1.0
 */
#include "lemac_aesni.h"
#include "lemac_aesni_impl.h"

namespace lemac::inline v1 {

namespace {
constexpr auto level = AESNI_variant::vaes512full;
}

template <> std::unique_ptr<detail::ImplInterface> make_aesni<level>() {
  return std::make_unique<AESNI<level>::LeMacAESNI>();
}

template <>
std::unique_ptr<detail::ImplInterface>
make_aesni<level>(std::span<const std::uint8_t, key_size> key) {
  return std::make_unique<AESNI<level>::LeMacAESNI>(key);
}

} // namespace lemac::inline v1
