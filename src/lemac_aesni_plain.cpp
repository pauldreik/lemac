#include "lemac_aesni.h"
#include "lemac_aesni_impl.h"

namespace lemac::inline v1 {

template <>
std::unique_ptr<detail::ImplInterface> make_aesni<AESNI_variant::plain>() {
  return std::make_unique<AESNI<AESNI_variant::plain>::LeMacAESNI>();
}

template <>
std::unique_ptr<detail::ImplInterface>
make_aesni<AESNI_variant::plain>(std::span<const std::uint8_t, key_size> key) {
  return std::make_unique<AESNI<AESNI_variant::plain>::LeMacAESNI>(key);
}

} // namespace lemac::inline v1
