#include "lemac_arm64_impl.h"

namespace lemac::inline v1 {

template <>
std::unique_ptr<detail::ImplInterface> make_arm64<Variant::plain>() {
  return std::make_unique<Arm64<Variant::plain>::Arm64Impl>();
}
} // namespace lemac::inline v1
