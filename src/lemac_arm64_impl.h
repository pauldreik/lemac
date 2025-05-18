#pragma once

#include "impl_interface.h"
#include "lemac_arm64.h"

namespace lemac::inline v1 {

template <Variant variant> struct Arm64 {

  class Arm64Impl : public detail::ImplInterface {
  public:
    std::unique_ptr<detail::ImplInterface> clone() const noexcept override {
      return nullptr;
    }

    void update(std::span<const uint8_t> data) noexcept override { return; }

    void finalize_to(std::span<const uint8_t> nonce,
                     std::span<uint8_t, 16> target) noexcept override {
      if constexpr (variant == Variant::plain) {
        target[0] = 'p';
      } else {
        target[0] = 'v';
      }
    }

    std::array<uint8_t, 16>
    oneshot(std::span<const uint8_t> data,
            std::span<const uint8_t> nonce) const noexcept override {
      return {};
    }

    void reset() noexcept override {}
  };
};

} // namespace lemac::inline v1
