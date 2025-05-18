#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>

namespace lemac::inline v1 {

namespace detail {

class ImplInterface {
public:
  virtual ~ImplInterface() = default;
  virtual std::unique_ptr<detail::ImplInterface> clone() const noexcept = 0;

  virtual void update(std::span<const std::uint8_t> data) noexcept = 0;

  virtual void finalize_to(std::span<const std::uint8_t> nonce,
                           std::span<std::uint8_t, 16> target) noexcept = 0;

  virtual std::array<std::uint8_t, 16>
  oneshot(std::span<const std::uint8_t> data,
          std::span<const std::uint8_t> nonce) const noexcept = 0;

  virtual void reset() noexcept = 0;
};

} // namespace detail

} // namespace lemac::inline v1
