#pragma once

#include "impl_interface.h"
#include "lemac.h"

#include "arm_neon.h"

namespace lemac::inline v1 {

namespace detail {
struct Sstate {
  uint8x16_t S[9];
};

struct Rstate {
  void reset();
  uint8x16_t RR;
  uint8x16_t R0;
  uint8x16_t R1;
  uint8x16_t R2;
};

// this is the state that changes during absorption of data
struct ComboState {
  Sstate s;
  Rstate r;
};

// this is inited on lemac construction and not changed after
struct LeMacContext {
  Sstate init;
  uint8x16_t keys[2][11];
  uint8x16_t subkeys[18];

  template <std::size_t i>
    requires(i >= 0 && i <= 8)
  std::span<const uint8x16_t, 11> get_subkey() const {
    return std::span<const uint8x16_t, 11>(subkeys + i, 11);
  }
};
} // namespace detail

/**
 * implements lemac with Armv8A intrinsics
 */
class LemacArm64v8A final : public detail::ImplInterface {
public:
  LemacArm64v8A() noexcept;
  explicit LemacArm64v8A(std::span<const uint8_t, key_size> key) noexcept;

  // we are copyable and movable without anything special to consider
  LemacArm64v8A(const LemacArm64v8A&) = default;
  LemacArm64v8A(LemacArm64v8A&&) = default;
  LemacArm64v8A& operator=(const LemacArm64v8A&) = default;
  LemacArm64v8A& operator=(LemacArm64v8A&&) = default;

  std::unique_ptr<detail::ImplInterface> clone() const noexcept override;

  void update(std::span<const uint8_t> data) noexcept override;

  void finalize_to(std::span<const uint8_t> nonce,
                   std::span<uint8_t, 16> target) noexcept override;

  std::array<uint8_t, 16>
  oneshot(std::span<const uint8_t> data,
          std::span<const uint8_t> nonce) const noexcept override;

  void reset() noexcept override;

private:
  detail::LeMacContext m_context;
  detail::ComboState m_state;

  static constexpr std::size_t block_size = 64;

  /// this is a buffer that keeps data between update() invocations,
  /// in case data is provided in sizes not evenly divisible by the block size
  std::array<std::uint8_t, block_size> m_buf{};
  std::size_t m_bufsize{};
};

} // namespace lemac::inline v1
