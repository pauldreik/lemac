/*
 * This is a C++ implementation of LeMac, based on the 2024 public domain
 * implementation (CC0-1.0 license) by Augustin Bariant and Gaëtan Leurent.
 *
 * By Paul Dreik, https://www.pauldreik.se/
 *
 * https://github.com/pauldreik/lemac
 * SPDX-License-Identifier: BSL-1.0
 */
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#ifdef LEMAC_INTERNAL_STATE_VISIBILITY
#include <string>
#endif

namespace lemac::inline v1 {

/// the size of the key in bytes
static constexpr std::size_t key_size = 16;

namespace detail {
// items in this namespace are not part of the public api
class ImplInterface;
} // namespace detail

/**
 * A cryptographic hash function designed by Augustin Bariant
 *
 * This class is copyable and moveable as if it was a value type.
 */
class LeMac final {
public:
  /**
   * constructs a hasher with a zero key
   */
  LeMac() noexcept;

  /**
   * constructs a hasher with a correctly sized key, verified at runtime.
   *
   * @param key the key does not need to be aligned, but it must have the
   * correct size (lemac::key_size). if not, an exception is thrown.
   */
  explicit LeMac(std::span<const std::uint8_t> key);

  LeMac(const LeMac& other) noexcept;
  LeMac(LeMac&& other) noexcept;
  LeMac& operator=(const LeMac& other) noexcept;
  LeMac& operator=(LeMac&& other) noexcept;
  ~LeMac() noexcept;

  /**
   * updates the hash with the provided data. this may be called zero or more
   * times.
   *
   * if all data is known up front, prefer the oneshot() function instead which
   * is faster.
   *
   * @param data does not need to be aligned
   */
  void update(std::span<const std::uint8_t> data) noexcept;

  /**
   * finalizes the hash with a zero nonce and returns the result
   * @return
   */
  std::array<std::uint8_t, 16> finalize() noexcept;

  /**
   * finalizes the hash and returns the result
   * @param nonce does not need to be aligned
   * @return
   */
  std::array<std::uint8_t, 16> finalize(std::span<const std::uint8_t> nonce);

  /**
   * finalizes the hash and writes the result into the provided target, using a
   * zero nonce.
   * @param target does not need to be aligned
   */
  void finalize_to(std::span<std::uint8_t, 16> target) noexcept {
    finalize_to(zeros, target);
  }

  /**
   * finalizes the hash and writes the result into the provided target
   * @param nonce does not need to be aligned
   * @param target does not need to be aligned
   */
  void finalize_to(std::span<const std::uint8_t> nonce,
                   std::span<std::uint8_t, 16> target) noexcept;

  /**
   * hashes with the provided data and then finalizes the hash, using a zero
   * nonce. this is more efficient than update()+finalize() and should be
   * preferred when all data is known upfront.
   *
   * @param data does not need to be aligned
   * @return the lemac hash
   */
  std::array<std::uint8_t, 16>
  oneshot(std::span<const std::uint8_t> data) const noexcept {
    return oneshot(data, zeros);
  }

  /**
   * hashes with the provided data and then finalizes the hash with the given
   * nonce. this is more efficient than update()+finalize() and should be
   * preferred when all data is known upfront.
   *
   * @param data does not need to be aligned
   * @param nonce does not need to be aligned
   * @return the lemac hash
   */
  std::array<std::uint8_t, 16>
  oneshot(std::span<const std::uint8_t> data,
          std::span<const std::uint8_t> nonce) const noexcept;

  /**
   * resets the object as if it had been newly constructed. this is more
   * efficent than creating a new object.
   */
  void reset() noexcept;

#ifdef LEMAC_INTERNAL_STATE_VISIBILITY
  /**
   * for debugging/development. returns a text representation of the internal
   * state
   */
  std::string get_internal_state() const noexcept;
#endif

private:
  /// zeros which can be used as a key or a nonce
  static constexpr std::array<const std::uint8_t, key_size> zeros{};

  /// the implementation is held by pointer:
  /// - to dynamically pick the best version supported by the cpu, determined
  ///  at runtime
  /// - to hide implementation detail
  /// - to have a small impact on compile time on user code
  std::unique_ptr<detail::ImplInterface> m_impl;
};

} // namespace lemac::inline v1
