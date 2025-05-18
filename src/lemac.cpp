/*
 * This is a C++ implementation of LeMac, based on the 2024 public domain
 * implementation (CC0-1.0 license) by Augustin Bariant and Gaëtan Leurent.
 *
 * By Paul Dreik, https://www.pauldreik.se/
 *
 * https://github.com/pauldreik/lemac
 * SPDX-License-Identifier: BSL-1.0
 */

#include "lemac.h"

#if defined(__x86_64__)
#include "lemac_aesni.h"
#endif

namespace lemac::inline v1 {

LeMac::LeMac() noexcept {
#if defined(__x86_64__)
  m_impl = LeMacAESNI::make();
#endif

  if (!m_impl) {
    // no implementation available
    std::abort();
  }
}

LeMac::LeMac(std::span<const uint8_t> key) {

  if (key.size() != lemac::key_size) {
    throw std::runtime_error("wrong size of key");
  }

  const auto right_size_key = key.first<lemac::key_size>();

#if defined(__x86_64__)
  m_impl = LeMacAESNI::make(right_size_key);
#endif

  if (!m_impl) {
    // no implementation available
    std::abort();
  }
}

LeMac::LeMac(const LeMac& other) noexcept { m_impl = other.m_impl->clone(); }

LeMac::LeMac(LeMac&& other) noexcept { m_impl = std::move(other.m_impl); }

LeMac& LeMac::operator=(const LeMac& other) noexcept {
  m_impl = other.m_impl->clone();
  return *this;
}
LeMac& LeMac::operator=(LeMac&& other) noexcept {
  m_impl = std::move(other.m_impl);
  return *this;
}

LeMac::~LeMac() noexcept {}

void LeMac::update(std::span<const uint8_t> data) noexcept {
  m_impl->update(data);
}

std::array<uint8_t, 16> LeMac::finalize() noexcept {
  std::array<std::uint8_t, 16> ret;
  finalize_to(zeros, ret);
  return ret;
}

std::array<uint8_t, 16> LeMac::finalize(std::span<const uint8_t> nonce) {
  std::array<std::uint8_t, 16> ret;
  finalize_to(nonce, ret);
  return ret;
}

void LeMac::finalize_to(std::span<const uint8_t> nonce,
                        std::span<uint8_t, 16> target) noexcept {
  m_impl->finalize_to(nonce, target);
}

std::array<uint8_t, 16>
LeMac::oneshot(std::span<const uint8_t> data,
               std::span<const uint8_t> nonce) const noexcept {
  return m_impl->oneshot(data, nonce);
}

void LeMac::reset() noexcept { m_impl->reset(); }

} // namespace lemac::inline v1
