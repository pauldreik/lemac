/*
 * By Paul Dreik, https://www.pauldreik.se/
 *
 * https://github.com/pauldreik/lemac
 * SPDX-License-Identifier: BSL-1.0
 */
#include "x86_capabilities.h"

#if defined(_MSC_VER)
// see
// https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex?view=msvc-170
#include <array>
#include <intrin.h>
#if defined(bit_AES) || defined(bit_VAES) || defined(bit_AVX512F) ||           \
    defined(bit_AVX512VL)
#error "bit_AES is already defined"
#endif
constexpr auto bit_AES{1U << 25};
constexpr auto bit_VAES{1U << 9};
constexpr auto bit_AVX512F{1U << 16};
constexpr auto bit_AVX512VL{1U << 31};
#elif defined(__GNUC__) || defined(__clang__)
// this works on clang and gcc
#include <cpuid.h>
#else
#error "fix cpuid support"
#endif

#include <stdexcept>

namespace {
struct cpuidresponse {
  unsigned int eax;
  unsigned int ebx;
  unsigned int ecx;
  unsigned int edx;
};
cpuidresponse query_cpuid(const unsigned int leaf, const unsigned int subleaf) {
  cpuidresponse ret{};
#if defined(_MSC_VER)
  std::array<int, 4> cpui{};
  static_assert(sizeof(cpui) == sizeof(ret));
  __cpuidex(cpui.data(), leaf, subleaf);
  std::memcpy(&ret, cpui.data(), sizeof(ret));
#elif defined(__GNUC__) || defined(__clang__)
  if (1 != __get_cpuid_count(leaf, subleaf, &ret.eax, &ret.ebx, &ret.ecx,
                             &ret.edx)) {
    throw std::runtime_error("failed running cpuid");
  }
#else
#error "fix cpuid support"
#endif
  return ret;
}

bool supports_aes() { return (query_cpuid(1, 0).ecx & bit_AES) == bit_AES; }
bool supports_vaes() { return (query_cpuid(7, 0).ecx & bit_VAES) == bit_VAES; }
bool supports_AVX512F() {
  return (query_cpuid(7, 0).ebx & bit_AVX512F) == bit_AVX512F;
}
bool supports_AVX512VL() {
  return (query_cpuid(7, 0).ebx & bit_AVX512VL) == bit_AVX512VL;
}

lemac::AESNI_variant get_support_level() {
  if (supports_vaes() && supports_AVX512VL() && supports_AVX512F()) {
    return lemac::AESNI_variant::vaes512full;
  }
  if (supports_vaes() && supports_AVX512F()) {
    return lemac::AESNI_variant::vaes512;
  }
  if (supports_aes()) {
    return lemac::AESNI_variant::aes128;
  }
  return lemac::AESNI_variant::none;
}

} // namespace

namespace lemac::inline v1 {

AESNI_variant get_aesni_support_level() {
  static const auto cached_value = get_support_level();
  return cached_value;
}

} // namespace lemac::inline v1
