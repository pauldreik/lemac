#include "x86_capabilities.h"

// this works on clang and gcc
#if defined(__GNUC__) || defined(__clang__)
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
#if defined(__GNUC__) || defined(__clang__)
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
