#include "arm64_capabilities.h"

#ifdef __linux__
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace {

bool aes_support_impl() {
#ifdef __linux__
  // from
  // https://community.arm.com/arm-community-blogs/b/operating-systems-blog/posts/runtime-detection-of-cpu-features-on-an-armv8-a-cpu
  const auto hwcaps = getauxval(AT_HWCAP);
  return (hwcaps & HWCAP_AES) == HWCAP_AES;
#else
#error "unsupported implementation, fix me!"
#endif
}

} // namespace

namespace lemac::inline v1 {

bool supports_arm64v8a_crypto() {
  static const bool cached_value = aes_support_impl();
  return cached_value;
}

} // namespace lemac::inline v1
