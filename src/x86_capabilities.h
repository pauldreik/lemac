/*
 * By Paul Dreik, https://www.pauldreik.se/
 *
 * https://github.com/pauldreik/lemac
 * SPDX-License-Identifier: BSL-1.0
 */
#pragma once

#include "lemac_aesni.h"

namespace lemac::inline v1 {

/// this checks (at runtime) if aes-ni is available and to what extent.
/// @return the best supported variant
AESNI_variant get_aesni_support_level();

} // namespace lemac::inline v1
