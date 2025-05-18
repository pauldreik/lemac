#pragma once

#include "impl_interface.h"
#include <memory>

namespace lemac::inline v1 {

enum class Variant { plain, vaes };

template <Variant variant> std::unique_ptr<detail::ImplInterface> make_arm64();
} // namespace lemac::inline v1
