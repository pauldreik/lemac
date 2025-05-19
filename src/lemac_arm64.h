#pragma once

#include "impl_interface.h"
#include "lemac.h"
#include <memory>

namespace lemac::inline v1 {

std::unique_ptr<detail::ImplInterface> make_arm64_v8A();

std::unique_ptr<detail::ImplInterface>
make_arm64_v8A(std::span<const uint8_t, key_size> key);
} // namespace lemac::inline v1
