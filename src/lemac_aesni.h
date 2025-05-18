#pragma once

#include "impl_interface.h"
#include "lemac.h"
#include <memory>

namespace lemac::inline v1 {

enum class AESNI_variant { plain, vaes };

template <AESNI_variant variant>
std::unique_ptr<detail::ImplInterface> make_aesni();

template <AESNI_variant variant>
std::unique_ptr<detail::ImplInterface>
    make_aesni(std::span<const std::uint8_t, key_size>);
} // namespace lemac::inline v1
