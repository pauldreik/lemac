# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

add_executable(benchmark benchmark.cpp)
target_link_libraries(benchmark PRIVATE lemac)
target_link_libraries(benchmark PRIVATE lemac_compiler_warnings)
