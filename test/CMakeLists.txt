# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

find_package(Catch2 3 REQUIRED)
add_executable(tests tests.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain lemac
                                    lemac_compiler_warnings)
add_test(NAME tests COMMAND tests)
