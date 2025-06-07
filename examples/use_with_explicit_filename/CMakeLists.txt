# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 3.23)
project(
  example_with_install_not_benefitting_from_cmake
  VERSION 0.0
  LANGUAGES CXX)

# this shows how lemac is consumed by assuming it is available in a default
# location (on debian linux, that is /usr/include/lemac.h and
# /usr/lib/$ARCH/liblemac.so) note that we explicitly have to point out use of
# C++20

add_executable(executable main.cpp)
target_compile_features(executable PRIVATE cxx_std_20)
target_link_libraries(executable PRIVATE lemac)
