# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 3.23)
project(
  example_with_cmake_installed_lemac
  VERSION 0.0
  LANGUAGES CXX)

add_executable(executable main.cpp)
target_compile_features(executable PRIVATE cxx_std_20)
target_link_libraries(executable PRIVATE lemac)
