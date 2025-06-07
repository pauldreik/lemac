# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 3.23)
project(
  example_with_find_package
  VERSION 0.0
  LANGUAGES CXX)

# this shows how to use lemac if it has been properly installed with cmake
# support so that find_package can be used.

find_package(lemac REQUIRED)

add_executable(executable main.cpp)
target_link_libraries(executable PRIVATE lemac::lemac)
