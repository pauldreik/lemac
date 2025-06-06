# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 3.23)
project(
  example_with_fetchcontent
  VERSION 0.0
  LANGUAGES CXX)

option(GIT_REPOSITORY "url to repo" "https://github.com/pauldreik/lemac")
option(GIT_BRANCH "git branch" "main")

include(FetchContent)
FetchContent_Declare(
  lemac
  GIT_REPOSITORY ${GIT_REPOSITORY}
  GIT_TAG ${GIT_BRANCH})
FetchContent_MakeAvailable(lemac)

add_executable(executable main.cpp)
target_link_libraries(executable PRIVATE lemac::lemac)
