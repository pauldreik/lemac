# By Paul Dreik, https://www.pauldreik.se/
#
# https://github.com/pauldreik/lemac

# SPDX-License-Identifier: BSL-1.0

cmake_minimum_required(VERSION 3.23)

project(lemac LANGUAGES CXX)

set(gcc_like_cxx "$<COMPILE_LANG_AND_ID:CXX,AppleClang,Clang,GNU>")
set(msvc_cxx "$<COMPILE_LANG_AND_ID:CXX,MSVC>")

add_library(lemac src/impl_interface.h src/lemac.cpp)

target_sources(
  lemac
  PUBLIC FILE_SET
         public_headers
         TYPE
         HEADERS
         BASE_DIRS
         include
         FILES
         include/lemac.h)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(x86_64|AMD64)")
  target_sources(
    lemac
    PRIVATE src/lemac_aesni_128.cpp src/lemac_aesni_full.cpp src/lemac_aesni.h
            src/lemac_aesni_impl.h src/x86_capabilities.cpp
            src/x86_capabilities.h)
  # see https://en.wikichip.org/wiki/x86/vaes
  set_source_files_properties(
    src/lemac_aesni_128.cpp
    PROPERTIES
      COMPILE_OPTIONS
      "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-maes;-msse2>>$<${msvc_cxx}:$<BUILD_INTERFACE:/arch:SSE2>>"
  )
  set_source_files_properties(
    src/lemac_aesni_full.cpp
    PROPERTIES
      COMPILE_OPTIONS
      "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-maes;-mvaes;-mavx512f;-mavx512vl>>$<${msvc_cxx}:$<BUILD_INTERFACE:/arch:FIXME>>"
  )
  target_compile_definitions(lemac PRIVATE LEMAC_ARCH_IS_AMD64=1)
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64|ARM64|arm64)")
  target_sources(
    lemac
    PRIVATE src/arm64_capabilities.cpp src/arm64_capabilities.h
            src/lemac_arm64.h src/lemac_arm64_v8A.cpp src/lemac_arm64_v8A.h)

  # we need the v8-A crypto extension. tests on a raspberry pi 5 reveals no
  # significant changes in compiling with armv8-a, armv8.1-a, arm8.2-a (or
  # cpu=a76+crypto which matches perfectly) so go with the most general.
  set_source_files_properties(
    src/lemac_arm64_v8A.cpp
    PROPERTIES
      COMPILE_OPTIONS
      "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-march=armv8-a+aes>>$<${msvc_cxx}:$<BUILD_INTERFACE:>>"
  )
  target_compile_definitions(lemac PRIVATE LEMAC_ARCH_IS_ARM64=1)
  find_package(fmt REQUIRED)
  target_link_libraries(lemac PRIVATE fmt::fmt)
else()
  message(FATAL_ERROR "unrecognized architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

add_library(lemac::lemac ALIAS lemac)
target_compile_features(lemac PUBLIC cxx_std_20)
target_include_directories(lemac PRIVATE src)

if(PROJECT_IS_TOP_LEVEL)
  add_library(lemac_compiler_warnings INTERFACE)
  target_compile_options(
    lemac_compiler_warnings
    INTERFACE
      "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-Wall;-Wextra;-pedantic;-Wshadow;-Wunused>>"
      "$<${msvc_cxx}:$<BUILD_INTERFACE:-W3>>")
  target_link_libraries(lemac PUBLIC lemac_compiler_warnings)

  option(LEMAC_SANITIZERS "enables sanitizers" Off)
  if(LEMAC_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
  endif()
  option(
    LEMAC_INTERNAL_STATE_VISIBILITY
    "enables an api to export the internal state of the hasher (for debugging/development purposes)"
    Off)
  if(LEMAC_INTERNAL_STATE_VISIBILITY)
    target_compile_definitions(lemac PUBLIC LEMAC_INTERNAL_STATE_VISIBILITY)
  endif()

  option(LEMAC_BUILD_TESTING "enables lemac unit tests" On)
  if(LEMAC_BUILD_TESTING)
    enable_testing()
    add_subdirectory(test)
  endif()

  option(LEMAC_BUILD_BENCHMARK "enables lemac benchmark" On)
  if(LEMAC_BUILD_BENCHMARK)
    add_subdirectory(benchmark)
  endif()

  include(GNUInstallDirs)

  option(LEMAC_BUILD_TOOL "enables lemac command line tool lemacsum" On)
  if(LEMAC_BUILD_TOOL)
    add_executable(lemacsum src/main.cpp)
    target_link_libraries(lemacsum PRIVATE lemac)
    # install(FILES lemacsum.1 TYPE MAN)
    install(TARGETS lemacsum RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()

  install(
    TARGETS lemac
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} FILE_SET public_headers)
endif() # PROJECT_IS_TOP_LEVEL
