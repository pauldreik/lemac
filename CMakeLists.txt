cmake_minimum_required(VERSION 3.21)

project(lemac LANGUAGES CXX)

set(gcc_like_cxx "$<COMPILE_LANG_AND_ID:CXX,AppleClang,Clang,GNU>")
set(msvc_cxx "$<COMPILE_LANG_AND_ID:CXX,MSVC>")

add_library(lemac include/lemac.h src/impl_interface.h src/lemac.cpp)

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
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64|ARM64)")
  target_sources(
    lemac PRIVATE src/lemac_arm64_plain.cpp src/lemac_arm64_vaes.cpp
                  src/lemac_arm64.h src/lemac_arm64_impl.h)
  target_compile_definitions(lemac PRIVATE LEMAC_ARCH_IS_ARM64=1)

else()
  message(FATAL_ERROR "unrecognized architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

add_library(lemac::lemac ALIAS lemac)
target_compile_features(lemac PUBLIC cxx_std_20)
target_include_directories(lemac PRIVATE src)
target_include_directories(lemac PUBLIC include)

add_library(lemac_compiler_warnings INTERFACE)

target_compile_options(
  lemac_compiler_warnings
  INTERFACE
    "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-Wall;-Wextra;-pedantic;-Wshadow;-Wunused>>"
    "$<${msvc_cxx}:$<BUILD_INTERFACE:-W3>>")
target_link_libraries(lemac PUBLIC lemac_compiler_warnings)

if(PROJECT_IS_TOP_LEVEL)
  option(LEMAC_SANITIZERS "enables sanitizers" Off)
  if(LEMAC_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
  endif()
  enable_testing()
  add_subdirectory(test)
  add_subdirectory(benchmark)

  add_executable(lemacsum src/main.cpp)
  target_link_libraries(lemacsum PRIVATE lemac)
  target_link_libraries(lemacsum PUBLIC lemac_compiler_warnings)

  include(GNUInstallDirs)
  install(
    TARGETS lemacsum
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
