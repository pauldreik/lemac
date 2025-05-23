cmake_minimum_required(VERSION 3.21)

project(lemac LANGUAGES CXX)

add_library(lemac src/lemac.cpp include/lemac.h)
add_library(lemac::lemac ALIAS lemac)
target_compile_features(lemac PUBLIC cxx_std_20)
target_include_directories(lemac PRIVATE src)
target_include_directories(lemac PUBLIC include)

add_library(lemac_compiler_warnings INTERFACE)
set(gcc_like_cxx "$<COMPILE_LANG_AND_ID:CXX,AppleClang,Clang,GNU>")
set(msvc_cxx "$<COMPILE_LANG_AND_ID:CXX,MSVC>")
target_compile_options(
  lemac_compiler_warnings
  INTERFACE
    "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-Wall;-Wextra;-pedantic;-Wshadow;-Wunused>>"
    "$<${msvc_cxx}:$<BUILD_INTERFACE:-W3>>")
target_link_libraries(lemac PUBLIC lemac_compiler_warnings)

target_compile_options(
  lemac PUBLIC "$<${gcc_like_cxx}:$<BUILD_INTERFACE:-maes;-msse2>>"
               "$<${msvc_cxx}:$<BUILD_INTERFACE:??????>>")

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
