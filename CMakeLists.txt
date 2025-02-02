cmake_minimum_required(VERSION 3.16)

project(lemac LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(lemac
    src/lemac.c
    src/lemac.h)
target_compile_options(lemac PRIVATE -maes -msse2)

target_include_directories(lemac PUBLIC src)

add_executable(lemacsum
    src/main.cpp
)

target_link_libraries(lemacsum PRIVATE lemac)


include(GNUInstallDirs)
install(TARGETS lemacsum
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
