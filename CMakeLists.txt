cmake_minimum_required(VERSION 3.16)

project(lemac LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


add_compile_options(-fsanitize=address,undefined)
add_link_options(-fsanitize=address,undefined)

add_library(lemac
    src/lemac.cpp
    src/lemac.h)
target_compile_options(lemac PRIVATE -maes -msse2)

target_include_directories(lemac PUBLIC src)

add_subdirectory(test)



add_executable(lemacsum
    src/main.cpp
)

target_link_libraries(lemacsum PRIVATE lemac)

include(GNUInstallDirs)
install(TARGETS lemacsum
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
