find_package(fmt REQUIRED)
add_executable(benchmark benchmark.cpp)
target_link_libraries(benchmark PRIVATE lemac fmt::fmt)
target_link_libraries(benchmark PRIVATE lemac_compiler_warnings)
