
find_package(Catch2 3 REQUIRED)

add_executable(tests tests.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain lemac)
add_test(NAME tests COMMAND tests)
