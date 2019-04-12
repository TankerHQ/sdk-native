add_executable(test_format
  test_format.cpp
  test_format_json.cpp

  main.cpp
)
target_link_libraries(test_format tankerformat CONAN_PKG::doctest)

add_test(NAME test_format COMMAND test_format)
