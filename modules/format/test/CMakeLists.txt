add_executable(test_format
  test_format.cpp
  test_format_json.cpp
  test_format_enum.cpp
)
target_link_libraries(test_format tankerformat Catch2::Catch2WithMain)

add_test(NAME test_format COMMAND test_format)
