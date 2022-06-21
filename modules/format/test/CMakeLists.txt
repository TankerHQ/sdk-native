add_executable(test_format
  test_format.cpp
  test_format_json.cpp
  test_format_enum.cpp

  main.cpp
)
target_link_libraries(test_format tankerformat catch2::catch2)

add_test(NAME test_format COMMAND test_format)
