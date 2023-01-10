add_executable(test_errors
  test_errors.cpp
)
target_link_libraries(test_errors tankererrors Catch2::Catch2WithMain)

add_test(NAME test_errors COMMAND test_errors)
