add_executable(test_errors
  test_errors.cpp

  main.cpp
)
target_link_libraries(test_errors tankererrors CONAN_PKG::catch2)

add_test(NAME test_errors COMMAND test_errors)
