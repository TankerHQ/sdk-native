add_executable(test_errors
  test_errc.cpp

  main.cpp
)
target_link_libraries(test_errors tankererrors CONAN_PKG::doctest)

add_test(NAME test_errors COMMAND test_errors)
