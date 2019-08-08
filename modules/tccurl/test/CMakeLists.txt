add_executable(test_functional_tccurl
  main.cpp
  test_curl.cpp
)
target_link_libraries(test_functional_tccurl tccurl CONAN_PKG::doctest)
add_test(NAME test_functional_tccurl COMMAND test_functional_tccurl)
