add_executable(test_functional_filekit
  main.cpp
  test_filekit.cpp
)

target_link_libraries(test_functional_filekit
  tankercore_test
  tankerfilekit
  tankertesthelpers
  CONAN_PKG::doctest-async
)
add_test(NAME test_functional_filekit COMMAND test_functional_filekit)
