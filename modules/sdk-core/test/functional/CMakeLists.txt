add_executable(test_functional
  main_functional.cpp
  test_functional.cpp
  test_unlock.cpp
  test_unlock_methods.cpp
  test_chunkencryptor.cpp
  test_groups.cpp
)

target_link_libraries(test_functional
  tankercore_test
  tankertesthelpers
  CONAN_PKG::doctest
)

target_compile_definitions(test_functional PRIVATE FMT_STRING_ALIAS)
add_test(NAME test_functional COMMAND test_functional --duration=true)
