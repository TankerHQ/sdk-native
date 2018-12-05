add_executable(test_serialization
  test_serialization.cpp

  main.cpp
)
target_link_libraries(test_serialization tankerserialization CONAN_PKG::doctest)

add_test(NAME test_serialization COMMAND test_serialization)
