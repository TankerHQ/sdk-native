add_executable(test_identity
  test_identity.cpp
  main.cpp
)

target_link_libraries(test_identity tankeridentity CONAN_PKG::doctest)
add_test(NAME test_identity COMMAND test_identity --duration=true)
