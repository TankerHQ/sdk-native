add_executable(test_tanker_crypto
  test_crypto.cpp
  main.cpp
)

target_link_libraries(test_tanker_crypto tankercrypto tankertesthelpers CONAN_PKG::doctest)
add_test(NAME test_tanker_crypto COMMAND test_tanker_crypto --duration=true)
