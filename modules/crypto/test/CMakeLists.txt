add_executable(test_tanker_crypto
  test_crypto.cpp
  test_padding.cpp
)

target_link_libraries(test_tanker_crypto tankercrypto tankertesthelpers Catch2::Catch2WithMain)
add_test(NAME test_tanker_crypto COMMAND test_tanker_crypto --durations=true)
