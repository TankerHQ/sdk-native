add_executable(test_identity
  test_identity.cpp
)

target_link_libraries(test_identity tankeridentity tankertesthelpers Catch2::Catch2WithMain)
add_test(NAME test_identity COMMAND test_identity --durations=true)
