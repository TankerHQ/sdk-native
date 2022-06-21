add_executable(test_identity
  test_identity.cpp
  main.cpp
)

target_link_libraries(test_identity tankeridentity tankertesthelpers catch2::catch2)
add_test(NAME test_identity COMMAND test_identity --durations=true)
