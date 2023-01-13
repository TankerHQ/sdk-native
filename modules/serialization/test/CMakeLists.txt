add_executable(test_serialization
  test_serialization.cpp
)
target_link_libraries(test_serialization tankerserialization tankertesthelpers Catch2::Catch2WithMain)

add_test(NAME test_serialization COMMAND test_serialization)
