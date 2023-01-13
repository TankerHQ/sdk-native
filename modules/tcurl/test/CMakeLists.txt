add_executable(test_tcurl
  test_curl.cpp
)

target_link_libraries(test_tcurl tcurl Catch2::Catch2WithMain)
add_test(NAME test_tcurl COMMAND test_tcurl --durations=true)
