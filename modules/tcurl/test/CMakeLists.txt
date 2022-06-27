add_executable(test_tcurl
  test_curl.cpp
  main.cpp
)

target_link_libraries(test_tcurl tcurl catch2::catch2)
add_test(NAME test_tcurl COMMAND test_tcurl --durations=true)
