add_executable(test_encryptor
  test_encryptor.cpp

  main.cpp
  )
target_link_libraries(test_encryptor
  tankerencryptor
  tankertesthelpers
  Catch2::Catch2
  trompeloeil::trompeloeil
  )
add_test(NAME test_encryptor COMMAND test_encryptor --durations=true)
