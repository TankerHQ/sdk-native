cmake_minimum_required(VERSION 3.4)

project(functional-tests)

set(_main_cpp main_functional.cpp)

add_executable(test_functional
  ${_main_cpp}
  HttpHelpers.cpp
  test_functional.cpp
  test_verification.cpp
  test_groups.cpp
  test_provisional.cpp
  test_encryption_session.cpp

  CheckDecrypt.cpp
)

target_link_libraries(test_functional
  tankerfunctionalhelpers
  tankertesthelpers
  tankeradmin
  tankercore
  catch2-async::catch2-async
)

add_test(NAME test_functional COMMAND test_functional --durations=true)
