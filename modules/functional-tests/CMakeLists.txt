cmake_minimum_required(VERSION 3.4)

project(functional-tests)

set(_main_cpp main_functional.cpp)

add_executable(test_functional
  ${_main_cpp}
  test_functional.cpp
  test_verification.cpp
  test_groups.cpp
  test_revocation.cpp
  test_encryption_session.cpp
)

target_link_libraries(test_functional
  tankerfunctionalhelpers
  tankertesthelpers
  tankeradmin
  tankercore
  CONAN_PKG::doctest-async
)
if (TANKER_BUILD_WITH_SSL)
  target_link_libraries(test_functional
  CONAN_PKG::fetchpp
)
endif()


add_test(NAME test_functional COMMAND test_functional --duration=true)
