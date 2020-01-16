cmake_minimum_required(VERSION 3.4)

project(functional-tests)

if (NOT EMSCRIPTEN)
  set(_main_cpp main_functional.cpp)
else ()
  set(_main_cpp main_functional_emscripten.cpp)
endif()

add_executable(test_functional
  ${_main_cpp}
  test_functional.cpp
  test_verification.cpp
  test_groups.cpp
  test_revocation.cpp
)

target_link_libraries(test_functional
  tankerfunctionalhelpers
  tankertesthelpers
  tankeradmin
  tankercore
  CONAN_PKG::doctest-async
)

add_test(NAME test_functional COMMAND test_functional --duration=true)
