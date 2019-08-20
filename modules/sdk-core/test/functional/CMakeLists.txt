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
  test_filekit.cpp
)

target_link_libraries(test_functional
  tankercore_test
  tankertesthelpers
  tankercore
  CONAN_PKG::doctest-async
)

add_test(NAME test_functional COMMAND test_functional --duration=true)
