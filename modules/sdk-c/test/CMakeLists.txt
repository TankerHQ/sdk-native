add_executable(test_tanker_c
  test_promise.cpp
  test_functional.cpp
  main.cpp
)

target_link_libraries(test_tanker_c tanker tankertesthelpers CONAN_PKG::doctest)
add_test(NAME test_tanker_c COMMAND test_tanker_c ---duration=true)
