add_executable(test_functional_fakeauthentication
  main.cpp
  test_fakeauthentication.cpp
)

target_link_libraries(test_functional_fakeauthentication
  tankerfakeauthentication
  tankercore_test
  tankertesthelpers
  CONAN_PKG::doctest-async
)
add_test(NAME test_functional_fakeauthentication COMMAND test_functional_fakeauthentication)
