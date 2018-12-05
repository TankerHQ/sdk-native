add_executable(test_usertoken
  test_user_token.cpp
  main.cpp
)

target_link_libraries(test_usertoken tankerusertoken CONAN_PKG::doctest)
add_test(NAME test_usertoken COMMAND test_usertoken --duration=true)
