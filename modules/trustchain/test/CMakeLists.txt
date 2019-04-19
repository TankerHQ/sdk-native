add_executable(test_trustchain
  test_actions_devicecreation.cpp
  test_actions_trustchaincreation.cpp
  test_actions_keypublishtodevice.cpp

  main.cpp
)
target_link_libraries(test_trustchain tankertrustchain tankertesthelpers CONAN_PKG::doctest)

add_test(NAME test_trustchain COMMAND test_trustchain)
