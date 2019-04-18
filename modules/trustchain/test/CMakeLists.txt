add_executable(test_trustchain
  test_actions_devicecreation.cpp

  main.cpp
)
target_link_libraries(test_trustchain tankertrustchain tankertesthelpers CONAN_PKG::doctest)

add_test(NAME test_trustchain COMMAND test_trustchain)
