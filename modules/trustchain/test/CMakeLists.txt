add_executable(test_trustchain
  test_actions_devicecreation.cpp
  test_actions_trustchaincreation.cpp
  test_actions_keypublishtouser.cpp
  test_actions_keypublishtoprovisionaluser.cpp
  test_actions_keypublishtousergroup.cpp
  test_actions_provisionalidentityclaim.cpp
  test_actions_devicerevocation.cpp
  test_actions_usergroupcreation.cpp
  test_actions_usergroupaddition.cpp
  test_actions_usergroupremoval.cpp
  test_actions_sessioncertificate.cpp
  test_preprocessor_actions.cpp
  test_upgrade_required.cpp

  main.cpp
)
target_link_libraries(test_trustchain tankertrustchain tankertesthelpers CONAN_PKG::catch2)

add_test(NAME test_trustchain COMMAND test_trustchain)
