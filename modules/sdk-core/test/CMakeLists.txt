add_executable(test_tanker
  test_localuserstore.cpp
  test_groupstore.cpp
  test_groupaccessor.cpp
  test_groupupdater.cpp
  test_userupdater.cpp
  test_resourcekeystore.cpp
  test_provisionaluserkeysstore.cpp
  test_log.cpp
  test_oidcmanager.cpp
  test_encryptor.cpp
  test_encryptionsession.cpp
  test_receivekey.cpp
  test_share.cpp
  test_ghostdevice.cpp
  test_verificationkey.cpp
  test_requestwithverif.cpp
  test_useraccessor.cpp
  test_groups.cpp
  test_verif.cpp
  test_preregistration.cpp
  test_datastore.cpp
  test_datastore_new.cpp
  test_taskcoalescer.cpp

  TrustchainGenerator.hpp
  TrustchainGenerator.cpp

  main.cpp
)
target_link_libraries(test_tanker
  tankercore
  tankertesthelpers
  catch2::catch2
  trompeloeil::trompeloeil
)
add_test(NAME test_tanker COMMAND test_tanker --durations=true)
