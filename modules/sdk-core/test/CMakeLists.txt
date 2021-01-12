set(TEST_TANKER_EXTRA_SRC test_datastore.cpp)

add_executable(test_tanker
  test_groupkeystore.cpp
  test_groupaccessor.cpp
  test_groupupdater.cpp
  test_userupdater.cpp
  test_resourcekeystore.cpp
  test_provisionaluserkeysstore.cpp
  test_log.cpp
  test_encryptor.cpp
  test_encryptorstream.cpp
  test_encryptionsession.cpp
  test_receivekey.cpp
  test_share.cpp
  test_ghostdevice.cpp
  test_verificationkey.cpp
  test_useraccessor.cpp
  test_groups.cpp
  test_verif.cpp
  test_revocation.cpp
  test_preregistration.cpp
  test_stream.cpp

  TrustchainGenerator.hpp
  TrustchainGenerator.cpp

  main.cpp

  ${TEST_TANKER_EXTRA_SRC}
)
target_link_libraries(test_tanker
  tankercore
  tankertesthelpers
  CONAN_PKG::doctest
  CONAN_PKG::trompeloeil
)
add_test(NAME test_tanker COMMAND test_tanker --duration=true)
