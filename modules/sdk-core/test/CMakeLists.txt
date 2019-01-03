add_executable(test_tanker
  test_serialization.cpp
  test_client.cpp
  test_contactstore.cpp
  test_devicekeystore.cpp
  test_groupstore.cpp
  test_groupaccessor.cpp
  test_groupupdater.cpp
  test_resourcekeystore.cpp
  test_trustchain.cpp
  test_userkeystore.cpp
  test_blockgenerator.cpp
  test_log.cpp
  test_encryptor.cpp
  test_datastore.cpp
  test_chunkencryptor.cpp
  test_receivekey.cpp
  test_seal.cpp
  test_session.cpp
  test_share.cpp
  test_ghostdevice.cpp
  test_unlockkey.cpp
  test_useraccessor.cpp
  test_entry.cpp
  test_groups.cpp
  test_verif.cpp
  test_trustchainverifier.cpp
  test_revocation.cpp

  TestVerifier.cpp
  MockConnection.cpp
  TrustchainBuilder.cpp

  main.cpp
)
target_link_libraries(test_tanker
  tankercore_test
  tankertesthelpers
  CONAN_PKG::doctest
  CONAN_PKG::trompeloeil
)
add_test(NAME test_tanker COMMAND test_tanker --duration=true)

add_subdirectory(functional)
