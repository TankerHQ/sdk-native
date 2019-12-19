cmake_minimum_required(VERSION 3.4)

project(TankerSDK-Core)

option(TANKER_BUILD_WITH_SSL "Tanker uses ssl" ON)

if (NOT EMSCRIPTEN)
  set(TANKER_CORE_DATASTORE_SRC
    include/Tanker/DataStore/Connection.hpp
    include/Tanker/DataStore/Database.hpp
    include/Tanker/DataStore/Table.hpp
    include/Tanker/DataStore/Utils.hpp
    include/Tanker/DataStore/Version.hpp
    include/Tanker/DataStore/Errors/Errc.hpp
    include/Tanker/DataStore/Errors/ErrcCategory.hpp
    include/Tanker/DbModels/ContactDevices.hpp
    include/Tanker/DbModels/ContactUserKeys.hpp
    include/Tanker/DbModels/DeviceKeyStore.hpp
    include/Tanker/DbModels/Groups.hpp
    include/Tanker/DbModels/ResourceKeys.hpp
    include/Tanker/DbModels/ProvisionalUserKeys.hpp
    include/Tanker/DbModels/Trustchain.hpp
    include/Tanker/DbModels/TrustchainInfo.hpp
    include/Tanker/DbModels/UserKeys.hpp
    include/Tanker/DbModels/Versions.hpp
    include/Tanker/DbModels/Version.hpp

    src/DataStore/Connection.cpp
    src/DataStore/Database.cpp
    src/DataStore/Table.cpp
    src/DbModels/ContactDevices.cpp
    src/DbModels/ContactUserKeys.cpp
    src/DbModels/DeviceKeyStore.cpp
    src/DbModels/Groups.cpp
    src/DbModels/ResourceKeys.cpp
    src/DbModels/ProvisionalUserKeys.cpp
    src/DbModels/Trustchain.cpp
    src/DbModels/TrustchainInfo.cpp
    src/DbModels/UserKeys.cpp
    src/DbModels/Versions.cpp
    src/DbModels/Version.cpp
  )
else()
  set(TANKER_CORE_DATASTORE_SRC
    include/Tanker/DataStore/JsDatabase.hpp
    src/DataStore/JsDatabase.cpp
  )
  set(TANKER_CORE_EXTRA_SRC
    include/Tanker/Emscripten/Error.hpp
    include/Tanker/Emscripten/Helpers.hpp
    src/Emscripten/Error.cpp
    src/Emscripten/Helpers.cpp
  )
endif()

add_library(tankercore STATIC
  include/Tanker/AsyncCore.hpp
  include/Tanker/AttachResult.hpp
  include/Tanker/BasicPullResult.hpp
  include/Tanker/DataStore/ADatabase.hpp
  include/Tanker/DataStore/Errors/Errc.hpp
  include/Tanker/Init.hpp
  include/Tanker/Retry.hpp
  include/Tanker/TrustchainStore.hpp
  include/Tanker/TrustchainPuller.hpp
  include/Tanker/ITrustchainPuller.hpp
  include/Tanker/TrustchainVerifier.hpp
  include/Tanker/BlockGenerator.hpp
  include/Tanker/GhostDevice.hpp
  include/Tanker/EncryptedUserKey.hpp
  include/Tanker/Unlock/Registration.hpp
  include/Tanker/Unlock/Verification.hpp
  include/Tanker/Unlock/Methods.hpp
  include/Tanker/Opener.hpp
  include/Tanker/DeviceKeys.hpp
  include/Tanker/Client.hpp
  include/Tanker/Entry.hpp
  include/Tanker/Index.hpp
  include/Tanker/ReceiveKey.hpp
  include/Tanker/ProvisionalUsers/Accessor.hpp
  include/Tanker/ProvisionalUsers/IAccessor.hpp
  include/Tanker/ProvisionalUsers/Updater.hpp
  include/Tanker/ProvisionalUsers/Requests.hpp
  include/Tanker/ProvisionalUsers/Manager.hpp
  include/Tanker/Groups/Group.hpp
  include/Tanker/Groups/GroupProvisionalUser.hpp
  include/Tanker/Groups/GroupEncryptedKey.hpp
  include/Tanker/Groups/Store.hpp
  include/Tanker/Groups/Updater.hpp
  include/Tanker/Groups/Accessor.hpp
  include/Tanker/Groups/IAccessor.hpp
  include/Tanker/Groups/Manager.hpp
  include/Tanker/Groups/Requester.hpp
  include/Tanker/Groups/EntryGenerator.hpp
  include/Tanker/Groups/Verif/UserGroupAddition.hpp
  include/Tanker/Groups/Verif/UserGroupCreation.hpp
  include/Tanker/ResourceKeyStore.hpp
  include/Tanker/Session.hpp
  include/Tanker/Core.hpp
  include/Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp
  include/Tanker/Version.hpp
  include/Tanker/Share.hpp
  include/Tanker/Status.hpp
  include/Tanker/Revocation.hpp
  include/Tanker/Users/User.hpp
  include/Tanker/Users/Updater.hpp
  include/Tanker/Users/IRequester.hpp
  include/Tanker/Users/Requester.hpp
  include/Tanker/Users/LocalUser.hpp
  include/Tanker/Users/UserAccessor.hpp
  include/Tanker/Users/IUserAccessor.hpp
  include/Tanker/Users/ContactStore.hpp
  include/Tanker/Users/Device.hpp
  include/Tanker/Users/EntryGenerator.hpp
  include/Tanker/ResourceKeyAccessor.hpp
  include/Tanker/SecretProvisionalUser.hpp
  include/Tanker/PublicProvisionalUser.hpp
  include/Tanker/IdentityUtils.hpp
  include/Tanker/Utils.hpp
  include/Tanker/Verif/DeviceCreation.hpp
  include/Tanker/Verif/DeviceRevocation.hpp
  include/Tanker/Verif/TrustchainCreation.hpp
  include/Tanker/ProvisionalUsers/Verif/ProvisionalIdentityClaim.hpp
  include/Tanker/Verif/Helpers.hpp
  include/Tanker/Verif/Errors/Errc.hpp
  include/Tanker/Verif/Errors/ErrcCategory.hpp
  include/Tanker/Encryptor.hpp
  include/Tanker/EncryptionMetadata.hpp
  include/Tanker/Encryptor/v2.hpp
  include/Tanker/Encryptor/v3.hpp
  include/Tanker/Encryptor/v4.hpp
  include/Tanker/Encryptor/v5.hpp
  include/Tanker/Retry.hpp

  src/AsyncCore.cpp
  src/AttachResult.cpp
  src/Init.cpp
  src/DataStore/ADatabase.cpp
  src/DataStore/Errors/Errc.cpp
  src/DataStore/Errors/ErrcCategory.cpp
  src/DataStore/DatabaseFactory.cpp
  src/BlockGenerator.cpp
  src/Client.cpp
  src/GhostDevice.cpp
  src/Unlock/Verification.cpp
  src/Session.cpp
  src/Opener.cpp
  src/Core.cpp
  src/Status.cpp
  src/TrustchainStore.cpp
  src/TrustchainPuller.cpp
  src/TrustchainVerifier.cpp
  src/DeviceKeys.cpp
  src/ReceiveKey.cpp
  src/ResourceKeyStore.cpp
  src/Entry.cpp
  src/Share.cpp
  src/IdentityUtils.cpp
  src/ProvisionalUsers/Accessor.cpp
  src/ProvisionalUsers/Updater.cpp
  src/ProvisionalUsers/ProvisionalUserKeysStore.cpp
  src/ProvisionalUsers/Requests.cpp
  src/ProvisionalUsers/Manager.cpp
  src/Groups/Group.cpp
  src/Groups/EntryGenerator.cpp
  src/Groups/GroupEncryptedKey.cpp
  src/Groups/Store.cpp
  src/Groups/Accessor.cpp
  src/Groups/Updater.cpp
  src/Groups/Manager.cpp
  src/Groups/Requester.cpp
  src/Groups/Verif/UserGroupAddition.cpp
  src/Groups/Verif/UserGroupCreation.cpp
  src/Users/User.cpp
  src/Users/Updater.cpp
  src/Users/LocalUser.cpp
  src/Users/UserAccessor.cpp
  src/Users/ContactStore.cpp
  src/Users/Device.cpp
  src/Users/EntryGenerator.cpp
  src/Users/Requester.cpp
  src/ResourceKeyAccessor.cpp
  src/Revocation.cpp
  src/Verif/Errors/Errc.cpp
  src/Verif/Errors/ErrcCategory.cpp
  src/Verif/DeviceCreation.cpp
  src/Verif/DeviceRevocation.cpp
  src/Verif/TrustchainCreation.cpp
  src/ProvisionalUsers/Verif/ProvisionalIdentityClaim.cpp
  src/Encryptor.cpp
  src/Encryptor/v2.cpp
  src/Encryptor/v3.cpp
  src/Encryptor/v4.cpp
  src/Encryptor/v5.cpp
  src/Retry.cpp

  ${TANKER_CORE_DATASTORE_SRC}
  ${TANKER_CORE_CONNECTION_SRC}
  ${TANKER_CORE_EXTRA_SRC}
)

target_include_directories(tankercore
  PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

target_link_libraries(tankercore
  tankererrors
  tankerserialization
  tankeridentity
  tankertypes
  tankernetwork
  tankerstreams
  tankertrustchain
  tankercrypto
  tankerformat
  tankerlog
  tankerconfig
  tankeradmin
  ttracer
  CONAN_PKG::Boost
  CONAN_PKG::tconcurrent
  CONAN_PKG::cppcodec
  CONAN_PKG::gsl-lite
  CONAN_PKG::fmt
  CONAN_PKG::jsonformoderncpp
  CONAN_PKG::enum-flags
)

if(TANKER_BUILD_WITH_SSL)
  target_link_libraries(tankercore tankercacerts)
  target_compile_definitions(tankercore PUBLIC TANKER_BUILD_WITH_SSL)
endif()

if (NOT EMSCRIPTEN)
  target_link_libraries(tankercore
    CONAN_PKG::socket.io-client-cpp
    CONAN_PKG::sqlpp11-connector-sqlite3
  )
endif()

install(TARGETS tankercore
  EXPORT tanker
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)


if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(EMSCRIPTEN)
  add_executable(emtanker
    src/emtanker.cpp
    )
  target_link_libraries(emtanker tankercore)
endif()
