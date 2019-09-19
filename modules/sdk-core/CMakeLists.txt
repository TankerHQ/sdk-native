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
    include/Tanker/DbModels/KeyPublishes.hpp
    include/Tanker/DbModels/GroupsProvisionalEncryptionKeys.hpp
    include/Tanker/DbModels/ResourceIdToKeyPublish.hpp
    include/Tanker/DbModels/ResourceKeys.hpp
    include/Tanker/DbModels/ProvisionalUserKeys.hpp
    include/Tanker/DbModels/Trustchain.hpp
    include/Tanker/DbModels/TrustchainIndexes.hpp
    include/Tanker/DbModels/TrustchainInfo.hpp
    include/Tanker/DbModels/UserKeys.hpp
    include/Tanker/DbModels/Versions.hpp
    include/Tanker/DbModels/Version.hpp

    src/DataStore/Connection.cpp
    src/DataStore/Database.cpp
    src/DataStore/Table.cpp
    src/FileKit/DownloadStream.cpp
    src/FileKit/Metadata.cpp
    src/FileKit/Request.cpp
    src/DbModels/ContactDevices.cpp
    src/DbModels/ContactUserKeys.cpp
    src/DbModels/DeviceKeyStore.cpp
    src/DbModels/Groups.cpp
    src/DbModels/KeyPublishes.cpp
    src/DbModels/GroupsProvisionalEncryptionKeys.cpp
    src/DbModels/ResourceIdToKeyPublish.cpp
    src/DbModels/ResourceKeys.cpp
    src/DbModels/ProvisionalUserKeys.cpp
    src/DbModels/Trustchain.cpp
    src/DbModels/TrustchainIndexes.cpp
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
  include/Tanker/TrustchainVerifier.hpp
  include/Tanker/BlockGenerator.hpp
  include/Tanker/GhostDevice.hpp
  include/Tanker/EncryptedUserKey.hpp
  include/Tanker/Unlock/Registration.hpp
  include/Tanker/Unlock/Create.hpp
  include/Tanker/Unlock/Verification.hpp
  include/Tanker/Unlock/Methods.hpp
  include/Tanker/Opener.hpp
  include/Tanker/DeviceKeyStore.hpp
  include/Tanker/DeviceKeys.hpp
  include/Tanker/Client.hpp
  include/Tanker/Entry.hpp
  include/Tanker/Index.hpp
  include/Tanker/ReceiveKey.hpp
  include/Tanker/Preregistration.hpp
  include/Tanker/Groups/Group.hpp
  include/Tanker/Groups/GroupProvisionalUser.hpp
  include/Tanker/Groups/GroupEncryptedKey.hpp
  include/Tanker/Groups/GroupStore.hpp
  include/Tanker/Groups/GroupUpdater.hpp
  include/Tanker/Groups/GroupAccessor.hpp
  include/Tanker/Groups/Manager.hpp
  include/Tanker/ResourceKeyStore.hpp
  include/Tanker/Session.hpp
  include/Tanker/Core.hpp
  include/Tanker/UserKeyStore.hpp
  include/Tanker/ContactStore.hpp
  include/Tanker/ProvisionalUserKeysStore.hpp
  include/Tanker/Version.hpp
  include/Tanker/Share.hpp
  include/Tanker/Status.hpp
  include/Tanker/Device.hpp
  include/Tanker/Revocation.hpp
  include/Tanker/User.hpp
  include/Tanker/UserAccessor.hpp
  include/Tanker/ResourceKeyAccessor.hpp
  include/Tanker/SecretProvisionalUser.hpp
  include/Tanker/PublicProvisionalUser.hpp
  include/Tanker/IdentityUtils.hpp
  include/Tanker/Utils.hpp
  include/Tanker/Verif/DeviceCreation.hpp
  include/Tanker/Verif/DeviceRevocation.hpp
  include/Tanker/Verif/TrustchainCreation.hpp
  include/Tanker/Verif/UserGroupAddition.hpp
  include/Tanker/Verif/UserGroupCreation.hpp
  include/Tanker/Verif/ProvisionalIdentityClaim.hpp
  include/Tanker/Verif/Helpers.hpp
  include/Tanker/Verif/Errors/Errc.hpp
  include/Tanker/Verif/Errors/ErrcCategory.hpp
  include/Tanker/Encryptor.hpp
  include/Tanker/EncryptionMetadata.hpp
  include/Tanker/Encryptor/v2.hpp
  include/Tanker/Encryptor/v3.hpp
  include/Tanker/Encryptor/v4.hpp
  include/Tanker/Encryptor/v5.hpp
  include/Tanker/CloudStorage.hpp
  include/Tanker/FileKit/DownloadStream.hpp
  include/Tanker/FileKit/Metadata.hpp
  include/Tanker/FileKit/Request.hpp
  include/Tanker/FileKit/Constants.hpp
  include/Tanker/FileKit/DownloadResult.hpp
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
  src/Unlock/Create.cpp
  src/Unlock/Verification.cpp
  src/Session.cpp
  src/Opener.cpp
  src/Core.cpp
  src/Status.cpp
  src/TrustchainStore.cpp
  src/TrustchainPuller.cpp
  src/TrustchainVerifier.cpp
  src/DeviceKeyStore.cpp
  src/DeviceKeys.cpp
  src/ReceiveKey.cpp
  src/ResourceKeyStore.cpp
  src/Entry.cpp
  src/Share.cpp
  src/IdentityUtils.cpp
  src/UserKeyStore.cpp
  src/ContactStore.cpp
  src/Preregistration.cpp
  src/ProvisionalUserKeysStore.cpp
  src/Groups/Group.cpp
  src/Groups/GroupEncryptedKey.cpp
  src/Groups/GroupStore.cpp
  src/Groups/GroupAccessor.cpp
  src/Groups/GroupUpdater.cpp
  src/Groups/Manager.cpp
  src/Device.cpp
  src/User.cpp
  src/UserAccessor.cpp
  src/ResourceKeyAccessor.cpp
  src/Revocation.cpp
  src/Verif/Errors/Errc.cpp
  src/Verif/Errors/ErrcCategory.cpp
  src/Verif/DeviceCreation.cpp
  src/Verif/DeviceRevocation.cpp
  src/Verif/TrustchainCreation.cpp
  src/Verif/UserGroupAddition.cpp
  src/Verif/UserGroupCreation.cpp
  src/Verif/ProvisionalIdentityClaim.cpp
  src/Encryptor.cpp
  src/Encryptor/v2.cpp
  src/Encryptor/v3.cpp
  src/Encryptor/v4.cpp
  src/Encryptor/v5.cpp
  src/CloudStorage.cpp
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
  tankercacerts
  tankeradmin
  ttracer
  tccurl
  CONAN_PKG::Boost
  CONAN_PKG::tconcurrent
  CONAN_PKG::cppcodec
  CONAN_PKG::variant
  CONAN_PKG::gsl-lite
  CONAN_PKG::fmt
  CONAN_PKG::jsonformoderncpp
  CONAN_PKG::optional-lite
  CONAN_PKG::mockaron
  CONAN_PKG::enum-flags
)

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

if(TANKER_BUILD_WITH_SSL)
  target_compile_definitions(tankercore PUBLIC TANKER_BUILD_WITH_SSL)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(EMSCRIPTEN)
  add_executable(emtanker
    src/emtanker.cpp
    )
  target_link_libraries(emtanker tankercore)
endif()
