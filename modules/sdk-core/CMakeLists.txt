cmake_minimum_required(VERSION 3.4)

project(TankerSDK-Core)

set(TANKER_CORE_DATASTORE_SRC
  include/Tanker/DataStore/Backend.hpp
  include/Tanker/DataStore/Utils.hpp
  include/Tanker/DataStore/Errors/Errc.hpp
  include/Tanker/DataStore/Errors/ErrcCategory.hpp

  src/DataStore/Utils.cpp
)

if (WITH_SQLITE)
  set(TANKER_CORE_SQLITE_SRC
    include/Tanker/DataStore/Sqlite/Backend.hpp
    include/Tanker/DataStore/Connection.hpp
    src/DataStore/Sqlite/Backend.cpp
    src/DataStore/Connection.cpp
  )
endif()

if (WITH_FETCHPP)
  set(TANKER_CORE_HTTP_SRC
    include/Tanker/Network/FetchppBackend.hpp
    src/Network/FetchppBackend.cpp
  )
endif()

add_library(tankercore STATIC
  include/Tanker/AsyncCore.hpp
  include/Tanker/AttachResult.hpp
  include/Tanker/BasicPullResult.hpp
  include/Tanker/Core.hpp
  include/Tanker/Session.hpp
  include/Tanker/DataStore/Errors/Errc.hpp
  include/Tanker/Init.hpp
  include/Tanker/GhostDevice.hpp
  include/Tanker/EncryptedUserKey.hpp
  include/Tanker/Verification/Registration.hpp
  include/Tanker/Verification/Verification.hpp
  include/Tanker/Verification/Methods.hpp
  include/Tanker/Verification/IRequester.hpp
  include/Tanker/Verification/Requester.hpp
  include/Tanker/Verification/Request.hpp
  include/Tanker/DeviceKeys.hpp
  include/Tanker/Network/HttpMethod.hpp
  include/Tanker/Network/HttpRequest.hpp
  include/Tanker/Network/HttpClient.hpp
  include/Tanker/Network/Backend.hpp
  include/Tanker/Oidc/Nonce.hpp
  include/Tanker/Oidc/NonceManager.hpp
  include/Tanker/Index.hpp
  include/Tanker/ReceiveKey.hpp
  include/Tanker/ProvisionalUsers/Accessor.hpp
  include/Tanker/ProvisionalUsers/IAccessor.hpp
  include/Tanker/ProvisionalUsers/IRequester.hpp
  include/Tanker/ProvisionalUsers/Requester.hpp
  include/Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp
  include/Tanker/ProvisionalUsers/Updater.hpp
  include/Tanker/ProvisionalUsers/Manager.hpp
  include/Tanker/ProvisionalUsers/SecretUser.hpp
  include/Tanker/ProvisionalUsers/PublicUser.hpp
  include/Tanker/ProvisionalUsers/Verif/ProvisionalIdentityClaim.hpp
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
  include/Tanker/ResourceKeys/KeysResult.hpp
  include/Tanker/ResourceKeys/Store.hpp
  include/Tanker/ResourceKeys/Accessor.hpp
  include/Tanker/Version.hpp
  include/Tanker/Share.hpp
  include/Tanker/Status.hpp
  include/Tanker/Revocation.hpp
  include/Tanker/Users/User.hpp
  include/Tanker/Users/Updater.hpp
  include/Tanker/Users/IRequester.hpp
  include/Tanker/Users/Requester.hpp
  include/Tanker/Users/LocalUser.hpp
  include/Tanker/Users/LocalUserStore.hpp
  include/Tanker/Users/LocalUserAccessor.hpp
  include/Tanker/Users/ILocalUserAccessor.hpp
  include/Tanker/Users/UserAccessor.hpp
  include/Tanker/Users/IUserAccessor.hpp
  include/Tanker/Users/Device.hpp
  include/Tanker/Users/EntryGenerator.hpp
  include/Tanker/IdentityUtils.hpp
  include/Tanker/Utils.hpp
  include/Tanker/Verif/DeviceCreation.hpp
  include/Tanker/Verif/DeviceRevocation.hpp
  include/Tanker/Verif/TrustchainCreation.hpp
  include/Tanker/Verif/Helpers.hpp
  include/Tanker/Verif/Errors/Errc.hpp
  include/Tanker/Verif/Errors/ErrcCategory.hpp
  include/Tanker/Encryptor.hpp
  include/Tanker/EncryptionMetadata.hpp
  include/Tanker/Encryptor/v2.hpp
  include/Tanker/Encryptor/v3.hpp
  include/Tanker/Encryptor/v4.hpp
  include/Tanker/Encryptor/v5.hpp
  include/Tanker/Encryptor/v6.hpp
  include/Tanker/EncryptionSession.hpp

  src/AsyncCore.cpp
  src/AttachResult.cpp
  src/Core.cpp
  src/Session.cpp
  src/Init.cpp
  src/DataStore/Errors/Errc.cpp
  src/DataStore/Errors/ErrcCategory.cpp
  src/Network/HttpClient.cpp
  src/GhostDevice.cpp
  src/Verification/Verification.cpp
  src/Verification/Requester.cpp
  src/Verification/Request.cpp
  src/Status.cpp
  src/DeviceKeys.cpp
  src/ReceiveKey.cpp
  src/ResourceKeys/Store.cpp
  src/ResourceKeys/Accessor.cpp
  src/ResourceKeys/KeysResult.cpp
  src/Share.cpp
  src/IdentityUtils.cpp
  src/Oidc/NonceManager.cpp
  src/ProvisionalUsers/Accessor.cpp
  src/ProvisionalUsers/Requester.cpp
  src/ProvisionalUsers/Updater.cpp
  src/ProvisionalUsers/ProvisionalUserKeysStore.cpp
  src/ProvisionalUsers/Manager.cpp
  src/ProvisionalUsers/PublicUser.cpp
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
  src/Users/LocalUserStore.cpp
  src/Users/LocalUserAccessor.cpp
  src/Users/UserAccessor.cpp
  src/Users/Device.cpp
  src/Users/EntryGenerator.cpp
  src/Users/Requester.cpp
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
  src/Encryptor/v6.cpp
  src/EncryptionSession.cpp

  ${TANKER_CORE_DATASTORE_SRC}
  ${TANKER_CORE_SQLITE_SRC}
  ${TANKER_CORE_HTTP_SRC}
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
  tankerstreams
  tankertrustchain
  tankercrypto
  tankerformat
  tankerlog
  tankerconfig
  ttracer
  CONAN_PKG::boost
  CONAN_PKG::tconcurrent
  CONAN_PKG::mgs
  CONAN_PKG::gsl-lite
  CONAN_PKG::fmt
  CONAN_PKG::nlohmann_json
  CONAN_PKG::enum-flags
  CONAN_PKG::range-v3
  CONAN_PKG::date
)

if(WITH_FETCHPP)
  target_link_libraries(tankercore tankercacerts CONAN_PKG::fetchpp)
endif()

if(WITH_SQLITE)
  target_link_libraries(tankercore CONAN_PKG::sqlpp11-connector-sqlite3)
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
