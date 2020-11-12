cmake_minimum_required(VERSION 3.4)

project(tankertrustchain)

add_library(tankertrustchain STATIC
  include/Tanker/Trustchain/Actions/DeviceCreation.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v1.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v2.hpp
  include/Tanker/Trustchain/Actions/DeviceCreation/v3.hpp
  include/Tanker/Trustchain/Actions/DeviceRevocation.hpp
  include/Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp
  include/Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp
  include/Tanker/Trustchain/Actions/Nature.hpp
  include/Tanker/Trustchain/Actions/KeyPublish.hpp
  include/Tanker/Trustchain/Actions/KeyPublish/ToProvisionalUser.hpp
  include/Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp
  include/Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp
  include/Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp
  include/Tanker/Trustchain/Actions/TrustchainCreation.hpp
  include/Tanker/Trustchain/Actions/UserGroupAddition.hpp
  include/Tanker/Trustchain/Actions/UserGroupAddition/v1.hpp
  include/Tanker/Trustchain/Actions/UserGroupAddition/v2.hpp
  include/Tanker/Trustchain/Actions/UserGroupAddition/v3.hpp
  include/Tanker/Trustchain/Actions/UserGroupCreation.hpp
  include/Tanker/Trustchain/Actions/UserGroupCreation/v1.hpp
  include/Tanker/Trustchain/Actions/UserGroupCreation/v2.hpp
  include/Tanker/Trustchain/Actions/UserGroupCreation/v3.hpp
  include/Tanker/Trustchain/Actions/UserGroupMember2.hpp
  include/Tanker/Trustchain/Actions/UserGroupProvisionalMember2.hpp
  include/Tanker/Trustchain/Actions/UserGroupProvisionalMember3.hpp
  include/Tanker/Trustchain/Context.hpp
  include/Tanker/Trustchain/Errors/Errc.hpp
  include/Tanker/Trustchain/Errors/ErrcCategory.hpp
  include/Tanker/Trustchain/DeviceId.hpp
  include/Tanker/Trustchain/GroupId.hpp
  include/Tanker/Trustchain/Preprocessor/Actions/VariantImplementation.hpp
  include/Tanker/Trustchain/Preprocessor/Actions/Implementation.hpp
  include/Tanker/Trustchain/Preprocessor/Actions/Json.hpp
  include/Tanker/Trustchain/Preprocessor/Actions/Serialization.hpp
  include/Tanker/Trustchain/ResourceId.hpp
  include/Tanker/Trustchain/UserId.hpp
  include/Tanker/Trustchain/HashedPassphrase.hpp
  include/Tanker/Trustchain/TrustchainId.hpp
  include/Tanker/Trustchain/ComputeHash.hpp
  include/Tanker/Trustchain/Serialization.hpp
  include/Tanker/Trustchain/GroupAction.hpp
  include/Tanker/Trustchain/UserAction.hpp
  include/Tanker/Trustchain/KeyPublishAction.hpp

  src/Actions/DeviceCreation.cpp
  src/Actions/DeviceCreation/v1.cpp
  src/Actions/DeviceCreation/v2.cpp
  src/Actions/DeviceCreation/v3.cpp
  src/Actions/DeviceRevocation.cpp
  src/Actions/DeviceRevocation/v1.cpp
  src/Actions/DeviceRevocation/v2.cpp
  src/Actions/Nature.cpp
  src/Actions/KeyPublish.cpp
  src/Actions/KeyPublish/ToProvisionalUser.cpp
  src/Actions/KeyPublish/ToUser.cpp
  src/Actions/KeyPublish/ToUserGroup.cpp
  src/Actions/ProvisionalIdentityClaim.cpp
  src/Actions/TrustchainCreation.cpp
  src/Actions/UserGroupAddition.cpp
  src/Actions/UserGroupAddition/v1.cpp
  src/Actions/UserGroupAddition/v2.cpp
  src/Actions/UserGroupAddition/v3.cpp
  src/Actions/UserGroupCreation.cpp
  src/Actions/UserGroupCreation/v1.cpp
  src/Actions/UserGroupCreation/v2.cpp
  src/Actions/UserGroupCreation/v3.cpp
  src/Actions/UserGroupMember2.cpp
  src/Actions/UserGroupProvisionalMember2.cpp
  src/Actions/UserGroupProvisionalMember3.cpp
  src/Context.cpp
  src/Errors/Errc.cpp
  src/Errors/ErrcCategory.cpp
  src/ExternTemplates.cpp
  src/ComputeHash.cpp
  src/Serialization.cpp
  src/GroupAction.cpp
  src/UserAction.cpp
  src/KeyPublishAction.cpp
)

target_include_directories(tankertrustchain
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include DESTINATION .)

install(TARGETS tankertrustchain
  EXPORT tankertrustchain
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

target_link_libraries(tankertrustchain
  tankercrypto
  tankerserialization
  tankererrors
  tankerformat

  CONAN_PKG::nlohmann_json
  CONAN_PKG::boost
)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
